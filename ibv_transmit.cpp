/* Copyright 2015-2016 SKA South Africa
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#if HAVE_IBV

#include <algorithm>
#include <iostream>
#include <cstring>
#include <cassert>
#include <system_error>
#include <stdexcept>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include "ibv_transmit.h"

using boost::asio::ip::udp;

static mac_address multicast_mac(const boost::asio::ip::address_v4 &address)
{
    if (!address.is_multicast())
        throw std::runtime_error("Address must be multicast for --mode=ibv");
    mac_address ans;
    auto bytes = address.to_bytes();
    std::memcpy(&ans[2], &bytes, 4);
    ans[0] = 0x01;
    ans[1] = 0x00;
    ans[2] = 0x5e;
    ans[3] &= 0x7f;
    return ans;
}

// Finds the MAC address corresponding to an interface IP address
static std::array<unsigned char, 6> get_mac(const boost::asio::ip::address &address)
{
    ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        throw std::system_error(errno, std::system_category(), "getifaddrs failed");
    std::unique_ptr<ifaddrs, freeifaddrs_deleter> ifap_owner(ifap);

    // Map address to an interface name
    char *if_name = nullptr;
    for (ifaddrs *cur = ifap; cur; cur = cur->ifa_next)
    {
        if (cur->ifa_addr && *(sa_family_t *) cur->ifa_addr == AF_INET && address.is_v4())
        {
            const sockaddr_in *cur_address = (const sockaddr_in *) cur->ifa_addr;
            const auto expected = address.to_v4().to_bytes();
            if (memcmp(&cur_address->sin_addr, &expected, sizeof(expected)) == 0)
            {
                if_name = cur->ifa_name;
                break;
            }
        }
        else if (cur->ifa_addr && *(sa_family_t *) cur->ifa_addr == AF_INET6 && address.is_v6())
        {
            const sockaddr_in6 *cur_address = (const sockaddr_in6 *) cur->ifa_addr;
            const auto expected = address.to_v6().to_bytes();
            if (memcmp(&cur_address->sin6_addr, &expected, sizeof(expected)) == 0)
            {
                if_name = cur->ifa_name;
                break;
            }
        }
    }
    if (!if_name)
    {
        throw std::runtime_error("no interface found with the address " + address.to_string());
    }

    // Now find the MAC address for this interface
    for (ifaddrs *cur = ifap; cur; cur = cur->ifa_next)
    {
        if (strcmp(cur->ifa_name, if_name) == 0
            && cur->ifa_addr && *(sa_family_t *) cur->ifa_addr == AF_PACKET)
        {
            const sockaddr_ll *ll = (sockaddr_ll *) cur->ifa_addr;
            if (ll->sll_hatype == ARPHRD_ETHER && ll->sll_halen == 6)
            {
                std::array<unsigned char, 6> mac;
                std::memcpy(&mac, ll->sll_addr, 6);
                return mac;
            }
        }
    }
    throw std::runtime_error(std::string("no MAC address found for interface ") + if_name);
}

static std::uint16_t ip_checksum(const std::uint8_t *header)
{
    std::uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2)
    {
        if (i == 10)
            continue;   // skip the checksum itself
        std::uint16_t word;
        std::memcpy(&word, header + i, sizeof(word));
        sum += ntohs(word);
    }
    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~htons(sum);
}

static std::unique_ptr<std::uint8_t[], mmap_deleter<std::uint8_t>>
allocate_huge(std::size_t size)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
    std::uint8_t *ptr = (std::uint8_t *) mmap(
        nullptr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (ptr == MAP_FAILED)
    {
        std::cerr << "Warning: hugetlb allocation failed, falling back to regular pages\n";
        flags &= ~MAP_HUGETLB;
        ptr = (std::uint8_t *) mmap(
            nullptr, size, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (ptr == MAP_FAILED)
            throw std::bad_alloc();
    }
    return {ptr, mmap_deleter<std::uint8_t>(size)};
}

ibv_collector::slab::slab(ibv_pd *pd, std::size_t capacity)
    : data(allocate_huge(capacity)),
    mr(ibv_reg_mr(pd, data.get(), capacity, 0)),
    capacity(capacity),
    used(0)
{
}

ibv_collector::ibv_collector(
    ibv_pd *pd,
    const boost::asio::ip::udp::endpoint &src_endpoint,
    const mac_address &src_mac,
    std::size_t slab_size)
    : pd(pd), src_endpoint(src_endpoint), src_mac(src_mac),
    slab_size(slab_size)
{
}

void ibv_collector::add_packet(const packet &pkt)
{
    constexpr std::size_t header_size = 42;
    std::size_t raw_size = pkt.len + header_size;

    if (slabs.empty() || slabs.back().capacity - slabs.back().used < raw_size)
    {
        std::size_t alloc_size = std::max(slab_size, raw_size);
        slabs.emplace_back(pd, alloc_size);
    }
    std::uint8_t *data = slabs.back().data.get() + slabs.back().used;
    slabs.back().used += raw_size;

    boost::asio::ip::address_v4::bytes_type dst_addr;
    std::memcpy(&dst_addr, &pkt.dst_host, sizeof(dst_addr));
    mac_address dst_mac = multicast_mac(boost::asio::ip::address_v4(dst_addr));

    memset(data, 0, 42); // Headers
    // Ethernet header
    std::uint8_t *ether = data;
    std::memcpy(ether + 0, &dst_mac, sizeof(dst_mac));
    std::memcpy(ether + 6, &src_mac, sizeof(src_mac));
    ether[12] = 0x08; // ETHERTYPE_IP
    ether[13] = 0x00;

    // IP header
    std::uint8_t *ip = ether + 14;
    ip[0] = 0x45;  // Version 4, header length 20
    ip[8] = 1;     // TTL
    ip[9] = 0x11;  // Protocol: UDP
    auto src_addr = src_endpoint.address().to_v4().to_bytes();
    std::uint16_t length_ip = htons(pkt.len + 28);
    std::memcpy(ip + 2, &length_ip, sizeof(length_ip));
    std::memcpy(ip + 12, &src_addr, sizeof(src_addr));
    std::memcpy(ip + 16, &dst_addr, sizeof(dst_addr));
    std::uint16_t checksum = ip_checksum(ip);
    std::memcpy(ip + 10, &checksum, sizeof(checksum));

    // UDP header
    std::uint8_t *udp = ip + 20;
    std::uint16_t src_port_be = htons(src_endpoint.port());
    std::uint16_t dst_port_be = pkt.dst_port;
    std::uint16_t length_udp = htons(pkt.len + 8);
    std::memcpy(udp + 0, &src_port_be, sizeof(src_port_be));
    std::memcpy(udp + 2, &dst_port_be, sizeof(dst_port_be));
    std::memcpy(udp + 4, &length_udp, sizeof(length_udp));

    // Payload
    std::memcpy(udp + 8, pkt.data, pkt.len);

    frames.emplace_back();
    frame &f = frames.back();
    f.sge.addr = (std::uintptr_t) data;
    f.sge.lkey = slabs.back().mr->lkey;
    f.sge.length = raw_size;
    f.wr.sg_list = &f.sge;
    f.wr.num_sge = 1;
    f.wr.opcode = IBV_WR_SEND;
    f.packet_size = pkt.len;
    f.timestamp = pkt.timestamp;
    total_bytes += pkt.len;
}

std::size_t ibv_collector::num_packets() const
{
    return frames.size();
}

ibv_collector::frame &ibv_collector::get_frame(std::size_t idx)
{
    return frames[idx];
}

std::size_t ibv_collector::packet_size(std::size_t idx) const
{
    return frames[idx].packet_size;
}

duration ibv_collector::packet_timestamp(std::size_t idx) const
{
    return frames[idx].timestamp;
}

std::size_t ibv_collector::bytes() const
{
    return total_bytes;
}

void ibv_transmit::modify_state(ibv_qp_state state, int port_num)
{
    int flags = IBV_QP_STATE;
    ibv_qp_attr attr = {};
    attr.qp_state = state;
    if (port_num >= 0)
    {
        attr.port_num = port_num;
        flags |= IBV_QP_PORT;
    }
    int status = ibv_modify_qp(qp.get(), &attr, flags);
    if (status != 0)
        throw std::system_error(status, std::system_category(), "ibv_modify_qp failed");
}

void ibv_transmit::wait_for_wc(std::size_t min_slots)
{
    ibv_wc wc[batch_size];
    while (slots < min_slots)
    {
        int status;
        while ((status = ibv_poll_cq(cq.get(), batch_size, wc)) == 0)
        {
            // Do nothing
        }
        if (status < 0)
            throw std::runtime_error("ibv_poll_cq failed");
        for (int i = 0; i < status; i++)
        {
            if (wc[i].status != IBV_WC_SUCCESS)
            {
                std::cerr << "WC failure: id=" << wc[i].wr_id
                    << " status=" << wc[i].status
                    << " vendor_err=" << wc[i].vendor_err
                    << '\n';
                throw std::runtime_error("send failed");
            }
            slots += wc[i].wr_id;
        }
    }
}

ibv_transmit::ibv_transmit(const options &opts, boost::asio::io_service &io_service)
    : socket(io_service, udp::v4())
{
    if (opts.bind == "")
        throw std::runtime_error("--bind must be specified with --mode=ibv");
    auto src_address = boost::asio::ip::address::from_string(opts.bind);
    udp::endpoint src_endpoint(src_address, 0);
    // Get the OS to assign us a source port
    socket.bind(src_endpoint);
    src_endpoint = socket.local_endpoint();

    event_channel.reset(rdma_create_event_channel());
    if (!event_channel)
        throw std::system_error(errno, std::system_category(), "rdma_create_event_channel failed");
    rdma_cm_id *cm_id_ptr;
    if (rdma_create_id(event_channel.get(), &cm_id_ptr, NULL, RDMA_PS_UDP) < 0)
        throw std::system_error(errno, std::system_category(), "rdma_create_id failed");
    cm_id.reset(cm_id_ptr);
    if (rdma_bind_addr(cm_id.get(), src_endpoint.data()) < 0)
        throw std::system_error(errno, std::system_category(), "rdma_bind_addr failed");
    if (!cm_id->verbs)
        throw std::runtime_error("rdma_bind_addr did not bind to an RDMA device");

    cq.reset(ibv_create_cq(cm_id->verbs, depth, NULL, NULL, 0));
    if (!cq)
        throw std::runtime_error("ibv_create_cq failed");
    pd.reset(ibv_alloc_pd(cm_id->verbs));
    if (!pd)
        throw std::runtime_error("ibv_alloc_pd failed");

    ibv_qp_init_attr qp_init_attr = {};
    qp_init_attr.send_cq = cq.get();
    qp_init_attr.recv_cq = cq.get();
    qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
    qp_init_attr.cap.max_send_wr = depth;
    qp_init_attr.cap.max_recv_wr = 1;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    qp_init_attr.sq_sig_all = 0;
    qp.reset(ibv_create_qp(pd.get(), &qp_init_attr));
    if (!qp)
        throw std::runtime_error("ibv_create_qp failed");

    // Move to RTS state
    modify_state(IBV_QPS_INIT, cm_id->port_num);
    modify_state(IBV_QPS_RTR);
    modify_state(IBV_QPS_RTS);

    collector.reset(new ibv_collector(
            pd.get(), src_endpoint,
            get_mac(src_endpoint.address())));
}

void ibv_transmit::send_packets(std::size_t first, std::size_t last,
                                time_point start)
{
    (void) start; // unused;
    if (first == last)
        return;
    if (first == 0 && collector->num_packets() < depth)
    {
        // If we wrap the send queue around it could try to send the same
        // packet twice, which would do bad things.
        flush();
    }
    ibv_send_wr *prev = nullptr;
    ibv_send_wr *first_wr = nullptr;
    for (std::size_t i = first; i < last; ++i)
    {
        auto &f = collector->get_frame(i);
        if (prev)
            prev->next = &f.wr;
        else
            first_wr = &f.wr;
        prev = &f.wr;
        // We get a CQE only for the last WR in the batch, and we use the wr_id
        // to store the batch size.
        if (i == last - 1)
        {
            f.wr.wr_id = last - first;
            f.wr.send_flags = IBV_SEND_SIGNALED;
        }
        else
        {
            f.wr.wr_id = 0;
            f.wr.send_flags = 0;
        }
    }
    prev->next = nullptr;

    wait_for_wc(last - first);
    slots -= last - first;

    ibv_send_wr *bad;
    int status = ibv_post_send(qp.get(), first_wr, &bad);
    if (status != 0)
        throw std::system_error(status, std::system_category(), "ibv_post_send failed");
}

void ibv_transmit::flush()
{
    wait_for_wc(depth);
}

constexpr int ibv_transmit::depth;
constexpr int ibv_transmit::batch_size;

#endif // HAVE_IBV
