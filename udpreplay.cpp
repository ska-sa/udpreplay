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

// This is a bit hacky, but would need autoconf-style detection to do it right
#ifdef __linux__
# define HAVE_SENDMMSG 1
#else
# define HAVE_SENDMMSG 0
#endif
#ifndef HAVE_IBV
# define HAVE_IBV 0
#endif

#if HAVE_IBV
# include <sys/socket.h>
# include <rdma/rdma_cma.h>
# include <infiniband/verbs.h>
# include <ifaddrs.h>
# include <sys/types.h>
# include <net/ethernet.h>
# include <net/if_arp.h>
# include <netpacket/packet.h>
#endif
#if HAVE_SENDMMSG
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <arpa/inet.h>
#endif
#include <iostream>
#include <memory>
#include <vector>
#include <stack>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <system_error>
#include <pcap.h>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

namespace asio = boost::asio;
namespace po = boost::program_options;
using boost::asio::ip::udp;

struct options
{
    double pps = 0;
    double mbps = 0;
    size_t buffer_size = 0;
    size_t repeat = 1;
    std::string mode = "asio";
    bool parallel = false;
    std::string host = "localhost";
    std::string port = "8888";
    std::string bind = "";
    std::string input_file;
};

struct packet
{
    const u_char *data;
    std::size_t len;
};

static void set_buffer_size(udp::socket &socket, std::size_t size)
{
    if (size != 0)
    {
        socket.set_option(udp::socket::send_buffer_size(size));
        udp::socket::send_buffer_size actual;
        socket.get_option(actual);
        if ((std::size_t) actual.value() != size)
        {
            std::cerr << "Warning: requested buffer size of " << size
                << " but actual size is " << actual.value() << '\n';
        }
    }
}

class asio_transmit
{
private:
    udp::socket socket;
    udp::endpoint endpoint;

public:
    static constexpr int batch_size = 1;

    asio_transmit(const options &opts, boost::asio::io_service &io_service)
        : socket(io_service)
    {
        udp::resolver resolver(io_service);
        udp::resolver::query query(udp::v4(), opts.host, opts.port);
        endpoint = *resolver.resolve(query);
        socket.open(udp::v4());
        set_buffer_size(socket, opts.buffer_size);
    }

    template<typename Iterator>
    void send_packets(Iterator first, Iterator last)
    {
        assert(last - first == 1);
        socket.send_to(asio::buffer(first->data, first->len), endpoint);
    }

    void flush()
    {
    }
};

constexpr int asio_transmit::batch_size;

#if HAVE_SENDMMSG
class sendmmsg_transmit
{
public:
    static constexpr int batch_size = 8;

private:
    udp::socket socket;
    int fd;
    sockaddr_in addr;

public:
    sendmmsg_transmit(const options &opts, boost::asio::io_service &io_service)
        : socket(io_service)
    {
        udp::resolver resolver(io_service);
        udp::resolver::query query(udp::v4(), opts.host, opts.port);
        udp::endpoint endpoint = *resolver.resolve(query);

        addr.sin_family = AF_INET;
        addr.sin_port = htons(endpoint.port());
        addr.sin_addr.s_addr = htonl(endpoint.address().to_v4().to_ulong());

        socket.open(udp::v4());
        set_buffer_size(socket, opts.buffer_size);
        fd = socket.native_handle();
    }

    template<typename Iterator>
    void send_packets(Iterator first, Iterator last) const
    {
        mmsghdr msg_vec[batch_size];
        iovec msg_iov[batch_size];

        assert(last - first <= batch_size);
        int next = 0;
        std::memset(&msg_vec, 0, sizeof(msg_vec));
        for (Iterator i = first; i != last; ++i)
        {
            msg_vec[next].msg_hdr.msg_name = (void *) &addr;
            msg_vec[next].msg_hdr.msg_namelen = sizeof(addr);
            msg_vec[next].msg_hdr.msg_iov = &msg_iov[next];
            msg_vec[next].msg_hdr.msg_iovlen = 1;
            msg_iov[next].iov_base = const_cast<u_char *>(i->data);
            msg_iov[next].iov_len = i->len;
            next++;
        }
        int status = sendmmsg(fd, &msg_vec[0], next, 0);
        if (status != next)
            throw std::system_error(errno, std::system_category(), "sendmmsg failed");
        for (int i = 0; i < next; i++)
            if (msg_vec[i].msg_len != msg_iov[i].iov_len)
                throw std::runtime_error("short write");
    }

    void flush()
    {
    }
};

constexpr int sendmmsg_transmit::batch_size;
#endif

#if HAVE_IBV

struct freeifaddrs_deleter
{
    void operator()(ifaddrs *ifa) const
    {
        freeifaddrs(ifa);
    }
};


struct mr_deleter
{
    void operator()(ibv_mr *mr) const
    {
        ibv_dereg_mr(mr);
    }
};

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

static std::array<unsigned char, 6> multicast_mac(const boost::asio::ip::address_v4 &address)
{
    std::array<unsigned char, 6> ans;
    auto bytes = address.to_bytes();
    std::memcpy(&ans[2], &bytes, 4);
    ans[0] = 0x01;
    ans[1] = 0x00;
    ans[2] = 0x5e;
    ans[3] &= 0x7f;
    return ans;
}

static std::array<unsigned char, 6> multicast_mac(const boost::asio::ip::address &address)
{
    return multicast_mac(address.to_v4());
}

static uint16_t ip_checksum(const unsigned char *header)
{
    uint32_t sum = 0;
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

class ibv_transmit
{
public:
    static constexpr int depth = 256;
    static constexpr int batch_size = 16;

private:
    struct packet
    {
        ibv_sge sge{};
        ibv_send_wr wr{};
        std::unique_ptr<unsigned char[]> data;
        std::unique_ptr<ibv_mr, mr_deleter> mr;

        packet(packet &&other) noexcept(true)
        {
            *this = std::move(other);
        }

        packet &operator=(packet &&other) noexcept(true)
        {
            sge = std::move(other.sge);
            wr = std::move(other.wr);
            data = std::move(other.data);
            mr = std::move(other.mr);
            wr.sg_list = &sge;
            wr.wr_id = std::uintptr_t(this);
            return *this;
        }

        packet(ibv_pd *pd, std::size_t mtu,
               const std::array<unsigned char, 6> &src_mac,
               const std::array<unsigned char, 6> &dst_mac,
               const udp::endpoint &src_endpoint,
               const udp::endpoint &dst_endpoint)
            : data(new unsigned char[mtu]),
            mr(ibv_reg_mr(pd, data.get(), mtu, IBV_ACCESS_LOCAL_WRITE))
        {
            if (!mr)
                throw std::runtime_error("ibv_reg_mr failed");
            sge.addr = (std::uintptr_t) data.get();
            sge.lkey = mr->lkey;
            wr.sg_list = &sge;
            wr.num_sge = 1;
            wr.opcode = IBV_WR_SEND;
            wr.wr_id = std::uintptr_t(this);

            memset(data.get(), 0, 42); // Headers
            // Ethernet header
            unsigned char *ether = data.get();
            std::memcpy(ether + 0, &dst_mac, sizeof(dst_mac));
            std::memcpy(ether + 6, &src_mac, sizeof(src_mac));
            ether[12] = 0x08; // ETHERTYPE_IP
            ether[13] = 0x00;

            // IP header
            unsigned char *ip = ether + 14;
            ip[0] = 0x45;  // Version 4, header length 20
            ip[8] = 1;     // TTL
            ip[9] = 0x11;  // Protocol: UDP
            auto src_addr = src_endpoint.address().to_v4().to_bytes();
            auto dst_addr = dst_endpoint.address().to_v4().to_bytes();
            std::memcpy(ip + 12, &src_addr, sizeof(src_addr));
            std::memcpy(ip + 16, &dst_addr, sizeof(dst_addr));

            // UDP header
            unsigned char *udp = ip + 20;
            std::uint16_t src_port_be = htons(src_endpoint.port());
            std::uint16_t dst_port_be = htons(dst_endpoint.port());
            std::memcpy(udp + 0, &src_port_be, sizeof(src_port_be));
            std::memcpy(udp + 2, &dst_port_be, sizeof(dst_port_be));
        }

        void set_length(std::size_t length)
        {
            if (length > 65507)
                throw std::length_error("packet is too large");
            // IP header
            std::uint16_t length_ip = htons(length + 28);
            std::memcpy(&data[16], &length_ip, sizeof(length_ip));
            // UDP header
            std::uint16_t length_udp = htons(length + 8);
            std::memcpy(&data[38], &length_udp, sizeof(length_udp));
            sge.length = length + 42; // TODO: unhardcode
        }

        void update_checksum()
        {
            unsigned char *ip = data.get() + 14;
            uint16_t checksum = ip_checksum(ip);
            std::memcpy(&ip[10], &checksum, sizeof(checksum));
        }

        void *payload() const
        {
            return data.get() + 42;
        }
    };

    rdma_event_channel *event_channel = nullptr;
    rdma_cm_id *cm_id = nullptr;
    ibv_pd *pd = nullptr;
    ibv_qp *qp = nullptr;
    ibv_cq *cq = nullptr;
    std::vector<packet> packets;
    std::stack<packet *> available;

    void modify_state(ibv_qp_state state, int port_num = -1)
    {
        int flags = IBV_QP_STATE;
        ibv_qp_attr attr = {};
        attr.qp_state = state;
        if (port_num >= 0)
        {
            attr.port_num = port_num;
            flags |= IBV_QP_PORT;
        }
        int status = ibv_modify_qp(qp, &attr, flags);
        if (status != 0)
            throw std::system_error(status, std::system_category(), "ibv_modify_qp failed");
    }

    void wait_for_wc()
    {
        ibv_wc wc;
        int status;
        while ((status = ibv_poll_cq(cq, 1, &wc)) == 0)
        {
            // Do nothing
        }
        if (status < 0)
            throw std::runtime_error("ibv_poll_cq failed");
        if (wc.status != IBV_WC_SUCCESS)
        {
            std::cerr << "WC failure: id=" << wc.wr_id
                << " status=" << wc.status
                << " vendor_err=" << wc.vendor_err
                << '\n';
            throw std::runtime_error("send failed");
        }
        available.push((packet *) (std::uintptr_t) wc.wr_id);
    }

public:
    ibv_transmit(const options &opts, boost::asio::io_service &io_service)
    {
        if (opts.bind == "")
            throw std::runtime_error("--bind must be specified with --mode=ibv");
        auto src_address = boost::asio::ip::address::from_string(opts.bind);
        udp::endpoint src_endpoint(src_address, 12345);
        auto src_mac = get_mac(src_address);

        udp::resolver resolver(io_service);
        udp::resolver::query query(udp::v4(), opts.host, opts.port);
        udp::endpoint endpoint = *resolver.resolve(query);
        if (!endpoint.address().is_multicast())
            throw std::runtime_error("Address must be multicast for --mode=ibv");

        event_channel = rdma_create_event_channel();
        if (!event_channel)
            throw std::system_error(errno, std::system_category(), "rdma_create_event_channel failed");
        if (rdma_create_id(event_channel, &cm_id, NULL, RDMA_PS_UDP) < 0)
            throw std::system_error(errno, std::system_category(), "rdma_create_id failed");
        if (rdma_bind_addr(cm_id, src_endpoint.data()) < 0)
            throw std::system_error(errno, std::system_category(), "rdma_bind_addr failed");
        if (!cm_id->verbs)
            throw std::runtime_error("rdma_bind_addr did not bind to an RDMA device");

        cq = ibv_create_cq(cm_id->verbs, depth, NULL, NULL, 0);
        if (!cq)
            throw std::runtime_error("ibv_create_cq failed");
        pd = ibv_alloc_pd(cm_id->verbs);
        if (!pd)
            throw std::runtime_error("ibv_alloc_pd failed");

        ibv_qp_init_attr qp_init_attr = {};
        qp_init_attr.send_cq = cq;
        qp_init_attr.recv_cq = cq;
        qp_init_attr.qp_type = IBV_QPT_RAW_PACKET;
        qp_init_attr.cap.max_send_wr = depth;
        qp_init_attr.cap.max_recv_wr = 1;
        qp_init_attr.cap.max_send_sge = 2;
        qp_init_attr.cap.max_recv_sge = 1;
        qp_init_attr.sq_sig_all = 1;
        qp = ibv_create_qp(pd, &qp_init_attr);
        if (!qp)
            throw std::runtime_error("ibv_create_qp failed");

        // Move to RTS state
        modify_state(IBV_QPS_INIT, cm_id->port_num);
        modify_state(IBV_QPS_RTR);
        modify_state(IBV_QPS_RTS);

        // Prepare packets
        auto dst_mac = multicast_mac(endpoint.address());
        packets.reserve(depth);
        for (std::size_t i = 0; i < depth; i++)
        {
            packets.emplace_back(pd, 65535, src_mac, dst_mac, src_endpoint, endpoint);
            available.push(&packets.back());
        }
    }

    ~ibv_transmit()
    {
        if (qp != nullptr)
            ibv_destroy_qp(qp);
        if (cq != nullptr)
            ibv_destroy_cq(cq);
        if (pd != nullptr)
            ibv_dealloc_pd(pd);
        if (cm_id != nullptr)
            rdma_destroy_id(cm_id);
        if (event_channel != nullptr)
            rdma_destroy_event_channel(event_channel);
    }

    template<typename Iterator>
    void send_packets(Iterator first, Iterator last)
    {
        if (first == last)
            return;
        std::size_t idx = 0;
        ibv_send_wr *prev = nullptr;
        ibv_send_wr *first_wr = nullptr;
        for (Iterator cur = first; cur != last; ++cur, ++idx)
        {
            if (available.empty())
                wait_for_wc();
            packet *pkt = available.top();
            available.pop();
            std::memcpy(pkt->payload(), cur->data, cur->len);
            pkt->set_length(cur->len);
            pkt->update_checksum();
            if (prev)
                prev->next = &pkt->wr;
            else
                first_wr = &pkt->wr;
            prev = &pkt->wr;
        }
        prev->next = nullptr;

        ibv_send_wr *bad;
        int status = ibv_post_send(qp, first_wr, &bad);
        if (status != 0)
            throw std::system_error(status, std::system_category(), "ibv_post_send failed");
    }

    void flush()
    {
        while (available.size() < packets.size())
            wait_for_wc();
    }
};

constexpr int ibv_transmit::depth;
constexpr int ibv_transmit::batch_size;
#endif

/// Wraps a transmitter to rate-limit it
template<typename Transmit>
class sender
{
private:
    boost::asio::io_service &io_service;
    Transmit transmit;
    std::chrono::time_point<std::chrono::high_resolution_clock> start_time;
    std::chrono::time_point<std::chrono::high_resolution_clock> next_send;
    std::chrono::nanoseconds pps_interval{0};
    double ns_per_byte = 0;
    bool limited = false;

public:
    static constexpr int batch_size = Transmit::batch_size;

    explicit sender(const options &opts, boost::asio::io_service &io_service)
        : io_service(io_service), transmit(opts, io_service)
    {
        start_time = next_send = std::chrono::high_resolution_clock::now();
        if (opts.pps != 0)
        {
            pps_interval = std::chrono::nanoseconds(uint64_t(1e9 / opts.pps));
            limited = true;
        }
        if (opts.mbps != 0)
        {
            ns_per_byte = 8000.0 / opts.mbps;
            limited = true;
        }
    }

    template<typename Iterator>
    void send_packets(Iterator first, Iterator last)
    {
        std::size_t send_bytes = 0;
        for (Iterator i = first; i != last; ++i)
            send_bytes += i->len;
        if (limited)
        {
            asio::basic_waitable_timer<std::chrono::high_resolution_clock> timer(io_service);
            timer.expires_at(next_send);
            timer.wait();
#pragma omp task
            {
                transmit.send_packets(first, last);
            }
            next_send += pps_interval;
            next_send += std::chrono::nanoseconds(uint64_t(ns_per_byte * send_bytes));
        }
        else
        {
#pragma omp task
            {
                transmit.send_packets(first, last);
            }
        }
    }

    void flush()
    {
        transmit.flush();
    }

    std::chrono::high_resolution_clock::duration elapsed() const
    {
        return std::chrono::high_resolution_clock::now() - start_time;
    }
};

class collector
{
private:
    std::vector<u_char> storage;
    std::vector<std::pair<std::size_t, std::size_t> > packet_offsets;

public:
    void add_packet(const packet &p)
    {
        std::size_t offset = storage.size();
        storage.insert(storage.end(), p.data, p.data + p.len);
        packet_offsets.emplace_back(offset, p.len);
    }

    template<typename Sender>
    void replay(Sender &s, int repeat) const
    {
        std::array<packet, Sender::batch_size> batch;
        for (int pass = 0; pass < repeat; pass++)
        {
            for (std::size_t i = 0; i < packet_offsets.size(); i += Sender::batch_size)
            {
                std::size_t end = std::min(i + Sender::batch_size, packet_offsets.size());
                std::size_t len = end - i;
                for (std::size_t j = i; j < end; j++)
                {
                    batch[j - i] = packet{storage.data() + packet_offsets[j].first, packet_offsets[j].second};
                }
                s.send_packets(batch.begin(), batch.begin() + len);
            }
        }
        s.flush();
    }

    template<typename Sender>
    void replay_mt(Sender &s, int repeat) const
    {
        constexpr int batch_size = Sender::batch_size;
        std::vector<packet> packets;
        packets.reserve(packet_offsets.size());
        for (const auto &p : packet_offsets)
        {
            packets.push_back(packet{storage.data() + p.first, p.second});
        }
#pragma omp parallel
        {
#pragma omp master
            for (int pass = 0; pass < repeat; pass++)
                {
                    for (std::size_t i = 0; i < packets.size(); i += batch_size)
                    {
                        std::size_t last = std::min(i + batch_size, packets.size());
                        s.send_packets(packets.begin() + i, packets.begin() + last);
                    }
                }
#pragma omp taskwait
        }
    }

    std::size_t get_bytes() const
    {
        return storage.size();
    }
};

static void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    const unsigned int eth_hsize = 14;
    bpf_u_int32 len = h->caplen;
    if (h->len != len)
    {
        std::cerr << "Skipping truncated packet\n";
        return;
    }
    if (len > eth_hsize)
    {
        bytes += eth_hsize;
        len -= eth_hsize;
        const unsigned int ip_hsize = (bytes[0] & 0xf) * 4;
        if (len >= ip_hsize + 8)
        {
            bytes += ip_hsize;
            len -= ip_hsize;
            const unsigned int udp_hsize = 8;
            bytes += udp_hsize;
            len -= udp_hsize;

            collector *h = (collector *) user;
            packet p = {bytes, len};
            h->add_packet(p);
        }
    }
}

static void prepare(pcap_t *p)
{
    struct bpf_program fp;
    if (pcap_datalink(p) != DLT_EN10MB)
        throw std::runtime_error("Capture does not contain Ethernet frames");
    if (pcap_compile(p, &fp, "udp", 1, PCAP_NETMASK_UNKNOWN) == -1)
        throw std::runtime_error("Failed to parse filter");
    if (pcap_setfilter(p, &fp) == -1)
    {
        pcap_freecode(&fp);
        throw std::runtime_error("Failed to set filter");
    }
    pcap_freecode(&fp);
}

template<typename Transmit>
static void run(pcap_t *p, const options &opts)
{
    boost::asio::io_service io_service;
    typedef sender<Transmit> sender_t;

    collector c;
    pcap_loop(p, -1, callback, (u_char *) &c);

    sender_t s(opts, io_service);
    if (opts.parallel)
        c.replay_mt(s, opts.repeat);
    else
        c.replay(s, opts.repeat);
    std::chrono::duration<double> elapsed = s.elapsed();
    std::int64_t bytes = c.get_bytes() * opts.repeat;

    double time = elapsed.count();
    std::cout << "Transmitted " << bytes << " in " << time << "s = "
        << bytes * 8.0 / time / 1e9 << "Gbps\n";
}

static options parse_args(int argc, char **argv)
{
    options defaults;
    options out;

    po::positional_options_description positional;
    positional.add("input-file", 1);

    po::options_description desc;
    desc.add_options()
        ("pps", po::value<double>(&out.pps), "packets per second (0 for max speed)")
        ("mbps", po::value<double>(&out.mbps), "bits per second (0 for max speed)")
        ("host", po::value<std::string>(&out.host)->default_value(defaults.host), "destination host")
        ("port", po::value<std::string>(&out.port)->default_value(defaults.port), "destination port")
        ("bind", po::value<std::string>(&out.bind)->default_value(defaults.bind), "local address (for multicast)")
        ("mode", po::value<std::string>(&out.mode)->default_value(defaults.mode), "transmit mode (asio/sendmmsg/ibv)")
        ("buffer-size", po::value<size_t>(&out.buffer_size)->default_value(defaults.buffer_size), "transmit buffer size (0 for system default)")
        ("repeat", po::value<size_t>(&out.repeat)->default_value(defaults.repeat), "send the data this many times")
        ("parallel", po::bool_switch(&out.parallel)->default_value(defaults.parallel), "send packets in parallel (MIGHT NOT BE THREADSAFE)")
        ;

    po::options_description hidden;
    hidden.add_options()
        ("input-file", po::value<std::string>(&out.input_file)->required());

    po::options_description all;
    all.add(desc);
    all.add(hidden);

    try
    {
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv)
                  .style(po::command_line_style::default_style & ~po::command_line_style::allow_guessing)
                  .options(all)
                  .positional(positional)
                  .run(), vm);
        po::notify(vm);
        if (vm.count("pps") && vm.count("mbps"))
            throw po::error("Cannot specify both --pps and --mbps");
        return out;
    }
    catch (po::error &e)
    {
        std::cerr << e.what() << "\n\n";
        std::cerr << "Usage: udpreplay [options] capturefile\n";
        std::cerr << desc;
        throw;
    }
}

std::shared_ptr<pcap_t> open_capture(const options &opts)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(opts.input_file.c_str(), errbuf);
    if (p == NULL)
    {
        throw std::runtime_error(errbuf);
    }
    return std::shared_ptr<pcap_t>(p, pcap_close);
}

int main(int argc, char **argv)
{
    try
    {
        options opts = parse_args(argc, argv);
        std::shared_ptr<pcap_t> p = open_capture(opts);
        prepare(p.get());
#if HAVE_SENDMMSG
        if (opts.mode == "sendmmsg")
        {
            run<sendmmsg_transmit>(p.get(), opts);
        }
        else
#endif
#if HAVE_IBV
        if (opts.mode == "ibv")
        {
            run<ibv_transmit>(p.get(), opts);
        }
        else
#endif
        if (opts.mode == "asio")
        {
            run<asio_transmit>(p.get(), opts);
        }
        else
        {
            std::cerr << "Mode '" << opts.mode << "' is not supported\n";
            return 1;
        }
    }
    catch (po::error &e)
    {
        return 1;
    }
    catch (std::runtime_error &e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
    return 0;
}
