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

#ifndef UDPREPLAY_IBV_TRANSMIT_H
#define UDPREPLAY_IBV_TRANSMIT_H

#include <config.h>

#if HAVE_IBV

#include <memory>
#include <vector>
#include <deque>
#include <array>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <boost/noncopyable.hpp>
#include <boost/asio.hpp>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "common.h"

typedef std::array<std::uint8_t, 6> mac_address;

struct freeifaddrs_deleter
{
    void operator()(ifaddrs *ifa) const { freeifaddrs(ifa); }
};

struct mr_deleter
{
    void operator()(ibv_mr *mr) const { ibv_dereg_mr(mr); }
};

struct cq_deleter
{
    void operator()(ibv_cq *cq) const { ibv_destroy_cq(cq); }
};

struct qp_deleter
{
    void operator()(ibv_qp *qp) const { ibv_destroy_qp(qp); }
};

struct pd_deleter
{
    void operator()(ibv_pd *pd) const { ibv_dealloc_pd(pd); }
};

struct event_channel_deleter
{
    void operator()(rdma_event_channel *event_channel) const { rdma_destroy_event_channel(event_channel); }
};

struct cm_id_deleter
{
    void operator()(rdma_cm_id *cm_id) const { rdma_destroy_id(cm_id); }
};

template<typename T>
class mmap_deleter
{
private:
    std::size_t size;

public:
    mmap_deleter() = default;
    mmap_deleter(std::size_t size) : size(size) {}

    void operator()(T *ptr) const
    {
        munmap(ptr, size);
    }
};

class ibv_collector
{
private:
    struct slab
    {
        std::unique_ptr<std::uint8_t[], mmap_deleter<std::uint8_t>> data;
        std::unique_ptr<ibv_mr, mr_deleter> mr;
        std::size_t capacity;
        std::size_t used;

        slab(ibv_pd *pd, std::size_t capacity);
    };

    struct frame : public boost::noncopyable
    {
        ibv_sge sge{};
        ibv_send_wr wr{};
        std::size_t packet_size;
        duration timestamp;
    };

    ibv_pd *pd;
    boost::asio::ip::udp::endpoint src_endpoint, dst_endpoint;
    mac_address src_mac, dst_mac;
    // Cannot use a vector, because it is non-copyable
    std::deque<frame> frames;
    std::vector<slab> slabs;
    std::size_t slab_size;
    std::size_t total_bytes = 0;

public:
    explicit ibv_collector(
        ibv_pd *pd,
        const boost::asio::ip::udp::endpoint &src_endpoint,
        const boost::asio::ip::udp::endpoint &dst_endpoint,
        const mac_address &src_mac,
        const mac_address &dst_mac,
        std::size_t slab_size = 64 * 1024 * 1024);

    void add_packet(const packet &pkt);
    std::size_t num_packets() const;
    std::size_t packet_size(std::size_t idx) const;
    duration packet_timestamp(std::size_t idx) const;
    std::size_t bytes() const;
    frame &get_frame(std::size_t idx);
};

class ibv_transmit
{
public:
    static constexpr int depth = 256;
    static constexpr int batch_size = 16;

private:
    std::unique_ptr<rdma_event_channel, event_channel_deleter> event_channel;
    std::unique_ptr<rdma_cm_id, cm_id_deleter> cm_id;
    std::unique_ptr<ibv_pd, pd_deleter> pd;
    std::unique_ptr<ibv_qp, qp_deleter> qp;
    std::unique_ptr<ibv_cq, cq_deleter> cq;
    boost::asio::ip::udp::socket socket; // only to allocate a port number
    std::size_t slots = depth;
    std::unique_ptr<ibv_collector> collector;

    void modify_state(ibv_qp_state state, int port_num = -1);
    void wait_for_wc();

public:
    typedef ibv_collector collector_type;

    ibv_transmit(const options &opts, boost::asio::io_service &io_service);

    collector_type &get_collector() { return *collector; }
    void send_packets(std::size_t first, std::size_t last, time_point start);
    void flush();
};

#endif // HAVE_IBV
#endif // UDPREPLAY_IBV_TRANSMIT_H
