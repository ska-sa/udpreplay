/* Copyright 2015, 2020 SKA South Africa
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
#include <iostream>
#include <memory>
#include <vector>
#include <list>
#include <chrono>
#include <cstring>
#include <sstream>
#include <cerrno>
#include <atomic>
#include <thread>
#include <future>
#include <system_error>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/program_options.hpp>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#if HAVE_LINUX_IF_PACKET_H
# include <linux/if_packet.h>
# include <linux/if_ether.h>
# include <linux/ip.h>
# include <linux/udp.h>
# include <linux/filter.h>
#endif

#if HAVE_RECVMMSG && HAVE_SYS_TIMERFD_H
# define USE_RECVMMSG 1
#else
# define USE_RECVMMSG 0
#endif
#if USE_RECVMMSG
# include <sys/timerfd.h>
#endif

#if HAVE_LIBURING && HAVE_LIBURING_H
# define USE_IO_URING 1
#else
# define USE_IO_URING 0
#endif
#if USE_IO_URING
# include <liburing.h>
# include <sys/timerfd.h>
#endif

namespace asio = boost::asio;
namespace po = boost::program_options;
using boost::asio::ip::udp;

struct options
{
    std::string host = "";
    std::string port = "8888";
    std::size_t socket_size = 0;
    std::size_t packet_size = 16384;
    std::size_t buffer_size = 0;
    std::string interface = "";
    std::string mode = "asio";
    int threads = 0;
    int poll = 0;
    bool affinity = false;
};

[[noreturn]] static void throw_errno(int err)
{
    throw std::system_error(err, std::system_category());
}

[[noreturn]] static void throw_errno()
{
    throw_errno(errno);
}

static options parse_args(int argc, char **argv)
{
    options out;

    po::options_description desc;
    desc.add_options()
        ("host", po::value<std::string>(&out.host)->default_value(out.host), "destination host")
        ("port,p", po::value<std::string>(&out.port)->default_value(out.port), "destination port")
        ("socket-size", po::value<std::size_t>(&out.socket_size)->default_value(out.socket_size), "receive buffer size (0 for system default)")
        ("packet-size", po::value<std::size_t>(&out.packet_size)->default_value(out.packet_size), "maximum packet size")
        ("buffer-size", po::value<std::size_t>(&out.buffer_size)->default_value(out.buffer_size), "size of receive arena (0 for packet size)")
        ("poll", po::value<int>(&out.poll)->default_value(out.poll), "make up to this many synchronous reads")
        ("interface,i", po::value<std::string>(&out.interface)->default_value(out.interface), "interface to bind (not all modes)")
        ("mode,m", po::value<std::string>(&out.mode)->default_value(out.mode), "capture mode (asio/recvmmsg/pcap/pfpacket/io_uring)")
        ("threads,t", po::value<int>(&out.threads)->default_value(out.threads), "number of threads (0 for auto) (not all modes)")
        ("affinity", po::bool_switch(&out.affinity)->default_value(out.affinity), "use CPU affinity (not all modes)")
        ;
    try
    {
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv)
                  .style(po::command_line_style::default_style & ~po::command_line_style::allow_guessing)
                  .options(desc)
                  .run(), vm);
        po::notify(vm);
        return out;
    }
    catch (po::error &e)
    {
        std::cerr << e.what() << "\n\n";
        std::cerr << "Usage: udpcount [options]\n";
        std::cerr << desc;
        throw;
    }
}

template<typename T>
class metrics
{
public:
    T packets;
    T bytes;
    T total_packets;
    T total_bytes;
    T truncated;
    T errors;

    metrics()
    {
        packets = 0;
        bytes = 0;
        total_packets = 0;
        total_bytes = 0;
        truncated = 0;
        errors = 0;
    }

    void add_packet(std::size_t bytes_transferred, bool is_truncated)
    {
        truncated += is_truncated;
        packets++;
        total_packets++;
        bytes += bytes_transferred;
        total_bytes += bytes_transferred;
    }

    void add_error()
    {
        errors++;
    }

    void reset()
    {
        packets = 0;
        bytes = 0;
        errors = 0;
        truncated = 0;
    }

    void show_stats(double elapsed)
    {
        std::cout << total_packets << " (" << packets / elapsed << ") packets\t"
            << total_bytes << " bytes ("
            << bytes * 8.0 / 1e9 / elapsed << " Gb/s)\t"
            << errors << " errors\t" << truncated << " trunc\n";
    }

    template<typename U>
    metrics &operator+=(const metrics<U> &other)
    {
        packets += other.packets;
        bytes += other.bytes;
        total_packets += other.total_packets;
        total_bytes += other.total_bytes;
        truncated += other.truncated;
        errors += other.errors;
        return *this;
    }
};

template<typename T>
class runner
{
private:
    std::chrono::steady_clock::time_point last_stats;

protected:
    asio::io_service io_service;
    metrics<T> counters;
    udp::endpoint local_endpoint;

    std::chrono::steady_clock::time_point get_last_stats() const
    {
        return last_stats;
    }

    void show_stats(std::chrono::steady_clock::time_point now)
    {
        typedef std::chrono::duration<double> duration_t;
        auto elapsed = std::chrono::duration_cast<duration_t>(now - last_stats).count();
        counters.show_stats(elapsed);
        counters.reset();
        last_stats = now;
    }

    explicit runner(const options &opts) : last_stats(std::chrono::steady_clock::now())
    {
        udp::resolver resolver(io_service);
        udp::resolver::query query(
            udp::v4(), opts.host, opts.port,
            udp::resolver::query::passive | udp::resolver::query::address_configured);
        local_endpoint = *resolver.resolve(query);
    }
};

/* Helper base class that creates and opens a socket. It is used by the basic
 * asio_runner, but also by pcap_runner and pfpacket_runner to have a socket
 * open to prevent ICMP connection refused replies even though none of the
 * data is consumed.
 */
template<typename T>
class socket_runner : public runner<T>
{
protected:
    udp::socket socket;

    explicit socket_runner(const options &opts) : runner<T>(opts), socket(this->io_service)
    {
        socket.open(udp::v4());
        socket.set_option(udp::socket::reuse_address());
        socket.bind(this->local_endpoint);
    }

    // Prepare socket for use in the data plane
    void prepare_socket(const options &opts)
    {
        socket.non_blocking(true);
        if (opts.socket_size != 0)
        {
            socket.set_option(udp::socket::receive_buffer_size(opts.socket_size));
            udp::socket::receive_buffer_size actual;
            socket.get_option(actual);
            if ((std::size_t) actual.value() != opts.socket_size)
            {
                std::cerr << "Warning: requested socket buffer size of " << opts.socket_size
                    << " but actual size is " << actual.value() << '\n';
            }
        }
    }
};

class asio_runner : public socket_runner<std::int64_t>
{
private:
    asio::basic_waitable_timer<std::chrono::steady_clock> timer;
    std::vector<std::uint8_t> buffer;
    const std::size_t packet_size;
    const int poll;
    std::size_t offset = 0;
    udp::endpoint remote;

    void enqueue_receive()
    {
        using namespace std::placeholders;
        socket.async_receive_from(
            asio::buffer(buffer.data() + offset, packet_size),
            remote,
            std::bind(&asio_runner::packet_handler, this, _1, _2));
    }

    void enqueue_wait()
    {
        using namespace std::placeholders;
        timer.async_wait(std::bind(&asio_runner::timer_handler, this, _1));
    }

    void update_counters(std::size_t bytes_transferred)
    {
        counters.add_packet(bytes_transferred, bytes_transferred == packet_size);
        offset += bytes_transferred;
        // Round up to a cache line offset
        offset = ((offset + 63) & ~63);
        if (offset >= buffer.size() - packet_size)
            offset = 0;
    }

    void packet_handler(const boost::system::error_code &error,
                        std::size_t bytes_transferred)
    {
        if (error)
            counters.add_error();
        else
            update_counters(bytes_transferred);
        for (int i = 0; i < poll; i++)
        {
            boost::system::error_code ec;
            bytes_transferred = socket.receive_from(
                asio::buffer(buffer.data() + offset, packet_size),
                remote, 0, ec);
            if (ec == asio::error::would_block)
                break;
            else if (ec)
                counters.add_error();
            else
                update_counters(bytes_transferred);
        }
        enqueue_receive();
    }

    void timer_handler(const boost::system::error_code &error)
    {
        auto now = timer.expires_at();
        show_stats(now);
        timer.expires_at(timer.expires_at() + std::chrono::seconds(1));
        enqueue_wait();
    }

public:
    explicit asio_runner(const options &opts)
        : socket_runner<std::int64_t>(opts), timer(io_service),
        buffer(std::max(opts.packet_size, opts.buffer_size)), packet_size(opts.packet_size), poll(opts.poll)
    {
        prepare_socket(opts);
        timer.expires_from_now(std::chrono::seconds(1));

        enqueue_wait();
        enqueue_receive();
    }

    void run()
    {
        io_service.run();
    }
};

class file_descriptor : public boost::noncopyable
{
public:
    int fd;

    explicit file_descriptor(int fd = -1) : fd(fd) {}

    file_descriptor(file_descriptor &&other) : fd(other.fd)
    {
        other.fd = -1;
    }

    file_descriptor &operator=(file_descriptor &&other)
    {
        if (this != &other)
        {
            if (fd != -1)
                close(fd);
            fd = other.fd;
            other.fd = -1;
        }
        return *this;
    }

    ~file_descriptor()
    {
        if (fd != -1)
            close(fd);
    }
};

#if USE_RECVMMSG
class recvmmsg_runner : public socket_runner<std::int64_t>
{
private:
    file_descriptor timerfd;
    std::vector<std::uint8_t> buffer;
    std::vector<struct mmsghdr> msgvec;
    std::vector<struct iovec> iovec;
    const int n_poll;

    static constexpr int batch_size = 64;

public:
    explicit recvmmsg_runner(const options &opts)
        : socket_runner<std::int64_t>(opts),
        buffer(std::max(opts.buffer_size, batch_size * opts.packet_size)),
        msgvec(batch_size), iovec(batch_size), n_poll(opts.poll)
    {
        prepare_socket(opts);
        for (int i = 0; i < batch_size; i++)
        {
            std::memset(&msgvec[i], 0, sizeof(msgvec[i]));
            msgvec[i].msg_hdr.msg_iov = &iovec[i];
            msgvec[i].msg_hdr.msg_iovlen = 1;
            iovec[i].iov_base = buffer.data() + opts.packet_size * i;
            iovec[i].iov_len = opts.packet_size;
        }

        int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
        if (fd < 0)
            throw_errno();
        timerfd = file_descriptor(fd);

        itimerspec spec;
        spec.it_interval.tv_sec = 1;
        spec.it_interval.tv_nsec = 0;
        spec.it_value = spec.it_interval;
        if (timerfd_settime(fd, 0, &spec, NULL) < 0)
            throw_errno();
    }

    bool process_packets()
    {
        int result = recvmmsg(socket.native_handle(), msgvec.data(), msgvec.size(), 0, NULL);
        if (result < 0)
        {
            if (errno != EAGAIN)
                throw_errno();
            return false;
        }
        for (int i = 0; i < result; i++)
        {
            bool trunc = (msgvec[i].msg_hdr.msg_flags & MSG_TRUNC);
            counters.add_packet(msgvec[i].msg_len, trunc);
        }
        return true;
    }

    void run()
    {
        pollfd fds[2] = {};
        fds[0].fd = socket.native_handle();
        fds[0].events = POLLIN;
        fds[1].fd = timerfd.fd;
        fds[1].events = POLLIN;
        /* This might not be perfectly synced with the timer, but all
         * that actually matters is that we advance it each time the
         * timer fires.
         */
        auto alarm_time = std::chrono::steady_clock::now();
        while (true)
        {
            int result = poll(fds, 2, -1);
            if (result < 0)
                throw_errno();
            if (fds[0].revents & POLLIN)
            {
                for (int i = 0; i <= n_poll; i++)
                    if (!process_packets())
                        break;
            }
            if (fds[1].revents & POLLIN)
            {
                uint64_t fired;
                result = read(timerfd.fd, &fired, sizeof(fired));
                if (result < 0)
                {
                    if (errno != EAGAIN)
                        throw_errno();
                }
                else
                {
                    alarm_time += std::chrono::seconds(fired);
                    show_stats(alarm_time);
                }
            }
        }
    }
};
#endif  // USE_RECVMMSG

#if USE_IO_URING
class io_uring_runner : public socket_runner<std::int64_t>
{
private:
    io_uring ring;
    std::vector<std::uint8_t> buffer;
    std::vector<struct iovec> iovec;
    std::vector<struct msghdr> msgvec;
    __kernel_timespec timeout;

    static constexpr int entries = 64;
    static constexpr int depth = entries - 1;  // one slot reserved for timeout
    static constexpr int batch = 32;

public:
    explicit io_uring_runner(const options &opts)
        : socket_runner<std::int64_t>(opts),
        buffer(std::max(opts.buffer_size, depth * opts.packet_size)),
        iovec(depth), msgvec(depth)
    {
        prepare_socket(opts);
        socket.non_blocking(false);
        int result = io_uring_queue_init(entries, &ring, 0);
        if (result < 0)
            throw_errno(-result);

        for (int i = 0; i < depth; i++)
        {
            iovec[i].iov_base = buffer.data() + i * opts.packet_size;
            iovec[i].iov_len = opts.packet_size;
            std::memset(&msgvec[i], 0, sizeof(msgvec[i]));
            msgvec[i].msg_iov = &iovec[i];
            msgvec[i].msg_iovlen = 1;
        }

        timeout.tv_sec = 1;
        timeout.tv_nsec = 0;
    }

    ~io_uring_runner()
    {
        io_uring_queue_exit(&ring);
    }

    void run()
    {
        for (int i = 0; i < depth; i++)
        {
            io_uring_sqe *sqe = io_uring_get_sqe(&ring);
            io_uring_prep_recvmsg(sqe, socket.native_handle(), &msgvec[i], 0);
            io_uring_sqe_set_data(sqe, &msgvec[i]);
        }
        io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        io_uring_prep_timeout(sqe, &timeout, 0, 0);
        io_uring_sqe_set_data(sqe, &timeout);

        while (true)
        {
            int ret = io_uring_submit_and_wait(&ring, batch);
            if (ret < 0)
                throw_errno(-ret);
            int seen = 0;
            io_uring_cqe *cqe;
            unsigned head;
            io_uring_for_each_cqe(&ring, head, cqe)
            {
                seen++;
                if ((void *) cqe->user_data == &timeout)
                {
                    // Don't check the error code - it will most likely be -ETIME
                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_timeout(sqe, &timeout, 0, 0);
                    io_uring_sqe_set_data(sqe, &timeout);
                    show_stats(std::chrono::steady_clock::now());
                }
                else
                {
                    if (cqe->res < 0)
                    {
                        int err = -cqe->res;
                        throw_errno(err);
                    }
                    msghdr *hdr = (msghdr *) cqe->user_data;
                    bool trunc = (hdr->msg_flags & MSG_TRUNC);
                    counters.add_packet(cqe->res, trunc);

                    sqe = io_uring_get_sqe(&ring);
                    io_uring_prep_recvmsg(sqe, socket.native_handle(), hdr, 0);
                    io_uring_sqe_set_data(sqe, hdr);
                }
                if (seen == batch)
                    break;
            }
            io_uring_cq_advance(&ring, seen);
        }
    }
};
#endif  // USE_IO_URING

class pcap_runner : public socket_runner<std::int64_t>
{
private:
    pcap_t *cap;

    pcap_runner(const pcap_runner &) = delete;
    pcap_runner &operator=(const pcap_runner &) = delete;

    static void check_status(int status)
    {
        if (status != 0)
            throw std::runtime_error(pcap_statustostr(status));
    }

    void process_packet(const struct pcap_pkthdr *h, const u_char *bytes)
    {
        const unsigned int eth_hsize = 14;
        bpf_u_int32 len = h->caplen;
        bool truncated = h->len != len;
        if (len > eth_hsize)
        {
            bytes += eth_hsize;
            len -= eth_hsize;
            const unsigned int ip_hsize = (bytes[0] & 0xf) * 4;
            const unsigned int udp_hsize = 8;
            if (len >= ip_hsize + udp_hsize)
                counters.add_packet(len - (ip_hsize + udp_hsize), truncated);
        }
    }

public:
    explicit pcap_runner(const options &opts) : socket_runner<std::int64_t>(opts)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        cap = pcap_create(opts.interface.c_str(), errbuf);
        if (cap == NULL)
            throw std::runtime_error(std::string(errbuf));
        check_status(pcap_set_snaplen(cap, opts.packet_size));
        if (opts.socket_size != 0)
            check_status(pcap_set_buffer_size(cap, opts.socket_size));
        check_status(pcap_set_timeout(cap, 10));
        check_status(pcap_activate(cap));
        int ret = pcap_set_datalink(cap, DLT_EN10MB);
        if (ret != 0)
            throw std::runtime_error(std::string(pcap_geterr(cap)));
        ret = pcap_setdirection(cap, PCAP_D_IN);
        if (ret != 0)
            throw std::runtime_error(std::string(pcap_geterr(cap)));

        struct bpf_program fp;
        std::ostringstream program;
        program << "ip and udp dst port " << local_endpoint.port();
        if (opts.host != "")
            program << " and dst host " << local_endpoint.address().to_string();
        if (pcap_compile(cap, &fp, program.str().c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1)
            throw std::runtime_error("Failed to parse filter");
        if (pcap_setfilter(cap, &fp) == -1)
        {
            pcap_freecode(&fp);
            throw std::runtime_error(std::string(pcap_geterr(cap)));
        }
        pcap_freecode(&fp);
    }

    ~pcap_runner()
    {
        pcap_close(cap);
    }

    void run()
    {
        while (true)
        {
            struct pcap_pkthdr *pkt_header;
            const u_char *pkt_data;
            int status = pcap_next_ex(cap, &pkt_header, &pkt_data);
            switch (status)
            {
            case 1:
                // Valid packet
                process_packet(pkt_header, pkt_data);
                break;
            case 0:
                // Timeout expired; this is harmless
                break;
            case -1:
                // Error
                throw std::runtime_error(std::string(pcap_geterr(cap)));
            default:
                throw std::runtime_error("unexpected return from pcap_next_ex");
            }
            auto now = std::chrono::steady_clock::now();
            if (now - get_last_stats() >= std::chrono::seconds(1))
                show_stats(now);
        }
    }
};

template<typename T>
static void apply_offset(T *&out, void *in, std::ptrdiff_t offset)
{
    out = reinterpret_cast<T *>(reinterpret_cast<std::uint8_t *>(in) + offset);
}

template<typename T>
static void apply_offset(const T *&out, const void *in, std::ptrdiff_t offset)
{
    out = reinterpret_cast<const T *>(reinterpret_cast<const std::uint8_t *>(in) + offset);
}

class memory_map : public boost::noncopyable
{
public:
    std::uint8_t *ptr;
    std::size_t length;

    memory_map() : ptr(NULL), length(0) {}
    memory_map(std::uint8_t *ptr, std::size_t length) : ptr(ptr), length(length) {}

    memory_map(memory_map &&other) : ptr(other.ptr), length(other.length)
    {
        other.ptr = NULL;
        other.length = 0;
    }

    ~memory_map()
    {
        if (ptr != NULL)
            munmap(ptr, length);
    }
};

#if HAVE_LINUX_IF_PACKET_H
class pfpacket_runner : public socket_runner<std::atomic<std::int64_t>>
{
private:
    struct thread_data_t
    {
        file_descriptor fd;
        memory_map map;
    };

    tpacket_req3 ring_req;
    std::vector<thread_data_t> thread_data;
    bool use_affinity;

    void set_packet_filter(int fd)
    {
        sock_filter code_no_host[] =
        {
            { 0x28, 0, 0, 0x0000000c },
            { 0x15, 0, 8, 0x00000800 },
            { 0x30, 0, 0, 0x00000017 },
            { 0x15, 0, 6, 0x00000011 },
            { 0x28, 0, 0, 0x00000014 },
            { 0x45, 4, 0, 0x00001fff },
            { 0xb1, 0, 0, 0x0000000e },
            { 0x48, 0, 0, 0x00000010 },
            { 0x15, 0, 1, local_endpoint.port() },
            { 0x6, 0, 0, 0x0000ffff },
            { 0x6, 0, 0, 0x00000000 }
        };
        sock_filter code_host[] =
        {
            { 0x28, 0, 0, 0x0000000c },
            { 0x15, 0, 10, 0x00000800 },
            { 0x30, 0, 0, 0x00000017 },
            { 0x15, 0, 8, 0x00000011 },
            { 0x28, 0, 0, 0x00000014 },
            { 0x45, 6, 0, 0x00001fff },
            { 0xb1, 0, 0, 0x0000000e },
            { 0x48, 0, 0, 0x00000010 },
            { 0x15, 0, 3, local_endpoint.port() },
            { 0x20, 0, 0, 0x0000001e },
            { 0x15, 0, 1, (std::uint32_t) local_endpoint.address().to_v4().to_ulong() },
            { 0x6, 0, 0, 0x0000ffff },
            { 0x6, 0, 0, 0x00000000 },
        };
        sock_fprog prog_no_host =
        {
            sizeof(code_no_host) / sizeof(code_no_host[0]),
            code_no_host
        };
        sock_fprog prog_host =
        {
            sizeof(code_host) / sizeof(code_host[0]),
            code_host
        };
        sock_fprog *prog = local_endpoint.address().is_unspecified() ? &prog_no_host : &prog_host;
        int status = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, prog, sizeof(*prog));
        if (status < 0)
            throw_errno();
    }

    void prepare_thread_data(thread_data_t &data, const options &opts)
    {
        int status;
        // Create the socket
        int fd = ::socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd < 0)
            throw_errno();
        data.fd.fd = fd;
        // Set up the packet filter.
        set_packet_filter(fd);

        // Bind it to interface
        if (opts.interface != "")
        {
            ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, opts.interface.c_str(), sizeof(ifr.ifr_name));
            status = ioctl(fd, SIOCGIFINDEX, &ifr);
            if (status < 0)
                throw_errno();
            sockaddr_ll addr;
            memset(&addr, 0, sizeof(addr));
            addr.sll_family = AF_PACKET;
            addr.sll_protocol = htons(ETH_P_ALL);
            addr.sll_ifindex = ifr.ifr_ifindex;
            status = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
            if (status < 0)
                throw_errno();
        }
        // Join the FANOUT group
        int fanout = (getpid() & 0xffff) | (PACKET_FANOUT_CPU << 16);
        status = setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &fanout, sizeof(fanout));
        if (status < 0)
            throw_errno();
        // Set to version 3
        int version = TPACKET_V3;
        status = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
        if (status < 0)
            throw_errno();
        // Set up the ring buffer
        status = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &ring_req, sizeof(ring_req));
        if (status < 0)
            throw_errno();
        std::size_t length = ring_req.tp_block_size * ring_req.tp_block_nr;
        void *ptr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
        if (ptr == NULL)
            throw_errno();
        data.map.ptr = (std::uint8_t *) ptr;
        data.map.length = length;
    }

    void process_packet(const tpacket3_hdr *header, metrics<std::int64_t> &local_counters)
    {
        bool truncated = header->tp_snaplen != header->tp_len;
        const ethhdr *eth;
        const iphdr *ip;
        apply_offset(eth, header, header->tp_mac);
        apply_offset(ip, eth, ETH_HLEN);
        if (eth->h_proto == htons(ETH_P_IP))
        {
            const unsigned int ip_hsize = ip->ihl * 4;
            // TODO: check for IP options
            local_counters.add_packet(header->tp_len - ETH_HLEN - ip_hsize - sizeof(udphdr), truncated);
        }
    }

public:
    explicit pfpacket_runner(const options &opts) : socket_runner<std::atomic<std::int64_t>>(opts)
    {
        use_affinity = opts.affinity;
        // Set up ring buffer parameters
        memset(&ring_req, 0, sizeof(ring_req));
        ring_req.tp_block_size = 1 << 22;
        ring_req.tp_frame_size = 1 << 11;
        ring_req.tp_block_nr = 1 << 6;
        ring_req.tp_frame_nr = ring_req.tp_block_size / ring_req.tp_frame_size * ring_req.tp_block_nr;
        ring_req.tp_retire_blk_tov = 10;

        // Create per-thread sockets
        int threads = opts.threads;
        if (threads == 0)
        {
            cpu_set_t affinity;
            int status = sched_getaffinity(0, sizeof(affinity), &affinity);
            if (status < 0)
                throw_errno();
            threads = CPU_COUNT(&affinity);
        }
        thread_data.resize(threads);
        for (int i = 0; i < threads; i++)
            prepare_thread_data(thread_data[i], opts);
    }

    void run_thread(thread_data_t &data, int cpu)
    {
        int status;
        if (use_affinity)
        {
            cpu_set_t old;
            cpu_set_t affinity;
            status = sched_getaffinity(0, sizeof(old), &old);
            if (status < 0)
                throw_errno();
            cpu %= CPU_COUNT(&old);

            int hw_cpu = 0;
            for (int i = 0; i <= cpu; i++)
            {
                while (!CPU_ISSET(hw_cpu, &old))
                    hw_cpu++;
                CPU_CLR(hw_cpu, &old);
            }

            CPU_ZERO(&affinity);
            CPU_SET(hw_cpu, &affinity);
            status = sched_setaffinity(0, sizeof(affinity), &affinity);
            if (status < 0)
                throw_errno();
        }
        unsigned int next_block = 0;
        pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = data.fd.fd;
        pfd.events = POLLIN | POLLERR;
        while (true)
        {
            tpacket_block_desc *block_desc;
            apply_offset(block_desc, data.map.ptr, next_block * ring_req.tp_block_size);
            std::atomic_thread_fence(std::memory_order_acquire);
            while (!(block_desc->hdr.bh1.block_status & TP_STATUS_USER))
            {
                status = poll(&pfd, 1, 10);
                if (status < 0)
                    throw_errno();
                std::atomic_thread_fence(std::memory_order_acquire);
            }

            std::size_t num_packets = block_desc->hdr.bh1.num_pkts;
            tpacket3_hdr *header;
            apply_offset(header, block_desc, block_desc->hdr.bh1.offset_to_first_pkt);
            metrics<std::int64_t> local_counters;
            for (std::size_t i = 0; i < num_packets; i++)
            {
                process_packet(header, local_counters);
                apply_offset(header, header, header->tp_next_offset);
            }
            counters += local_counters;

            block_desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
            std::atomic_thread_fence(std::memory_order_release);
            next_block++;
            if (next_block == ring_req.tp_block_nr)
                next_block = 0;
        }
    }

    void run()
    {
        std::vector<std::future<void>> futures;
        int cpu = 0;
        for (auto &data : thread_data)
        {
            auto call = [&data, cpu, this] { run_thread(data, cpu); };
            futures.push_back(std::async(std::launch::async, call));
            cpu++;
        }
        auto now = std::chrono::steady_clock::now();
        while (true)
        {
            now += std::chrono::seconds(1);
            std::this_thread::sleep_until(now);
            show_stats(now);
        }
    }
};
#endif  // HAVE_LINUX_IF_PACKET_H

int main(int argc, char **argv)
{
    try
    {
        options opts = parse_args(argc, argv);
#if HAVE_LINUX_IF_PACKET_H
        if (opts.mode == "pfpacket")
        {
            pfpacket_runner r(opts);
            r.run();
        }
        else
#endif // HAVE_LINUX_IF_PACKET_H
#if USE_RECVMMSG
        if (opts.mode == "recvmmsg")
        {
            recvmmsg_runner r(opts);
            r.run();
        }
        else
#endif
#if USE_IO_URING
        if (opts.mode == "io_uring")
        {
            io_uring_runner r(opts);
            r.run();
        }
        else
#endif
        if (opts.mode == "pcap")
        {
            pcap_runner r(opts);
            r.run();
        }
        else if (opts.mode == "asio")
        {
            asio_runner r(opts);
            r.run();
        }
        else
        {
            std::cerr << "Mode " << opts.mode << " is not known\n";
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
