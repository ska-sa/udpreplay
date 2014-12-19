/* Replays UDP packets from a pcap dump. Unlike tcpreplay, it only replays the
 * payload and not the headers, so it does not require root privileges and
 * works fine with the Linux loopback device.
 *
 * It supports rate control, either in packets per second or bits per second.
 * It does not support replay at the original speed.
 *
 * It is currently single-threaded, and hence can fall behind the requested
 * rate if pcap is too slow.
 */

#define USE_SENDMMSG 1

#if USE_SENDMMSG
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <arpa/inet.h>
#endif
#include <iostream>
#include <memory>
#include <vector>
#include <list>
#include <chrono>
#include <cstring>
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
    bool parallel = false;
    std::string host = "localhost";
    std::string port = "8888";
    std::string input_file;
};

struct packet
{
    const u_char *data;
    std::size_t len;
};

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
        if (opts.buffer_size != 0)
            socket.set_option(decltype(socket)::send_buffer_size(opts.buffer_size));
    }

    template<typename Iterator>
    void send_packets(Iterator first, Iterator last)
    {
        assert(last - first == 1);
        socket.send_to(asio::buffer(first->data, first->len), endpoint);
    }
};

constexpr int asio_transmit::batch_size;

class sendmmsg_transmit
{
public:
    static constexpr int batch_size = 1;

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
        if (opts.buffer_size != 0)
            socket.set_option(decltype(socket)::send_buffer_size(opts.buffer_size));
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
            throw std::runtime_error("sendmmsg failed: status=" + std::to_string(status));
        for (int i = 0; i < next; i++)
            if (msg_vec[i].msg_len != msg_iov[i].iov_len)
                throw std::runtime_error("short write");
    }
};

constexpr int sendmmsg_transmit::batch_size;

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

static int run(pcap_t *p, const options &opts)
{
    struct bpf_program fp;
    if (pcap_datalink(p) != DLT_EN10MB)
    {
        std::cerr << "Capture does not contain Ethernet frames\n";
        return 1;
    }

    if (pcap_compile(p, &fp, "udp", 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "Failed to parse filter";
        return 1;
    }

    if (pcap_setfilter(p, &fp) == -1)
    {
        std::cerr << "Failed to set filter\n";
        return 1;
    }

    boost::asio::io_service io_service;
    std::chrono::duration<double> elapsed;
    std::int64_t bytes;
#if USE_SENDMMSG
    typedef sender<sendmmsg_transmit> sender_t;
#else
    typedef sender<asio_transmit> sender_t;
#endif

    collector c;
    pcap_loop(p, -1, callback, (u_char *) &c);

    sender_t s(opts, io_service);
    if (opts.parallel)
        c.replay_mt(s, opts.repeat);
    else
        c.replay(s, opts.repeat);
    elapsed = s.elapsed();
    bytes = c.get_bytes() * opts.repeat;

    double time = elapsed.count();
    std::cout << "Transmitted " << bytes << " in " << time << "s = "
        << bytes * 8.0 / time / 1e9 << "Gbps\n";
    return 0;
}

static options parse_args(int argc, char **argv)
{
    options defaults;
    options out;

    po::positional_options_description positional;
    positional.add("input-file", 1);

    po::options_description desc;
    desc.add_options()
        ("pps", po::value<double>(&out.pps), "packets per second (0 for max speed")
        ("mbps", po::value<double>(&out.mbps), "bits per second (0 for max speed")
        ("host", po::value<std::string>(&out.host)->default_value(defaults.host), "destination host")
        ("port", po::value<std::string>(&out.port)->default_value(defaults.port), "destination port")
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
        run(p.get(), opts);
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
