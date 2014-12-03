#include <iostream>
#include <memory>
#include <chrono>
#include <pcap.h>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>

namespace asio = boost::asio;
namespace po = boost::program_options;
using boost::asio::ip::udp;

struct options
{
    double pps = 0;
    size_t buffer_size = 1024 * 1024;
    std::string host = "localhost";
    std::string port = "12345";
    std::string input_file;
};

struct sender
{
    boost::asio::io_service io_service;
    udp::socket socket;
    udp::endpoint endpoint;
    std::chrono::time_point<std::chrono::high_resolution_clock> next_send;
    std::chrono::nanoseconds interval;

    explicit sender(const options &opts)
        : socket(io_service)
    {
        udp::resolver resolver(io_service);
        udp::resolver::query query(udp::v4(), opts.host, opts.port);
        endpoint = *resolver.resolve(query);
        socket.open(udp::v4());
        if (opts.buffer_size != 0)
            socket.set_option(decltype(socket)::send_buffer_size(opts.buffer_size));
        next_send = std::chrono::high_resolution_clock::now();
        interval = std::chrono::nanoseconds(opts.pps ? long(1000000000 / opts.pps) : 0);
    }

    void send_packet(const u_char *data, std::size_t len)
    {
        asio::basic_waitable_timer<std::chrono::high_resolution_clock> timer(io_service);
        timer.expires_at(next_send);
        timer.wait();
        socket.send_to(asio::buffer(data, len), endpoint);
        next_send += interval;
    }
};

static void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    std::cout << "Got a packet\n";
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

            sender *s = (sender *) user;
            s->send_packet(bytes, len);
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

    sender s(opts);
    pcap_loop(p, -1, callback, (u_char *) &s);
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
        ("pps", po::value<double>(&out.pps)->default_value(defaults.pps), "packets per second (0 for max speed")
        ("host", po::value<std::string>(&out.host)->default_value(defaults.host), "destination host")
        ("port", po::value<std::string>(&out.port)->default_value(defaults.port), "destination port")
        ("buffer-size", po::value<size_t>(&out.buffer_size)->default_value(defaults.buffer_size), "transmit buffer size (0 for system default)")
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
        return out;
    }
    catch (po::error &e)
    {
        std::cerr << e.what() << "\n\n";
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
