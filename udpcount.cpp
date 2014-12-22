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

#include <iostream>
#include <memory>
#include <vector>
#include <list>
#include <chrono>
#include <cstring>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/program_options.hpp>

namespace asio = boost::asio;
namespace po = boost::program_options;
using boost::asio::ip::udp;

struct options
{
    std::string host = "";
    std::string port = "8888";
    std::size_t buffer_size = 0;
    std::size_t packet_size = 16384;
    int poll = 0;
};

static options parse_args(int argc, char **argv)
{
    options defaults;
    options out;

    po::positional_options_description positional;
    positional.add("input-file", 1);

    po::options_description desc;
    desc.add_options()
        ("host", po::value<std::string>(&out.host)->default_value(defaults.host), "destination host")
        ("port", po::value<std::string>(&out.port)->default_value(defaults.port), "destination port")
        ("buffer-size", po::value<std::size_t>(&out.buffer_size)->default_value(defaults.buffer_size), "receive buffer size (0 for system default)")
        ("packet-size", po::value<std::size_t>(&out.packet_size)->default_value(defaults.packet_size), "maximum packet size")
        ("poll", po::value<int>(&out.poll)->default_value(defaults.poll), "make up to this many synchronous reads")
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

class runner
{
private:
    asio::io_service io_service;
    udp::socket socket;
    asio::steady_timer timer;
    std::vector<std::uint8_t> buffer;
    udp::endpoint remote;
    int poll;
    std::int64_t packets = 0;
    std::int64_t bytes = 0;
    std::int64_t truncated = 0;
    std::int64_t errors = 0;

    void enqueue_receive()
    {
        using namespace std::placeholders;
        socket.async_receive_from(
            asio::buffer(buffer),
            remote,
            std::bind(&runner::packet_handler, this, _1, _2));
    }

    void enqueue_wait()
    {
        using namespace std::placeholders;
        timer.async_wait(std::bind(&runner::timer_handler, this, _1));
    }

    void packet_handler(const boost::system::error_code &error,
                        std::size_t bytes_transferred)
    {
        if (error)
        {
            errors++;
        }
        else
        {
            packets++;
            truncated += (bytes_transferred == buffer.size());
            bytes += bytes_transferred;
        }
        for (int i = 0; i < poll; i++)
        {
            boost::system::error_code ec;
            bytes_transferred = socket.receive_from(asio::buffer(buffer), remote, 0, ec);
            if (ec == asio::error::would_block)
                break;
            else if (ec)
                errors++;
            else
            {
                packets++;
                truncated += (bytes_transferred == buffer.size());
                bytes += bytes_transferred;
            }
        }
        enqueue_receive();
    }

    void timer_handler(const boost::system::error_code &error)
    {
        std::cout << packets << " packets\t" << bytes << " bytes ("
            << bytes * 8.0 / 1e9 << " Gb/s)\t"
            << errors << " errors\t" << truncated << " trunc\n";
        packets = 0;
        bytes = 0;
        errors = 0;
        truncated = 0;
        timer.expires_at(timer.expires_at() + std::chrono::seconds(1));
        enqueue_wait();
    }

public:
    explicit runner(const options &opts)
        : socket(io_service), timer(io_service), buffer(opts.packet_size), poll(opts.poll)
    {
        udp::resolver resolver(io_service);
        udp::resolver::query query(
            udp::v4(), opts.host, opts.port,
            udp::resolver::query::passive | udp::resolver::query::address_configured);
        auto endpoint = *resolver.resolve(query);
        socket.open(udp::v4());
        socket.bind(endpoint);
        socket.non_blocking(true);

        if (opts.buffer_size != 0)
        {
            socket.set_option(udp::socket::receive_buffer_size(opts.buffer_size));
            udp::socket::receive_buffer_size actual;
            socket.get_option(actual);
            if ((std::size_t) actual.value() != opts.buffer_size)
            {
                std::cerr << "Warning: requested buffer size of " << opts.buffer_size
                    << " but actual size is " << actual.value() << '\n';
            }
        }
        timer.expires_from_now(std::chrono::seconds(1));

        enqueue_wait();
        enqueue_receive();
    }

    void run()
    {
        io_service.run();
    }
};

int main(int argc, char **argv)
{
    try
    {
        options opts = parse_args(argc, argv);
        runner r(opts);
        r.run();
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
