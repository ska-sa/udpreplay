/* Copyright 2015-2016, 2018 SKA South Africa
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
#include <chrono>
#include <stdexcept>
#include <functional>
#include <system_error>
#include <pcap.h>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include "common.h"
#include "asio_transmit.h"
#include "sendmmsg_transmit.h"
#include "ibv_transmit.h"
#include "rate_transmit.h"

namespace asio = boost::asio;
namespace po = boost::program_options;
using boost::asio::ip::udp;

struct callback_data
{
    std::function<void(const packet &packet)> add_packet;
    std::chrono::duration<double, duration::period> per_packet{0.0};
    std::chrono::duration<double, duration::period> per_byte{0.0};
    bool use_timestamps;
    bool use_destination;
    boost::asio::ip::udp::endpoint destination;
    struct timeval start;
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
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
        std::uint32_t dst_host;   // big endian
        std::memcpy(&dst_host, bytes + 16, sizeof(dst_host));
        if (len >= ip_hsize + 8)
        {
            bytes += ip_hsize;
            len -= ip_hsize;
            std::uint16_t dst_port;     // big endian
            std::memcpy(&dst_port, bytes + 2, sizeof(dst_port));
            const unsigned int udp_hsize = 8;
            bytes += udp_hsize;
            len -= udp_hsize;

            callback_data *data = (callback_data *) user;
            duration timestamp;
            if (data->use_timestamps)
            {
                if (data->packets == 0)
                    data->start = h->ts;
                auto ts = std::chrono::seconds(h->ts.tv_sec - data->start.tv_sec)
                    + std::chrono::nanoseconds(h->ts.tv_usec - data->start.tv_usec);
                timestamp = std::chrono::duration_cast<duration>(ts);
            }
            else
            {
                timestamp = std::chrono::duration_cast<duration>(
                    data->per_byte * data->bytes + data->per_packet * data->packets);
            }
            if (!data->use_destination)
            {
                asio::ip::address_v4::bytes_type dst_raw = data->destination.address().to_v4().to_bytes();
                std::memcpy(&dst_host, &dst_raw, sizeof(dst_host));
                dst_port = htons(data->destination.port());
            }
            packet p = {bytes, len, timestamp, dst_host, dst_port};
            data->add_packet(p);
            data->packets++;
            data->bytes += len;
        }
    }
}

static void generate_packets(callback_data &data, std::size_t packet_size, int addresses)
{
    std::unique_ptr<uint8_t[]> payload{new uint8_t[packet_size]};
    std::fill(payload.get(), payload.get() + packet_size, 0);

    std::uint32_t dst_host;   // big endian
    asio::ip::address_v4::bytes_type dst_raw = data.destination.address().to_v4().to_bytes();
    std::memcpy(&dst_host, &dst_raw, sizeof(dst_host));
    std::uint32_t dst_host_he = ntohl(dst_host);  // host endian
    std::uint16_t dst_port = htons(data.destination.port());  // big endian

    // Put in a reasonable number of packets, because there are overheads if
    // we can't batch things.
    int batch_size = 1024;
    // Round up to a multiple of the number of addresses
    batch_size = (batch_size + addresses - 1) / addresses * addresses;
    for (int i = 0; i < batch_size; i++)
    {
        std::uint32_t dst_host_cur_he = (dst_host_he + i % addresses);
        dst_host = htonl(dst_host_cur_he);
        duration timestamp = std::chrono::duration_cast<duration>(
            data.per_byte * data.bytes + data.per_packet * data.packets);
        packet p = {payload.get(), packet_size, timestamp, dst_host, dst_port};
        data.add_packet(p);
        data.packets++;
        data.bytes += packet_size;
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

    Transmit t(opts, io_service);
    typedef typename Transmit::collector_type Collector;
    callback_data data;
    Collector &collector = t.get_collector();
    data.add_packet = [&collector](const packet &pkt) { collector.add_packet(pkt); };
    if (opts.mbps != 0)
        data.per_byte = std::chrono::duration<double, std::micro>(8.0 / opts.mbps);
    if (opts.pps != 0)
        data.per_packet = std::chrono::duration<double>(1.0 / opts.pps);
    data.use_timestamps = opts.use_timestamps;
    data.use_destination = opts.use_destination;
    if (!opts.use_destination)
    {
        udp::resolver resolver(io_service);
        udp::resolver::query query(udp::v4(), opts.host, opts.port);
        data.destination = *resolver.resolve(query);
    }

    if (p)
        pcap_loop(p, -1, callback, (u_char *) &data);
    else
        generate_packets(data, opts.packet_size, opts.addresses);

    std::size_t num_packets = collector.num_packets();

    /* Time offset between the equivalent packets in each repetition. */
    std::chrono::duration<double, duration::period> rep_step;
    if (opts.use_timestamps)
        rep_step = collector.packet_timestamp(collector.num_packets() - 1);
    else
        rep_step = data.per_byte * data.bytes + data.per_packet * data.packets;

    std::cout << "Packets loaded, starting transmission" << std::endl;

    do
    {
        time_point start, rep_start, stop;
        start = std::chrono::high_resolution_clock::now();
        const std::size_t batch_size = opts.use_timestamps ? 1 : Transmit::batch_size;

        std::uint64_t passes = 0;
        std::uint64_t last_pass = 0;
        bool forever = false;
        if (opts.repeat == 0)
            forever = true;
        else if (!p)
        {
            // --repeat specifies number of packets to send, but we have a number of
            // packets in the collector so we have to break it into repeats plus
            // final pass.
            passes = opts.repeat / num_packets;
            last_pass = opts.repeat % num_packets;
        }
        else
        {
            passes = opts.repeat;
        }

        for (std::uint64_t pass = 0; forever || pass <= passes; pass++)
        {
            rep_start = start + std::chrono::duration_cast<duration>(pass * rep_step);
            std::size_t limit = (forever || pass < passes) ? num_packets : last_pass;
            for (std::size_t i = 0; i < limit; i += batch_size)
            {
                std::size_t end = std::min(i + batch_size, limit);
                t.send_packets(i, end, rep_start);
            }
        }
        t.flush();
        stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = stop - start;
        std::uint64_t total_bytes = collector.bytes() * passes;
        std::uint64_t total_packets = num_packets * passes + last_pass;
        for (std::size_t i = 0; i < last_pass; i++)
            total_bytes += collector.packet_size(i);

        double time = elapsed.count();
        std::cout << "Transmitted " << total_bytes << " bytes / "
            << total_packets << " packets in " << time << "s = "
            << total_bytes * 8.0 / time / 1e9 << "Gbps\n";
        if (opts.pause)
        {
            std::cout << "Press enter when ready for next repetition: " << std::flush;
            std::string dummy;
            getline(std::cin, dummy);
        }
    } while (opts.pause);
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
        ("sw-pacing", po::bool_switch(&out.sw_pacing)->default_value(defaults.sw_pacing), "do not use HW packet pacing, even if available")
        ("use-timestamps", po::bool_switch(&out.use_timestamps)->default_value(defaults.use_timestamps), "use timestamps from the file for replay timing")
        ("use-destination", po::bool_switch(&out.use_destination)->default_value(defaults.use_destination), "use original destination endpoints from the file")
        ("burst-size", po::value<std::uint32_t>(&out.burst_size)->default_value(defaults.burst_size), "maximum burst size when using HW packet pacing (0 = default)")
        ("host", po::value<std::string>(&out.host)->default_value(defaults.host), "destination host")
        ("port", po::value<std::string>(&out.port)->default_value(defaults.port), "destination port")
        ("bind", po::value<std::string>(&out.bind)->default_value(defaults.bind), "local address (for multicast)")
        ("mode", po::value<std::string>(&out.mode)->default_value(defaults.mode), "transmit mode (asio/sendmmsg/ibv)")
        ("buffer-size", po::value<size_t>(&out.buffer_size)->default_value(defaults.buffer_size), "transmit buffer size (0 for system default)")
        ("ttl", po::value<uint8_t>(&out.ttl)->default_value(defaults.ttl), "TTL for multicast (0 for system default)")
        ("repeat", po::value<size_t>(&out.repeat), "send the data this many times")
        ("addresses", po::value<int>(&out.addresses)->default_value(defaults.addresses), "number of sequential addresses to use with generator")
        ("pause", po::bool_switch(&out.pause)->default_value(defaults.pause), "after completion, wait for user input then send again")
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
        if (vm.count("pps") + vm.count("mbps") + out.use_timestamps > 1)
            throw po::error("Cannot specify more than one of --pps, --mbps and --use-timestamps");
        try
        {
            // See if we were given a packet size instead of a file
            out.packet_size = boost::lexical_cast<int>(out.input_file);
            out.input_file = "";
            if (out.packet_size <= 0)
                throw po::error("Packet size must be positive");
            if (out.use_timestamps)
                throw po::error("Cannot use --use-timestamps with packet generator");
            if (out.use_destination)
                throw po::error("Cannot use --use-destination with packet generator");
            if (out.addresses < 1)
                throw po::error("Value of --addresses cannot be less than 1");
            if (!vm.count("repeat"))
                out.repeat = 0;   // run forever
        }
        catch (boost::bad_lexical_cast &)
        {
            // It's a filename
            if (out.addresses != 1)
                throw po::error("Cannot use --addresses with a capture file");
        }
        if (out.repeat == 0 && out.pause)
            throw po::error("Cannot use --repeat=0 with --pause");
        return out;
    }
    catch (po::error &e)
    {
        std::cerr << e.what() << "\n\n";
        std::cerr << "Usage: udpreplay [options] capturefile|packet-size\n";
        std::cerr << desc;
        throw;
    }
}

std::shared_ptr<pcap_t> open_capture(const options &opts)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline_with_tstamp_precision(
        opts.input_file.c_str(), PCAP_TSTAMP_PRECISION_NANO, errbuf);
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
        std::shared_ptr<pcap_t> p;
        if (opts.packet_size == 0)
        {
            p = open_capture(opts);
            prepare(p.get());
        }
#if HAVE_SENDMMSG
        if (opts.mode == "sendmmsg")
        {
            run<rate_transmit<sendmmsg_transmit>>(p.get(), opts);
        }
        else
#endif
#if HAVE_IBV
        if (opts.mode == "ibv")
        {
            run<rate_transmit<ibv_transmit>>(p.get(), opts);
        }
        else
#endif
        if (opts.mode == "asio")
        {
            run<rate_transmit<asio_transmit>>(p.get(), opts);
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
