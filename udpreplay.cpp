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

#include <iostream>
#include <memory>
#include <vector>
#include <chrono>
#include <stdexcept>
#include <system_error>
#include <pcap.h>
#include <boost/program_options.hpp>
#include "common.h"
#include "asio_transmit.h"
#include "sendmmsg_transmit.h"
#include "ibv_transmit.h"
#include "rate_transmit.h"

namespace asio = boost::asio;
namespace po = boost::program_options;
using boost::asio::ip::udp;

template<typename Collector>
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

            Collector *c = (Collector *) user;
            packet p = {bytes, len};
            c->add_packet(p);
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

    Transmit t(opts, io_service);
    typedef typename Transmit::collector_type Collector;
    Collector &collector = t.get_collector();
    pcap_loop(p, -1, callback<Collector>, (u_char *) &collector);
    std::size_t num_packets = collector.num_packets();

    std::chrono::time_point<std::chrono::high_resolution_clock> start, stop;
    start = std::chrono::high_resolution_clock::now();
    for (int pass = 0; pass < opts.repeat; pass++)
    {
        for (std::size_t i = 0; i < num_packets; i += Transmit::batch_size)
        {
            std::size_t end = std::min(i + Transmit::batch_size, num_packets);
            t.send_packets(i, end);
        }
    }
    t.flush();
    stop = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = stop - start;
    std::uint64_t bytes = collector.bytes() * opts.repeat;

    double time = elapsed.count();
    std::cout << "Transmitted " << bytes << " bytes in " << time << "s = "
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
