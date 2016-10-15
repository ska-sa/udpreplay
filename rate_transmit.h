#ifndef UDPREPLAY_RATE_TRANSMIT_H
#define UDPREPLAY_RATE_TRANSMIT_H

#include <config.h>
#include <chrono>
#include <boost/asio.hpp>
#include "common.h"

/// Wraps another transmitter to rate-limit it
template<typename Transmit>
class rate_transmit
{
private:
    boost::asio::io_service &io_service;
    Transmit transmit;
    std::chrono::time_point<std::chrono::high_resolution_clock> next_send;
    std::chrono::nanoseconds pps_interval{0};
    double ns_per_byte = 0;
    bool limited = false;

public:
    static constexpr int batch_size = Transmit::batch_size;
    typedef typename Transmit::collector_type collector_type;

    explicit rate_transmit(const options &opts, boost::asio::io_service &io_service)
        : io_service(io_service), transmit(opts, io_service)
    {
        if (opts.pps != 0)
        {
            pps_interval = std::chrono::nanoseconds(std::uint64_t(1e9 / opts.pps));
            limited = true;
        }
        if (opts.mbps != 0)
        {
            ns_per_byte = 8000.0 / opts.mbps;
            limited = true;
        }
    }

    void send_packets(std::size_t first, std::size_t last)
    {
        if (limited)
        {
            if (next_send == std::chrono::high_resolution_clock::time_point())
                next_send = std::chrono::high_resolution_clock::now();
            std::size_t send_bytes = 0;
            auto &collector = transmit.get_collector();
            for (std::size_t i = first; i != last; ++i)
                send_bytes += collector.packet_size(i);
            boost::asio::basic_waitable_timer<std::chrono::high_resolution_clock> timer(io_service);
            timer.expires_at(next_send);
            timer.wait();
            transmit.send_packets(first, last);
            next_send += pps_interval;
            next_send += std::chrono::nanoseconds(std::uint64_t(ns_per_byte * send_bytes));
        }
        else
        {
            transmit.send_packets(first, last);
        }
    }

    collector_type &get_collector() { return transmit.get_collector(); }

    void flush()
    {
        transmit.flush();
    }
};

#endif // UDPREPLAY_RATE_TRANSMIT_H
