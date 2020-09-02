#ifndef UDPREPLAY_RATE_TRANSMIT_H
#define UDPREPLAY_RATE_TRANSMIT_H

#include <config.h>
#include <boost/asio.hpp>
#include "common.h"

/// Wraps another transmitter to rate-limit it
template<typename Transmit>
class rate_transmit
{
private:
    boost::asio::io_service &io_service;
    Transmit transmit;
    bool limited = false;

public:
    static constexpr int batch_size = Transmit::batch_size;
    typedef typename Transmit::collector_type collector_type;

    explicit rate_transmit(const options &opts, boost::asio::io_service &io_service)
        : io_service(io_service), transmit(opts, io_service)
    {
        limited = (opts.pps != 0 || opts.mbps != 0 || opts.use_timestamps)
            && !handles_rate_limit(transmit);
    }

    void send_packets(std::size_t first, std::size_t last,
                      time_point start)
    {
        if (limited)
        {
            auto &collector = transmit.get_collector();
            time_point next_send = start + collector.packet_timestamp(first);
            boost::asio::basic_waitable_timer<time_point::clock> timer(io_service);
            timer.expires_at(next_send);
            timer.wait();
        }
        transmit.send_packets(first, last, start);
    }

    collector_type &get_collector() { return transmit.get_collector(); }

    void flush()
    {
        transmit.flush();
    }
};

template<typename Transmit>
bool handles_rate_limit(const rate_transmit<Transmit> &transmit)
{
    return true;
}

#endif // UDPREPLAY_RATE_TRANSMIT_H
