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

#ifndef UDPREPLAY_SENDMMSG_TRANSMIT_H
#define UDPREPLAY_SENDMMSG_TRANSMIT_H

#include <config.h>

#if HAVE_SENDMMSG

#include <netinet/in.h>
#include <chrono>
#include <boost/asio.hpp>
#include "common.h"

class sendmmsg_transmit
{
public:
    static constexpr int batch_size = 8;

private:
    basic_collector collector;
    boost::asio::ip::udp::socket socket;
    int fd;
    sockaddr_in addr;

public:
    typedef basic_collector collector_type;

    sendmmsg_transmit(const options &opts, boost::asio::io_service &io_service);

    collector_type &get_collector() { return collector; }
    void send_packets(std::size_t first, std::size_t last, time_point start);
    void flush() {}
};

#endif // HAVE_SENDMMSG
#endif // UDPREPLAY_SENDMMSG_TRANSMIT_H
