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
#include <cstddef>
#include <boost/asio.hpp>
#include "asio_transmit.h"

using boost::asio::ip::udp;

asio_transmit::asio_transmit(const options &opts, boost::asio::io_service &io_service)
    : socket(io_service)
{
    udp::resolver resolver(io_service);
    udp::resolver::query query(udp::v4(), opts.host, opts.port);
    endpoint = *resolver.resolve(query);
    socket.open(udp::v4());
    set_buffer_size(socket, opts.buffer_size);
}

void asio_transmit::send_packets(std::size_t first, std::size_t last)
{
    for (std::size_t i = first; i < last; i++)
    {
        packet pkt = collector.get_packet(i);
        socket.send_to(boost::asio::buffer(pkt.data, pkt.len), endpoint);
    }
}

constexpr int asio_transmit::batch_size;
