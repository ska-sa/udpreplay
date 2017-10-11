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

#include <cstring>
#include <cstddef>
#include <iostream>
#include "common.h"

using boost::asio::ip::udp;

void basic_collector::add_packet(const packet &pkt)
{
    std::size_t offset = storage.size();
    storage.insert(storage.end(), pkt.data, pkt.data + pkt.len);
    packets.push_back(packet_info{offset, pkt.len, pkt.timestamp, pkt.dst_host, pkt.dst_port});
}

std::size_t basic_collector::num_packets() const
{
    return packets.size();
}

packet basic_collector::get_packet(std::size_t idx) const
{
    return {storage.data() + packets[idx].offset, packets[idx].len, packets[idx].timestamp,
            packets[idx].dst_host, packets[idx].dst_port};
}

std::size_t basic_collector::packet_size(std::size_t idx) const
{
    return packets[idx].len;
}

duration basic_collector::packet_timestamp(std::size_t idx) const
{
    return packets[idx].timestamp;
}

std::size_t basic_collector::bytes() const
{
    return storage.size();
}


void set_buffer_size(udp::socket &socket, std::size_t size)
{
    if (size != 0)
    {
        socket.set_option(udp::socket::send_buffer_size(size));
        udp::socket::send_buffer_size actual;
        socket.get_option(actual);
        if ((std::size_t) actual.value() != size)
        {
            std::cerr << "Warning: requested buffer size of " << size
                << " but actual size is " << actual.value() << '\n';
        }
    }
}

void set_ttl(udp::socket &socket, std::uint8_t ttl)
{
    if (ttl != 0)
        socket.set_option(boost::asio::ip::multicast::hops(ttl));
}
