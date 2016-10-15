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

#ifndef UDPREPLAY_COMMON_H
#define UDPREPLAY_COMMON_H

#include <config.h>
#include <vector>
#include <utility>
#include <cstdint>
#include <cstddef>
#include <string>
#include <boost/asio.hpp>
#include "common.h"

struct options
{
    double pps = 0;
    double mbps = 0;
    std::size_t buffer_size = 0;
    std::size_t repeat = 1;
    std::string mode = "asio";
    std::string host = "localhost";
    std::string port = "8888";
    std::string bind = "";
    std::string input_file;
};

struct packet
{
    const std::uint8_t *data;
    std::size_t len;
};

class basic_collector
{
private:
    std::vector<std::uint8_t> storage;
    std::vector<std::pair<std::size_t, std::size_t> > packet_offsets;

public:
    void add_packet(const packet &pkt);
    std::size_t num_packets() const;
    packet get_packet(std::size_t idx) const;
    std::size_t packet_size(std::size_t idx) const;
    std::size_t bytes() const;
};

void set_buffer_size(boost::asio::ip::udp::socket &socket, std::size_t size);

#endif // UDPREPLAY_COMMON_H
