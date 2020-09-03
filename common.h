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
#include <chrono>
#include <boost/asio.hpp>
#include "common.h"

typedef std::chrono::time_point<std::chrono::high_resolution_clock> time_point;
typedef time_point::duration duration;

struct options
{
    double pps = 0;
    double mbps = 0;
    bool use_timestamps = false;
    bool use_destination = false;
    bool sw_pacing = false;
    bool pause = false;
    std::uint32_t burst_size = 0;
    std::size_t buffer_size = 0;
    std::uint8_t ttl = 0;
    std::uint64_t repeat = 1;
    std::string mode = "asio";
    std::string host = "localhost";
    std::string port = "8888";
    std::string bind = "";
    std::string input_file;
    int packet_size = 0;
    int addresses = 1;
};

struct packet
{
    const std::uint8_t *data;
    std::size_t len;
    duration timestamp;  // relative to start of capture
    std::uint32_t dst_host;    // in big endian
    std::uint16_t dst_port;    // in big endian
};

class basic_collector
{
private:
    struct packet_info
    {
        std::size_t offset;
        std::size_t len;
        duration timestamp;
        std::uint32_t dst_host;    // in big endian
        std::uint16_t dst_port;    // in big endian
    };

    std::vector<std::uint8_t> storage;
    std::vector<packet_info> packets;

public:
    void add_packet(const packet &pkt);
    std::size_t num_packets() const;
    packet get_packet(std::size_t idx) const;
    std::size_t packet_size(std::size_t idx) const;
    duration packet_timestamp(std::size_t idx) const;
    std::size_t bytes() const;   // total payload bytes collected
};

// Overload for specific transmitter classes to determine whether they handle
// rate-limiting internally.
template<typename T>
bool handles_rate_limit(const T &transmitter) { return false; }

void set_buffer_size(boost::asio::ip::udp::socket &socket, std::size_t size);
void set_ttl(boost::asio::ip::udp::socket &socket, std::uint8_t ttl);

#endif // UDPREPLAY_COMMON_H
