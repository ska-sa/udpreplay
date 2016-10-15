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

#if HAVE_SENDMMSG

#include <system_error>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <boost/asio.hpp>
#include "sendmmsg_transmit.h"

using boost::asio::ip::udp;

sendmmsg_transmit::sendmmsg_transmit(const options &opts, boost::asio::io_service &io_service)
    : socket(io_service)
{
    udp::resolver resolver(io_service);
    udp::resolver::query query(udp::v4(), opts.host, opts.port);
    udp::endpoint endpoint = *resolver.resolve(query);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(endpoint.port());
    addr.sin_addr.s_addr = htonl(endpoint.address().to_v4().to_ulong());

    socket.open(udp::v4());
    set_buffer_size(socket, opts.buffer_size);
    fd = socket.native_handle();
}

void sendmmsg_transmit::send_packets(std::size_t first, std::size_t last)
{
    mmsghdr msg_vec[batch_size];
    iovec msg_iov[batch_size];

    assert(last - first <= batch_size);
    int next = 0;
    std::memset(&msg_vec, 0, sizeof(msg_vec));
    for (std::size_t i = first; i != last; ++i)
    {
        msg_vec[next].msg_hdr.msg_name = (void *) &addr;
        msg_vec[next].msg_hdr.msg_namelen = sizeof(addr);
        msg_vec[next].msg_hdr.msg_iov = &msg_iov[next];
        msg_vec[next].msg_hdr.msg_iovlen = 1;
        packet pkt = collector.get_packet(i);
        msg_iov[next].iov_base = const_cast<u_char *>(pkt.data);
        msg_iov[next].iov_len = pkt.len;
        next++;
    }
    int status = sendmmsg(fd, &msg_vec[0], next, 0);
    if (status != next)
        throw std::system_error(errno, std::system_category(), "sendmmsg failed");
    for (int i = 0; i < next; i++)
        if (msg_vec[i].msg_len != msg_iov[i].iov_len)
            throw std::runtime_error("short write");
}

constexpr int sendmmsg_transmit::batch_size;

#endif // HAVE_SENDMMSG

