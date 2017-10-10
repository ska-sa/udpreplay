# udpreplay

udpreplay is a tool to replays UDP packets from a pcap dump.

Unlike [tcpreplay](http://tcpreplay.appneta.com/), it only replays the payload
and not the headers, so it does not require root privileges and works fine with
the Linux loopback device.

It supports rate control, either in packets per second or bits per second. It
can also replay the original timings.

The packets are pre-loaded from the pcap file, so it is possible to send at a
higher rate than the packets can be loaded. Typically, the NIC or the kernel
limits the maximum rate.

## udpcount

An extra tool is included, called `udpcount`. It listens for UDP packets on a
socket, and reports statistics about the number of bytes and packets received
once per second.

## Requirements

You will need libpcap (including development headers), Boost headers, and the
libraries for the Boost `system` and `program_options` libraries. You will
also need a modern C++11-capable compiler. GCC 4.8 and Clang 3.4 are known to
work.

## Installation

udpcount uses the standard autoconf/automake flow for installation. If you
are installing from a git checkout, you should first run `./bootstrap.sh`.
After that, it is the usual process of
```sh
./configure
make
sudo make install
```

## Usage

First, capture a file using [tcpdump](http://www.tcpdump.org/) or whichever
tool you prefer. Only ethernet frame types are currently supported (which
includes the Linux loopback device). Then to replay it at 100Mbps, run

```sh
udpreplay --mbps 100 capture.pcap
```

Run `udpreplay -h` to see a list of other options. A particularly useful
option on Linux is `--mode sendmmsg`, which can increase performance.

## Infiniband Verbs API

If your NIC supports the Infiniband Verbs API, you may be able to get higher
performance by passing `--mode=ibv`. Support will be automatically detected at
configure time.

There are some caveats. It can only be used with multicast destination
addresses, and you must specify the interface to use by passing
`--bind <ip-address>`.

## Original timings

Specifying `--use-timestamps` will attempt to replay the packets according to
the timestamps in the original file. The mode is somewhat less efficient, so it
might not keep up with the goal when packets are close together in time.

## Original destinations

Normally, udpreplay sends all the traffic to a specific host and port, ignoring
the values in the original packets. With `--use-destination`, it will instead
use the original IP address and port. Note that the MAC address is not used,
even when using `--mode=ibv`, so if you edit the file to change the
destination, it's not necessary to update the MAC address to match.

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.
