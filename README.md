# udpreplay

udpreplay is a tool to replays UDP packets from a pcap dump.

Unlike [tcpreplay](http://tcpreplay.appneta.com/), it only replays the payload
and not the headers, so it does not require root privileges and works fine with
the Linux loopback device.

It supports rate control, either in packets per second or bits per second.
It does not support replay with the original timings.

The packets are pre-loaded from the pcap file, so it is possible to send at a
higher rate than the packets can be loaded. Typically, the NIC or the kernel
limits the maximum rate.

It supports sending in parallel, but it is a bit of a hack (uses the same
socket), almost certainly buggy, and seems to give errors.

## udpcount

An extra tool is included, called `udpcount`. It listens for UDP packets on a
socket, and reports statistics about the number of bytes and packets received
once per second.

## Requirements

You will need libpcap (including development headers), Boost headers, and the
libraries for the Boost `system` and `program_options` libraries. You will
also need a modern C++11-capable compiler. GCC 4.8 and Clang 3.4 are known to
work.

If your NIC supports the Infiniband Verbs API, you may be able to get higher
performance by using it. It will be automatically detected at configure time.

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

Run `udpreplay -h` to see a list of other options.

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
