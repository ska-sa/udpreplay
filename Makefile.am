LDADD = -lpcap -lboost_program_options
AM_LDFLAGS = -pthread
AM_CXXFLAGS = -Wall -std=c++11 -pthread

bin_PROGRAMS = udpreplay udpcount
udpreplay_SOURCES = udpreplay.cpp common.cpp asio_transmit.cpp sendmmsg_transmit.cpp ibv_transmit.cpp
udpcount_SOURCES = udpcount.cpp
