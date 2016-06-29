CXX = c++
CXXFLAGS = -Wall -g -std=c++11 -O2 -fopenmp
LDFLAGS = -lpcap -lboost_system -lboost_program_options -lpthread -fopenmp
TARGETS = udpreplay udpcount

ifeq ($(IBV),1)
    CXXFLAGS += -DHAVE_IBV=1
    LDFLAGS += -lrdmacm -libverbs
endif

all: $(TARGETS)

%: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
