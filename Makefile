CXX = g++
CXXFLAGS = -Wall -g -std=c++11
LDFLAGS = -lpcap -lboost_system -lboost_program_options -lpthread
TARGETS = udpreplay

all: $(TARGETS)

%: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
