CXX ?= g++
CPPFLAGS ?=
CXXFLAGS ?= -O3 -std=c++11 -Wall -Wextra -Wpedantic
LDFLAGS ?=
LDLIBS ?=
WITH_PCAP ?= 1
ifeq ($(WITH_PCAP),1)
CPPFLAGS += -DWITH_PCAP
LDLIBS += -lpcap
endif
HEADERS = Pallas.hpp OptPallas.hpp datatypes.hpp hash.hpp adaptor.hpp
.PHONY: all clean FORCE
all: main_hitter
# Rebuild when compiler flags or PCAP support change.
main_hitter: main_hitter.cpp Pallas.cpp adaptor.cpp $(HEADERS) FORCE
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) main_hitter.cpp Pallas.cpp adaptor.cpp -o $@ $(LDFLAGS) $(LDLIBS)
clean:
	rm -f main_hitter
