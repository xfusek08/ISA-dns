
CFLAGS = -std=c++11 -Wall -Wextra -Werror -lpcap
COMPILER = g++
EXECUTABLE = dns-export
SOURCES = $(wildcard *.cpp) $(wildcard */*.cpp)
OBJS = $(sort $(patsubst %.cpp,%.o,$(SOURCES)))

.PHONY: clean

all: clean $(EXECUTABLE) clean

#setting debug flags
debug: CFLAGS += -g -DDEBUG #-DST_DEBUG #-DPRECDEBUG
debug: $(EXECUTABLE) clean

%.o : %.cpp
	$(COMPILER) $(CFLAGS) -c $< -o $@

$(EXECUTABLE): $(OBJS)
	$(COMPILER) $(CFLAGS) -o $@ $^

test: debug
	./$(EXECUTABLE) -r /pcapexample/dns.pcap 2> res.txt

clean:
	-rm *.o
