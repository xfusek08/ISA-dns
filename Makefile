
CFLAGS = -std=c++11 -Wall -Wextra -Werror -lpcap
COMPILER = g++
EXECUTABLE = dns-export
SOURCES = $(wildcard *.cpp) $(wildcard */*.cpp)
OBJS = $(sort $(patsubst %.cpp,%.o,$(SOURCES)))

.PHONY: clean

all: clean $(EXECUTABLE) clean

#setting debug flags
debug: CFLAGS += -g -DDEBUG -DHEADERS
debug: $(EXECUTABLE) clean

%.o : %.cpp
	$(COMPILER) $(CFLAGS) -c $< -o $@

$(EXECUTABLE): $(OBJS)
	$(COMPILER) $(CFLAGS) -o $@ $^

test: debug
	valgrind ./$(EXECUTABLE) -r /pcapexample/dns.pcap 1> stdout.txt 2> stderr.txt
	column -t stdout.txt > stdout_formated.txt

clean:
	-rm *.o
