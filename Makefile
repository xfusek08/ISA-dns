
CFLAGS = -std=c++11 -Wall -Wextra -Werror -lpcap
COMPILER = g++
EXECUTABLE = dns-export
PCAPTESTFILE = dns.pcap
# PCAPTESTFILE = txtresponse.pcap
SOURCES = $(wildcard *.cpp) $(wildcard */*.cpp)
OBJS = $(sort $(patsubst %.cpp,%.o,$(SOURCES)))

.PHONY: clean

all: clean $(EXECUTABLE) clean

#setting debug flags
debug: CFLAGS += -g -DDEBUG -DHEADERS -DINCLUDE_UNKNOWN
debug: $(EXECUTABLE) clean

%.o : %.cpp
	$(COMPILER) $(CFLAGS) -c $< -o $@

$(EXECUTABLE): $(OBJS)
	$(COMPILER) $(CFLAGS) -o $@ $^

testfile: debug
	valgrind ./$(EXECUTABLE) -r /pcapexample/$(PCAPTESTFILE) 1> stdout.txt 2> stderr.txt
	column -t stdout.txt > stdout_formated.txt

testlive: debug
	./$(EXECUTABLE) -i any -t 10

clean:
	-rm *.o
