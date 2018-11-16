
CFLAGS = -std=c++11 -Wall -Wextra -Werror -lpcap
COMPILER = g++
EXECUTABLE = dns-export
PCAPTESTFILE = dns.pcap
# PCAPTESTFILE = txtresponse.pcap
SOURCES = $(wildcard *.cpp) $(wildcard */*.cpp)
OBJS = $(sort $(patsubst %.cpp,%.o,$(SOURCES)))

.PHONY: clean

all: compile

%.o : %.cpp
	$(COMPILER) $(CFLAGS) -c $< -o $@

$(EXECUTABLE): $(OBJS)
	$(COMPILER) $(CFLAGS) -o $@ $^

compile: clean $(EXECUTABLE)
	make clean --silent

#setting debug flags
debug: CFLAGS += -g -DDEBUG -DHEADERS -DINCLUDE_UNKNOWN
debug: compile

testfile: debug
	valgrind ./$(EXECUTABLE) -r /pcapexample/$(PCAPTESTFILE) 1> stdout.txt 2> stderr.txt
	column -t stdout.txt > stdout_formated.txt

testlive: debug
	./$(EXECUTABLE) -i enp0s3 -t 3
	make clean

testliverel: compile
	./$(EXECUTABLE) -i enp0s3 -t 3

clean:
ifneq (,$(wildcard *.o))
	-rm *.o
endif
