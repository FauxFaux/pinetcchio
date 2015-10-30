CC=clang
FLAGS=-Weverything -Wno-unused-variable -g
CFLAGS=-isystem /usr/include/libnl3 -isystem /usr/include/lua5.2 -std=c99 ${FLAGS}
LDLIBS=-lnl-3 -lnl-route-3 -llua5.2

TESTS = $(wildcard t/*.c)

all: teleport pocksify

teleport: teleport.o modifier.o tcpip.o tun.o

pocksify: pocksify.o tun.o

teleport.o: app.h tun.h

modifier.o: app.h

tcpip.o: app.h

tun.o: tun.h

tests.o: $(TESTS)

tests: tests.o tcpip.o
	$(LINK.o) -ltap $^ -o $@

check: test

test: tests
	./tests

deps:
	sudo apt-get install libnl-route-3-dev liblua5.2-dev

clean:
	$(RM) teleport tests pocksify *.o

