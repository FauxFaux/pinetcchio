CC=clang
CFLAGS=-Weverything -isystem /usr/include/libnl3 -g
LDLIBS=-lnl-3 -lnl-route-3

all: teleport

deps:
	sudo apt-get install libnl-route-3-dev

clean:
	$(RM) teleport
