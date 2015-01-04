CC=clang
CFLAGS=-Weverything -isystem /usr/include/libnl3 -g -std=c99
LDLIBS=-lnl-3 -lnl-route-3

all: teleport

teleport: teleport.o modifier.o

teleport.o: app.h

modifier.o: app.h

deps:
	sudo apt-get install libnl-route-3-dev

clean:
	$(RM) teleport
