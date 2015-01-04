CC=clang
CFLAGS=-Weverything -isystem /usr/include/libnl3 -isystem /usr/include/lua5.2 -g -std=c99
LDLIBS=-lnl-3 -lnl-route-3 -llua5.2

all: teleport

teleport: teleport.o modifier.o

teleport.o: app.h

modifier.o: app.h

deps:
	sudo apt-get install libnl-route-3-dev liblua5.2-dev

clean:
	$(RM) teleport *.o
