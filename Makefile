CC=clang
FLAGS=-Weverything -Wno-unused-variable -g
CFLAGS=-isystem /usr/include/libnl3 -isystem /usr/include/lua5.2 -std=c99 ${FLAGS}
LDLIBS=-lnl-3 -lnl-route-3 -llua5.2

all: teleport tcpip_test

test: tcpip_test
	./tcpip_test

teleport: teleport.o modifier.o tcpip.o

tcpip_test: tcpip.o tcpip_test.o

teleport.o: app.h

modifier.o: app.h

tcpip.o: app.h

tcpip_test.o: app.h

deps:
	sudo apt-get install libnl-route-3-dev liblua5.2-dev

clean:
	$(RM) teleport *.o
