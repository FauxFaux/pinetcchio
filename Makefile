CC=clang
CFLAGS=-Weverything -isystem /usr/include/libnl3

all: teleport

deps:
	sudo apt-get install libnl-route-3-dev

clean:
	$(RM) teleport
