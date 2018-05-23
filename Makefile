CC = gcc
CFLAGS = -Wall
LDFLAGS =

all: mqtt-arp

mqtt-arp: mqtt-arp.o
	$(CC) -o $@ $< $(LDFLAGS) -lmosquitto

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f mqtt-arp *.o
