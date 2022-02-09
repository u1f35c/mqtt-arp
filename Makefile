CC = gcc
CFLAGS = -Wall
LDFLAGS =

all: mqtt-arp

mqtt-arp: mqtt-arp.o
	$(CC) -o $@ $< $(LDFLAGS) -lmosquitto

install: mqtt-arp
	install -d $(DESTDIR)/etc
	install -d $(DESTDIR)/usr/sbin
	install mqtt-arp $(DESTDIR)/usr/sbin/
	install -m 600 mqtt-arp.conf $(DESTDIR)/etc/

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f mqtt-arp *.o
