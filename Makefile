CC = gcc
CFLAGS = -g -Os

all: toyproxy redirector redirectreq

toyproxy: toyproxy.c
	$(CC) $(CFLAGS) -o $@ $<

redirector: redirector.c
	$(CC) $(CFLAGS) -o $@ $<

redirectreq: redirectreq.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f toyproxy redirector redirectreq
