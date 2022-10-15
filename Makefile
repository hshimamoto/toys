all: toyproxy redirector redirectreq

toyproxy: toyproxy.c
	gcc -g -Os -o $@ $<

redirector: redirector.c
	gcc -g -Os -o $@ $<

redirectreq: redirectreq.c
	gcc -g -Os -o $@ $<

clean:
	rm -f toyproxy redirector redirectreq
