toyproxy: toyproxy.c
	gcc -g -Os -o $@ $<

clean:
	rm -f toyproxy
