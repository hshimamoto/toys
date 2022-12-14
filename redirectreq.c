// MIT License Copyright(c) 2022 Hiroshi Shimamoto
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

static inline void ldatetime(char *dt, int sz)
{
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	if (!tmp)
		strcpy(dt, "-");
	else
		strftime(dt, sz, "%F %T", tmp);
}

#define logf(...) \
	do { \
		char dt[80]; \
		ldatetime(dt, sizeof(dt)); \
		char msg[512]; \
		snprintf(msg, 512, __VA_ARGS__); \
		fprintf(stderr, "%s [%d] %s", dt, getpid(), msg); \
		fflush(stderr); \
	} while (0)

void get_duration(char *buf, int n, struct timeval *prev)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	int duration = now.tv_sec - prev->tv_sec;
	if (duration < 600) {
		int ms = (now.tv_usec - prev->tv_usec) / 1000;
		if (ms < 0) {
			ms += 1000;
			duration++;
		}
		snprintf(buf, n, "%d.%03ds", duration, ms);
	} else if (duration < 3600) {
		snprintf(buf, n, "%dm", duration / 60);
	} else if (duration < 12 * 3600) {
		int h = duration / 3600;
		int m = (duration / 60) % 60;
		snprintf(buf, n, "%dh %dm", h, m);
	} else {
		snprintf(buf, n, "%dh", duration / 3600);
	}
}

const int defport = 8888;
struct addrinfo *redirector;
struct addrinfo *target;

static int listensocket(int port)
{
	struct sockaddr_in addr;
	int s, one = 1;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		goto bad;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto bad;
	if (listen(s, 5) < 0)
		goto bad;

	return s;
bad:
	close(s);
	return -1;
}

static void enable_tcpkeepalive(int s, int idle, int cnt, int intvl)
{
	int val = 1;
	socklen_t len = sizeof(val);

	// enable
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &val, len);
	// set params
	val = idle;
	setsockopt(s, SOL_TCP, TCP_KEEPIDLE, &val, len);
	val = cnt;
	setsockopt(s, SOL_TCP, TCP_KEEPCNT, &val, len);
	val = intvl;
	setsockopt(s, SOL_TCP, TCP_KEEPINTVL, &val, len);
}

static struct addrinfo *resolve_addr(const char *hostport)
{
	struct addrinfo hints, *res;
	char host[256];
	const char *port = NULL;

	for (int i = 0; i < 256; i++) {
		if (hostport[i] == ' ' || hostport[i] == 0)
			break;
		if (hostport[i] == ':') {
			host[i] = 0;
			port = &hostport[i+1];
			break;
		}
		host[i] = hostport[i];
	}
	if (!port)
		return NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hints, &res) != 0)
		return NULL;

	return res;
}

struct session {
	struct session *next;
	int id;
	int ul, dl; // uplink and downlink
	int64_t ubytes, dbytes;
	struct sockaddr_in daddr;
	char buf[256];
	int n;
	int uclosed, dclosed;
	int connecting;
	struct timeval tv_start;
};

#define NR_SESSIONS 32
struct session sess[NR_SESSIONS];
struct session *sess_free;
struct session *sess_used;

static void init_sessions(void)
{
	for (int i = 0; i < NR_SESSIONS - 1; i++) {
		sess[i].id = i;
		sess[i].next = &sess[i+1];
	}
	sess_free = &sess[0];
	sess_used = NULL;
}

static struct session *alloc_session(void)
{
	if (!sess_free)
		return NULL;
	struct session *s = sess_free;
	sess_free = s->next;
	s->next = sess_used;
	sess_used = s;
	return s;
}

static void free_session(struct session *s)
{
	s->next = sess_free;
	sess_free = s;
}

static void check_sessions(void)
{
	struct session *gabage[NR_SESSIONS];
	int n = 0;
	struct session *prev = NULL;

	for (struct session *s = sess_used; s; s = s->next) {
		if (s->uclosed == 1 && s->dclosed == 1) {
			gabage[n++] = s;
			// unlink
			if (prev != NULL)
				prev->next = s->next;
			else
				sess_used = s->next;
			continue;
		}
		prev = s;
	}

	for (int i = 0; i < n; i++) {
		struct session *s = gabage[i];
		if (s->ul != -1)
			close(s->ul);
		if (s->dl != -1)
			close(s->dl);
		if (s->connecting != -1)
			close(s->connecting);
		s->ul = -1;
		s->dl = -1;
		s->connecting = -1;
		char buf[80];
		get_duration(buf, 80, &s->tv_start);
		logf("<%02d> close session %s u->d %ld bytes d->u %ld bytes\n", s->id, buf, s->ubytes, s->dbytes);
		free_session(s);
	}
}

static void session_markclose(struct session *s)
{
	s->uclosed = 1;
	s->dclosed = 1;
}

static int transfer(int from, int to)
{
	char buf[2048];

	int rd = read(from, buf, 2048);
	if (rd <= 0)
		return 0;
	int wr = write(to, buf, rd);
	if (wr != rd)
		return 0;
	return wr;
}

static void uplink(struct session *s)
{
	int bytes = transfer(s->ul, s->dl);
	if (bytes == 0) {
		session_markclose(s);
		return;
	}
	s->ubytes += bytes;
}

static void downlink(struct session *s)
{
	if (s->ul == -1)
		return;

	int bytes = transfer(s->dl, s->ul);
	if (bytes == 0) {
		session_markclose(s);
		return;
	}
	s->dbytes += bytes;
}

static void connected(struct session *s)
{
	int err = 0;
	socklen_t len = sizeof(err);
	int ret = getsockopt(s->connecting, SOL_SOCKET, SO_ERROR, &err, &len);
	if (ret == -1) {
		logf("<%02d> getsockopt failed: %d\n", s->id, errno);
		session_markclose(s);
		return;
	}
	if (err != 0) {
		logf("<%02d> connect failed: %d\n", s->id, err);
		session_markclose(s);
		return;
	}
	// okay connected
	s->ul = s->connecting;
	s->connecting = -1;
	logf("<%02d> connected\n", s->id);
	// send redirect request
	char buf[20];
	memcpy(buf, "\xff\xff\xff\xff", 4);
	memcpy(buf+4, target->ai_addr, 16); // support AF_INET only
	int wr = write(s->ul, buf, 20);
	if (wr != 20) {
		session_markclose(s);
		return;
	}
}

static int reset_fds(int s, fd_set *prfds, fd_set *pwfds)
{
	int max = s;

	FD_ZERO(prfds);
	FD_ZERO(pwfds);
	FD_SET(s, prfds);

	for (struct session *s = sess_used; s; s = s->next) {
		if (s->ul != -1)
			FD_SET(s->ul, prfds);
		if (s->dl != -1)
			FD_SET(s->dl, prfds);
		if (s->ul > max)
			max = s->ul;
		if (s->dl > max)
			max = s->dl;
		if (s->connecting != -1)
			FD_SET(s->connecting, pwfds);
		if (s->connecting > max)
			max = s->connecting;
	}

	return max + 1;
}

static void handle_wfds(fd_set *pfds)
{
	for (struct session *s = sess_used; s; s = s->next) {
		if (s->connecting != -1 && FD_ISSET(s->connecting, pfds))
			connected(s);
	}
}

static void handle_rfds(fd_set *pfds)
{
	for (struct session *s = sess_used; s; s = s->next) {
		if (s->ul != -1 && FD_ISSET(s->ul, pfds))
			uplink(s);
		if (s->dl != -1 && FD_ISSET(s->dl, pfds))
			downlink(s);
	}
}

static void request(struct session *s)
{
	// start connect
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		logf("<%02d> socket failed\n", s->id);
		session_markclose(s);
		return;
	}
	enable_tcpkeepalive(sock, 120, 5, 5);
	// make it non-blocking
	int one = 1;
	if (ioctl(sock, FIONBIO, &one) < 0) {
		close(sock);
		logf("<%02d> non-blocking failed\n", s->id);
		session_markclose(s);
		return;
	}
	connect(sock, redirector->ai_addr, redirector->ai_addrlen);
	s->connecting = sock;
}

static void handle_accept(int s)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	int sock = accept(s, (struct sockaddr *)&addr, &len);

	if (sock == -1) {
		logf("accept error: %d\n", errno);
		return;
	}

	logf("accepted %d from %s\n", sock, inet_ntoa(addr.sin_addr)); 

	struct session *sess = alloc_session();

	if (!sess) {
		logf("no free space\n");
		close(sock);
		return;
	}

	sess->ul = -1;
	sess->dl = sock;
	sess->n = 0;
	sess->uclosed = 0;
	sess->dclosed = 0;
	sess->connecting = -1;
	sess->ubytes = 0;
	sess->dbytes = 0;
	memcpy(&sess->daddr, &addr, len);
	gettimeofday(&sess->tv_start, NULL);

	request(sess);
}

static void run(int s)
{
	fd_set rfds, wfds;
	struct timeval tv;

	init_sessions();

	for (;;) {
		int max = reset_fds(s, &rfds, &wfds);

		tv.tv_sec = 600;
		tv.tv_usec = 0;

		int ret = select(max, &rfds, &wfds, NULL, &tv);

		if (ret < 0) {
			logf("select errno=%d\n", errno);
			return;
		}
		if (ret == 0) {
			logf("nothing happens in 600s, close\n");
			return;
		}

		handle_wfds(&wfds);
		handle_rfds(&rfds);
		check_sessions();

		if (FD_ISSET(s, &rfds))
			handle_accept(s);
	}
}

int main(int argc, char **argv)
{
	int port = defport;
	int s;

	if (argc < 4) {
		logf("redirectreq listen redirector target\n");
		return 1;
	}

	port = atoi(argv[1]);
	redirector = resolve_addr(argv[2]);
	target = resolve_addr(argv[3]);

	if (redirector == NULL) {
		logf("invalid redirector: %s\n", argv[2]);
		return 2;
	}
	if (target == NULL) {
		logf("invalid target: %s\n", argv[3]);
		return 3;
	}

	signal(SIGPIPE, SIG_IGN);

	s = listensocket(port);
	if (s < 0)
		exit(1);

	run(s);

	return 0;
}
