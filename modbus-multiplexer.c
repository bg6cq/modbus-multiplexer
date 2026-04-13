#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <pthread.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#ifdef __linux__
#include <linux/tcp.h>
#endif

#define MAXLEN 16384
#define MAXRTULEN 256

#define TCP 1
#define RTU 2

/* Socket option timeouts */
#ifdef __linux__
#define TCP_KEEPIDLE_VAL 2
#define TCP_KEEPINTVL_VAL 2
#define TCP_KEEPCNT_VAL 3
#define SOL_TCP_LEVEL SOL_TCP
#define TCP_KEEPIDLE_OPT TCP_KEEPIDLE
#define TCP_KEEPINTVL_OPT TCP_KEEPINTVL
#define TCP_KEEPCNT_OPT TCP_KEEPCNT
#else
/* macOS uses different socket options */
#define TCP_KEEPIDLE_VAL 2
#define TCP_KEEPINTVL_VAL 2
#define TCP_KEEPCNT_VAL 3
#define SOL_TCP_LEVEL IPPROTO_TCP
#define TCP_KEEPIDLE_OPT TCP_KEEPALIVE
#define TCP_KEEPINTVL_OPT TCP_KEEPINTVL
#define TCP_KEEPCNT_OPT TCP_KEEPCNT
#endif

#define DEFAULT_TIMEOUT 3
#define DEFAULT_TIMEOUT_RETRY_EXIT 10
#define MAX_TIMEOUT 100

/* Modbus packet offsets */
#define MBAP_TRANSID_OFFSET 0
#define MBAP_PROTOID_OFFSET 2
#define MBAP_LENGTH_OFFSET 4
#define MBAP_UNITID_OFFSET 6
#define MBAP_HEADER_LEN 6
#define RTU_HEADER_LEN 2
#define RTU_CRC_LEN 2

int dev_fd;
int debug = 0;
int timeout_retry_exit = DEFAULT_TIMEOUT_RETRY_EXIT;
int time_out = DEFAULT_TIMEOUT;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int s_type;
int r_type;
char pname[MAXLEN];
int daemon_proc = 0;

void daemon_init(void)
{
	int i;
	pid_t pid;

	if (debug != 0)
		return;

	/* First fork - parent terminates */
	if ((pid = fork()) != 0)
		exit(0);

	/* First child continues - become session leader */
	setsid();

	signal(SIGHUP, SIG_IGN);

	/* Second fork - first child terminates */
	if ((pid = fork()) != 0)
		exit(0);

	/* Second child continues */
	chdir("/");			/* change working directory */
	umask(0);			/* clear our file mode creation mask */

	for (i = 0; i < 3; i++)
		close(i);

	openlog(pname, LOG_PID, LOG_DAEMON);
	daemon_proc = 1;
}

void Log(const char *fmt, ...)
{
	char buf[MAXLEN];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, MAXLEN, fmt, ap);
	if (daemon_proc)
		syslog(LOG_INFO, "%s", buf);
	else {
		fflush(stdout);
		fputs(buf, stdout);
		fflush(stdout);
	}
	va_end(ap);
}

/* Table of CRC values for high-order byte */
static const uint8_t table_crc_hi[] = {
	0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
	0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
	0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
	0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
	0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
	0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
	0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
	0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
	0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
	0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
	0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
	0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
	0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
	0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
	0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
	0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
	0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
	0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
	0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
	0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
	0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
	0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40,
	0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1,
	0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
	0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
	0x80, 0x41, 0x00, 0xC1, 0x81, 0x40
};

/* Table of CRC values for low-order byte */
static const uint8_t table_crc_lo[] = {
	0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06,
	0x07, 0xC7, 0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD,
	0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
	0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A,
	0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC, 0x14, 0xD4,
	0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
	0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3,
	0xF2, 0x32, 0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4,
	0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
	0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29,
	0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF, 0x2D, 0xED,
	0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
	0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60,
	0x61, 0xA1, 0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67,
	0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
	0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68,
	0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA, 0xBE, 0x7E,
	0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
	0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71,
	0x70, 0xB0, 0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92,
	0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
	0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B,
	0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89, 0x4B, 0x8B,
	0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
	0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42,
	0x43, 0x83, 0x41, 0x81, 0x80, 0x40
};

static uint16_t crc16(uint8_t * buffer, uint16_t buffer_length)
{
	uint8_t crc_hi = 0xFF;	/* high CRC byte initialized */
	uint8_t crc_lo = 0xFF;	/* low CRC byte initialized */
	unsigned int i;		/* will index into CRC lookup */

	/* pass through message buffer */
	while (buffer_length--) {
		i = crc_hi ^ *buffer++;	/* calculate the CRC  */
		crc_hi = crc_lo ^ table_crc_hi[i];
		crc_lo = table_crc_lo[i];
	}

	return (crc_hi << 8 | crc_lo);
}

char *dump_pkt(char *str, uint8_t * buf, int type)
{
	if (type == TCP)
		sprintf(str, "%02X%02X %02X%02X %02X%02X ADDR %02X FC%02X",
			buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
	else
		sprintf(str, "ADDR %02X FC%02X", buf[0], buf[1]);
	return str;
}

void *Process(void *ptr)
{
	int tcp_fd = *(int *)ptr;
	uint8_t tcpbuf[MAXLEN];
	uint8_t rtubuf[MAXLEN];
	char strbuf[MAXLEN];
	uint16_t transid = 0;
	int optval;
	socklen_t optlen = sizeof(optval);

	free(ptr);	/* free the memory allocated in main */

	if (debug)
		Log("%s T:%ld start, tcp_fd:%d\n", pname, pthread_self(), tcp_fd);
	pthread_detach(pthread_self());

	/* Set TCP options */
	optval = 1;
	setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, &optval, optlen);
	setsockopt(tcp_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
#ifdef __linux__
	optval = TCP_KEEPCNT_VAL;
	setsockopt(tcp_fd, SOL_TCP_LEVEL, TCP_KEEPCNT_OPT, &optval, optlen);
	optval = TCP_KEEPIDLE_VAL;
	setsockopt(tcp_fd, SOL_TCP_LEVEL, TCP_KEEPIDLE_OPT, &optval, optlen);
	optval = TCP_KEEPINTVL_VAL;
	setsockopt(tcp_fd, SOL_TCP_LEVEL, TCP_KEEPINTVL_OPT, &optval, optlen);
#endif

	/* Set socket timeout */
	struct timeval timeout = { time_out, 0 };
	setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	while (1) {
		int n, nw __attribute__ ((unused)), expected_len;

		/* Clear MBAP header */
		memset(tcpbuf, 0, 4);

		/*===========================================================
		 * STEP 1: read request from tcp_fd to rtubuf
		 *===========================================================*/
		if (s_type == TCP) {
			/* Read MBAP header (8 bytes) */
			while (1) {
				n = read(tcp_fd, tcpbuf, MBAP_HEADER_LEN + 2);
				if (n >= 0)
					break;
				if ((errno == EAGAIN) || (errno == EINTR))
					continue;
				break;
			}
			if (n != MBAP_HEADER_LEN + 2) {
				if (debug)
					Log("%s T:%ld read tcp_fd:%d MBAP error, expect %d, get %d, errno=%d, exit thread\n",
					    pname, pthread_self(), tcp_fd, MBAP_HEADER_LEN + 2, n, errno);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			if (debug)
				Log("%s T:%ld read %d bytes from tcp_fd:%d tcp REQ %s\n",
				    pname, pthread_self(), n, tcp_fd, dump_pkt(strbuf, tcpbuf, TCP));

			expected_len = htons(*((uint16_t *)(tcpbuf + MBAP_LENGTH_OFFSET)));
			if (expected_len > MAXRTULEN - RTU_HEADER_LEN) {
				Log("%s T:%ld expected_len %d too large tcp_fd:%d, exit thread\n",
				    pname, pthread_self(), expected_len, tcp_fd);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			if (debug)
				Log("%s T:%ld expected_len %d from tcp_fd:%d tcp\n",
				    pname, pthread_self(), expected_len - RTU_HEADER_LEN, tcp_fd);

			memcpy(rtubuf, tcpbuf + MBAP_UNITID_OFFSET, RTU_HEADER_LEN);
			n = read(tcp_fd, rtubuf + RTU_HEADER_LEN, expected_len - RTU_HEADER_LEN);
			if (debug)
				Log("%s T:%ld read %d bytes from tcp_fd:%d\n",
				    pname, pthread_self(), n, tcp_fd);
			if (n != expected_len - RTU_HEADER_LEN) {
				Log("%s T:%ld read tcp_fd:%d error, expect %d, get %d, exit thread\n",
				    pname, pthread_self(), tcp_fd, expected_len - RTU_HEADER_LEN, n);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			n = n + RTU_HEADER_LEN;

			/* Add CRC for RTU */
			uint16_t crc = crc16(rtubuf, n);
			rtubuf[n] = crc >> 8;
			rtubuf[n + 1] = crc & 0x00FF;
			n = n + RTU_CRC_LEN;

		} else if (s_type == RTU) {
			int packet_len;

			/* Read RTU header (8 bytes) */
			while (1) {
				n = read(tcp_fd, rtubuf, 8);
				if (n >= 0)
					break;
				if ((errno == EAGAIN) || (errno == EINTR))
					continue;
				break;
			}
			if (n != 8) {
				if (debug)
					Log("%s T:%ld read tcp_fd:%d rtu header error, expect 8, get %d, errno=%d, exit thread\n",
					    pname, pthread_self(), tcp_fd, n, errno);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			if (debug)
				Log("%s T:%ld read %d bytes from tcp_fd:%d rtu REQ %s\n",
				    pname, pthread_self(), n, tcp_fd, dump_pkt(strbuf, rtubuf, RTU));

			/* Calculate expected packet length based on function code */
			switch (rtubuf[1]) {
			case 1:		/* Read coils */
			case 2:		/* Read inputs */
			case 3:		/* Read holding regs */
			case 4:		/* Read input regs */
			case 5:		/* Write coil */
			case 6:		/* Write holding */
				packet_len = 8;
				break;
			case 15:	/* Write coils */
			case 16:	/* Write holdings */
				packet_len = 8 + rtubuf[6] + 1;
				break;
			default:
				Log("%s T:%ld unsupported function code: %d, exit thread\n",
				    pname, pthread_self(), rtubuf[1]);
				close(tcp_fd);
				pthread_exit(NULL);
			}

			if (packet_len > 8) {
				n = read(tcp_fd, rtubuf + 8, packet_len - 8);
				if (debug)
					Log("%s T:%ld read %d bytes from tcp_fd:%d rtu\n",
					    pname, pthread_self(), n, tcp_fd);
				if (n != packet_len - 8) {
					Log("%s T:%ld read tcp_fd:%d error, expect %d, get %d, exit thread\n",
					    pname, pthread_self(), tcp_fd, packet_len - 8, n);
					close(tcp_fd);
					pthread_exit(NULL);
				}
				n = packet_len;
			}

			/* Verify CRC */
			uint16_t crc = crc16(rtubuf, n - RTU_CRC_LEN);
			if ((rtubuf[n - 2] != (crc >> 8)) || (rtubuf[n - 1] != (crc & 0x00FF))) {
				Log("%s T:%ld read tcp_fd:%d CRC error, expect %02X%02X, get %02X%02X, exit thread\n",
				    pname, pthread_self(), tcp_fd, crc >> 8, crc & 0xff, rtubuf[n - 2], rtubuf[n - 1]);
				close(tcp_fd);
				pthread_exit(NULL);
			}
		}

		pthread_mutex_lock(&mutex);

		/*
		 * Now data read from s_socket is in rtubuf, len is n
		 */

		/*===========================================================
		 * STEP 2: write request to dev_fd
		 *===========================================================*/
		if (r_type == TCP) {
			if (s_type == RTU) {
				*((uint16_t *) tcpbuf) = htons(transid);
				transid++;
			}
			*((uint16_t *) (tcpbuf + MBAP_LENGTH_OFFSET)) = htons(n - RTU_HEADER_LEN);
			memcpy(tcpbuf + MBAP_HEADER_LEN, rtubuf, n - RTU_HEADER_LEN);
			nw = write(dev_fd, tcpbuf, n - RTU_HEADER_LEN + MBAP_HEADER_LEN);
			if (debug)
				Log("%s T:%ld write %d bytes to dev_fd:%d, return %d\n",
				    pname, pthread_self(), n - RTU_HEADER_LEN + MBAP_HEADER_LEN, dev_fd, nw);
		} else if (r_type == RTU) {
			nw = write(dev_fd, rtubuf, n);
			if (debug)
				Log("%s T:%ld write %d bytes to dev_fd:%d, return %d\n",
				    pname, pthread_self(), n, dev_fd, nw);
		}

		/*===========================================================
		 * STEP 3: read response from dev_fd
		 *===========================================================*/
		if (r_type == TCP) {
			uint8_t saved_transid[2];
			uint8_t slaveid;

			slaveid = tcpbuf[MBAP_UNITID_OFFSET];
			memcpy(saved_transid, tcpbuf, 2);

			n = read(dev_fd, tcpbuf, MBAP_HEADER_LEN + 2);
			if ((n == -1) && (errno == EAGAIN)) {
				pthread_mutex_unlock(&mutex);
				if (timeout_retry_exit == -1)
					continue;
				if (timeout_retry_exit <= 0) {
					Log("%s T:%ld read timeout dev_fd:%d tcp slaveid:%d, exit all\n",
					    pname, pthread_self(), dev_fd, slaveid);
					exit(EXIT_FAILURE);
				}
				timeout_retry_exit--;
				Log("%s T:%ld read timeout dev_fd:%d tcp slaveid:%d, timeout_retry: %d continue\n",
				    pname, pthread_self(), dev_fd, slaveid, timeout_retry_exit);
				continue;
			}
			if (n != MBAP_HEADER_LEN + 2) {
				Log("%s T:%ld read dev_fd:%d slaveid:%d MBAP error, expect %d, get %d, errno=%d, exit all\n",
				    pname, pthread_self(), dev_fd, slaveid, MBAP_HEADER_LEN + 2, n, errno);
				exit(EXIT_FAILURE);
			}
			if (debug)
				Log("%s T:%ld read %d bytes from dev_fd:%d tcp RESPONSE %s\n",
				    pname, pthread_self(), n, dev_fd, dump_pkt(strbuf, tcpbuf, TCP));

			if (memcmp(saved_transid, tcpbuf, 2) != 0) {
				Log("%s T:%ld read transid %02X%02X != send %02X%02X dev_fd:%d tcp slaveid:%d, exit all\n",
				    pname, pthread_self(), tcpbuf[0], tcpbuf[1], saved_transid[0], saved_transid[1], dev_fd, slaveid);
				exit(EXIT_FAILURE);
			}

			expected_len = htons(*((uint16_t *) (tcpbuf + MBAP_LENGTH_OFFSET)));
			if (expected_len > MAXRTULEN - RTU_HEADER_LEN) {
				Log("%s T:%ld expected_len %d too large dev_fd:%d, exit all\n",
				    pname, pthread_self(), expected_len, dev_fd);
				exit(EXIT_FAILURE);
			}

			memcpy(rtubuf, tcpbuf + MBAP_UNITID_OFFSET, RTU_HEADER_LEN);
			n = read(dev_fd, rtubuf + RTU_HEADER_LEN, expected_len - RTU_HEADER_LEN);
			if (debug)
				Log("%s T:%ld read %d bytes from dev_fd:%d tcp\n",
				    pname, pthread_self(), n, dev_fd);
			pthread_mutex_unlock(&mutex);

			if (n != expected_len - RTU_HEADER_LEN) {
				Log("%s T:%ld read dev_fd:%d slaveid:%d error, expect %d, get %d, exit all\n",
				    pname, pthread_self(), dev_fd, slaveid, expected_len - RTU_HEADER_LEN, n);
				exit(EXIT_FAILURE);
			}
			n = n + RTU_HEADER_LEN;

			/* Add CRC for RTU */
			uint16_t crc = crc16(rtubuf, n);
			rtubuf[n] = crc >> 8;
			rtubuf[n + 1] = crc & 0x00FF;
			n = n + RTU_CRC_LEN;

		} else if (r_type == RTU) {
			uint8_t slaveid;

			slaveid = rtubuf[0];
			n = read(dev_fd, rtubuf, 3);
			if ((n == -1) && (errno == EAGAIN)) {
				pthread_mutex_unlock(&mutex);
				if (timeout_retry_exit == -1)
					continue;
				if (timeout_retry_exit <= 0) {
					Log("%s T:%ld read timeout dev_fd:%d rtu slaveid:%d, exit all\n",
					    pname, pthread_self(), dev_fd, slaveid);
					exit(EXIT_FAILURE);
				}
				timeout_retry_exit--;
				Log("%s T:%ld read timeout dev_fd:%d rtu slaveid:%d, timeout_retry:%d continue\n",
				    pname, pthread_self(), dev_fd, slaveid, timeout_retry_exit);
				continue;
			}
			if (n != 3) {
				Log("%s T:%ld read dev_fd:%d rtu slaveid:%d header error, expect 3, get %d, errno=%d, exit all\n",
				    pname, pthread_self(), dev_fd, slaveid, n, errno);
				exit(EXIT_FAILURE);
			}
			if (debug)
				Log("%s T:%ld read %d bytes from dev_fd:%d rtu RESPONSE %s\n",
				    pname, pthread_self(), n, dev_fd, dump_pkt(strbuf, rtubuf, RTU));

			/* Calculate expected packet length based on function code */
			switch (rtubuf[1]) {
			case 1:		/* Read coils */
			case 2:		/* Read inputs */
			case 3:		/* Read holding regs */
			case 4:		/* Read input regs */
				expected_len = 5 + rtubuf[2];
				break;
			case 5:		/* Write coil */
			case 6:		/* Write holding */
			case 15:	/* Write coils */
			case 16:	/* Write holdings */
				expected_len = 8;
				break;
			case 0x81:	/* Exception codes */
			case 0x82:
			case 0x83:
			case 0x84:
			case 0x85:
			case 0x86:
			case 0x8f:
			case 0x90:
				expected_len = 5;
				break;
			default:
				Log("%s T:%ld unsupported function code: %d, sleep 10, exit all\n",
				    pname, pthread_self(), rtubuf[1]);
				sleep(10);
				exit(EXIT_FAILURE);
			}

			n = read(dev_fd, rtubuf + 3, expected_len - 3);
			if (debug)
				Log("%s T:%ld read %d bytes from dev_fd:%d rtu\n",
				    pname, pthread_self(), n, dev_fd);

			pthread_mutex_unlock(&mutex);

			if (n != expected_len - 3) {
				Log("%s T:%ld read dev_fd:%d error, expect %d, get %d, exit all\n",
				    pname, pthread_self(), dev_fd, expected_len - 3, n);
				exit(EXIT_FAILURE);
			}
			n = expected_len;

			/* Verify CRC */
			uint16_t crc_calculated = crc16(rtubuf, n - RTU_CRC_LEN);
			uint16_t crc_received = (rtubuf[n - 2] << 8) | rtubuf[n - 1];
			if (crc_calculated != crc_received) {
				Log("%s T:%ld dev_fd:%d CRC error %02X%02X should be %02X%02X, exit all\n",
				    pname, pthread_self(), dev_fd, rtubuf[n - 2], rtubuf[n - 1],
				    crc_calculated >> 8, crc_calculated & 0xff);
				exit(EXIT_FAILURE);
			}
		}

		/*===========================================================
		 * STEP 4: write response to tcp_fd
		 *===========================================================*/
		if (s_type == TCP) {
			memcpy(tcpbuf + MBAP_UNITID_OFFSET, rtubuf, n - RTU_HEADER_LEN);
			*((uint16_t *) (tcpbuf + MBAP_LENGTH_OFFSET)) = htons(n - RTU_HEADER_LEN);
			nw = write(tcp_fd, tcpbuf, n - RTU_HEADER_LEN + MBAP_HEADER_LEN);
			if (debug)
				Log("%s T:%ld write %d bytes to tcp_fd:%d, return %d\n",
				    pname, pthread_self(), n - RTU_HEADER_LEN + MBAP_HEADER_LEN, tcp_fd, nw);
		} else if (s_type == RTU) {
			nw = write(tcp_fd, rtubuf, n);
			if (debug)
				Log("%s T:%ld write %d bytes to tcp_fd:%d, return %d\n",
				    pname, pthread_self(), tcp_fd, n, nw);
		}
	}
}

int tcp_connect(const char *host, const char *serv)
{
	int sockfd, n;
	struct addrinfo hints, *res, *ressave;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
		Log("%s getaddrinfo error: %s\n", pname, gai_strerror(n));
		exit(EXIT_FAILURE);
	}
	ressave = res;

	do {
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0)
			continue;

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
			break;

		close(sockfd);
	} while ((res = res->ai_next) != NULL);

	if (res == NULL) {
		Log("%s connect to %s:%s failed\n", pname, host, serv);
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(ressave);

	return (sockfd);
}

void usage(void)
{
	printf("\nmodbus-multiplexer v1.0 by james@ustc.edu.cn\n");
	printf("Usage: modbus-multiplexer [options] listen_port remote_ip remote_port\n\n");
	printf("Options:\n");
	printf("  -n name      Process name\n");
	printf("  -d           Debug mode\n");
	printf("  -e count     Timeout retry count before exit (default: %d, -1: no exit)\n", DEFAULT_TIMEOUT_RETRY_EXIT);
	printf("  -t seconds   Socket timeout (1-%d, default: %d)\n", MAX_TIMEOUT - 1, DEFAULT_TIMEOUT);
	printf("  -s type      Server type: tcp or rtu\n");
	printf("  -r type      Remote type: tcp or rtu\n");
	printf("\nExamples:\n");
	printf("  tcp server:  modbus-multiplexer -s tcp -r tcp 502 192.168.1.100 502\n");
	printf("  rtu server:  modbus-multiplexer -s rtu -r rtu 502 /dev/ttyUSB0 9600\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int lfd;
	int optval;
	socklen_t optlen = sizeof(optval);
	int c;
	int *fd_ptr;
	pthread_t thread_id;
	pthread_attr_t attr;

	strcpy(pname, "modbus-multiplexer");

	while ((c = getopt(argc, argv, "n:s:r:he:t:d")) != EOF) {
		switch (c) {
		case 'h':
			usage();
			break;
		case 's':
			if (strcmp(optarg, "tcp") == 0)
				s_type = TCP;
			else if (strcmp(optarg, "rtu") == 0)
				s_type = RTU;
			else
				fprintf(stderr, "unknown s_type: %s\n", optarg);
			break;
		case 'r':
			if (strcmp(optarg, "tcp") == 0)
				r_type = TCP;
			else if (strcmp(optarg, "rtu") == 0)
				r_type = RTU;
			else
				fprintf(stderr, "unknown r_type: %s\n", optarg);
			break;
		case 'n':
			strncpy(pname, optarg, MAXLEN - 1);
			pname[MAXLEN - 1] = '\0';
			break;
		case 'e':
			timeout_retry_exit = atoi(optarg);
			if (timeout_retry_exit <= 0)
				timeout_retry_exit = -1;
			else if (timeout_retry_exit >= MAX_TIMEOUT)
				timeout_retry_exit = DEFAULT_TIMEOUT_RETRY_EXIT;
			break;
		case 't':
			time_out = atoi(optarg);
			if ((time_out <= 0) || (time_out >= MAX_TIMEOUT))
				time_out = DEFAULT_TIMEOUT;
			break;
		case 'd':
			debug = 1;
			break;
		}
	}

	if (argc - optind != 3) {
		usage();
	}

	printf("%s starting\n", pname);

	if (debug == 0) {
		daemon_init();
		while (1) {
			pid_t pid = fork();
			if (pid == 0)
				break;		/* child continues */
			else if (pid == -1) {
				Log("fork returned %d, exiting\n", pid);
				exit(EXIT_FAILURE);
			} else {
				Log("forked pid %d as server\n", pid);
				wait(NULL);
			}
			sleep(2);		/* restart on failure */
		}
	}

	/* Create listening socket */
	optval = 1;
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) {
		Log("%s socket error: %s\n", pname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);

	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[optind]));

	if (bind(lfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		Log("%s bind error: %s, exiting\n", pname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (listen(lfd, 64) < 0) {
		Log("%s listen error: %s, exiting\n", pname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Connect to remote server */
	dev_fd = tcp_connect(argv[optind + 1], argv[optind + 2]);

	/* Set TCP options for dev_fd */
	optval = 1;
	setsockopt(dev_fd, IPPROTO_TCP, TCP_NODELAY, &optval, optlen);
	setsockopt(dev_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
#ifdef __linux__
	optval = TCP_KEEPCNT_VAL;
	setsockopt(dev_fd, SOL_TCP_LEVEL, TCP_KEEPCNT_OPT, &optval, optlen);
	optval = TCP_KEEPIDLE_VAL;
	setsockopt(dev_fd, SOL_TCP_LEVEL, TCP_KEEPIDLE_OPT, &optval, optlen);
	optval = TCP_KEEPINTVL_VAL;
	setsockopt(dev_fd, SOL_TCP_LEVEL, TCP_KEEPINTVL_OPT, &optval, optlen);
#endif

	/* Set socket timeout for dev_fd */
	struct timeval timeout = { time_out, 0 };
	setsockopt(dev_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	setsockopt(dev_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	/* Initialize thread attributes for detached threads */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	/* Main accept loop */
	while (1) {
		int tcp_fd = accept(lfd, NULL, NULL);
		if (tcp_fd < 0) {
			Log("%s accept error: %s\n", pname, strerror(errno));
			continue;
		}

		/* Allocate memory for tcp_fd to pass to thread */
		fd_ptr = malloc(sizeof(int));
		if (fd_ptr == NULL) {
			Log("%s malloc failed, closing connection\n", pname);
			close(tcp_fd);
			continue;
		}
		*fd_ptr = tcp_fd;

		if (pthread_create(&thread_id, &attr, Process, fd_ptr) != 0) {
			Log("%s pthread_create failed: %s\n", pname, strerror(errno));
			free(fd_ptr);
			close(tcp_fd);
		}
	}

	pthread_attr_destroy(&attr);
	return (0);
}
