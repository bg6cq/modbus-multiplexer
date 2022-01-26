#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <assert.h>
#include <pthread.h>
#include <ctype.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/wait.h>

#define MAXLEN 16384
#define MAXRTULEN 256

#define TCP 1
#define RTU 2

int dev_fd;
int debug = 0;
int timeout_exit = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int s_type = 1;
int r_type = 2;
char pname[MAXLEN];

void daemon_init(void)
{
	if (debug == 0) {
		int i;
		pid_t pid;
		if ((pid = fork()) != 0)
			exit(0);	/* parent terminates */
		/* 41st child continues */
		setsid();	/* become session leader */

		signal(SIGHUP, SIG_IGN);
		if ((pid = fork()) != 0)
			exit(0);	/* 1st child terminates */
		chdir("/");	/* change working directory */
		umask(0);	/* clear our file mode creation mask */
		for (i = 0; i < 3; i++)
			close(i);
		openlog(pname, LOG_PID, LOG_DAEMON);
	}
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
	int optval;
	socklen_t optlen = sizeof(optval);

	if (debug)
		printf("%s T:%ld start, tcp_fd:%d\n", pname, pthread_self(), tcp_fd);
	pthread_detach(pthread_self());

	optval = 1;
	setsockopt(tcp_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
	optval = 3;
	setsockopt(tcp_fd, SOL_TCP, TCP_KEEPCNT, &optval, optlen);
	optval = 2;
	setsockopt(tcp_fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen);
	optval = 2;
	setsockopt(tcp_fd, SOL_TCP, TCP_KEEPINTVL, &optval, optlen);

	struct timeval timeout = { 3, 0 };	// 3秒 超时时间
	setsockopt(tcp_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	setsockopt(tcp_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	while (1) {
		int n, nw __attribute__ ((unused)), expected_len;
		tcpbuf[0] = 0;
		tcpbuf[1] = 0;
		tcpbuf[2] = 0;
		tcpbuf[3] = 0;

		//===========================================
		// STEP 1: read request from tcp_fd to rtubuf
		//===========================================
		if (s_type == TCP) {
			while (1) {
				n = read(tcp_fd, tcpbuf, 8);
				if (n >= 0)
					break;
				if ((errno == EAGAIN) || (errno == EINTR))
					continue;
				break;
			}
			if (n != 8) {
				if (debug)
					printf
					    ("%s T:%ld read tcp_fd:%d MBAP error, expect 8, get %d, errno=%d, exit thread\n",
					     pname, pthread_self(), tcp_fd, n, errno);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			if (debug)
				printf("%s T:%ld read %d bytes from tcp_fd:%d tcp %s\n", pname,
				       pthread_self(), n, tcp_fd, dump_pkt(strbuf, tcpbuf, TCP));
			expected_len = htons(*((unsigned short *)(tcpbuf + 4)));
			if (expected_len > MAXRTULEN - 2) {
				if (debug)
					printf
					    ("%s T:%ld expected_len %d too large tcp_fd:%d, exit thread\n",
					     pname, pthread_self(), expected_len, tcp_fd);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			if (debug)
				printf("%s T:%ld expected_len %d from tcp_fd:%d tcp\n",
				       pname, pthread_self(), expected_len - 2, tcp_fd);
			memcpy(rtubuf, tcpbuf + 6, 2);
			n = read(tcp_fd, rtubuf + 2, expected_len - 2);
			if (debug)
				printf("%s T:%ld read %d bytes from tcp_fd:%d\n",
				       pname, pthread_self(), n, tcp_fd);
			if (n != expected_len - 2) {
				if (debug)
					printf
					    ("%s T:%ld read tcp_fd:%d error, expect %d, get %d, exit thread\n",
					     pname, pthread_self(), tcp_fd, expected_len - 2, n);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			n = n + 2;
			uint16_t crc = crc16(rtubuf, n);
			rtubuf[n] = crc >> 8;
			rtubuf[n + 1] = crc & 0x00FF;
			n = n + 2;
		} else if (s_type == RTU) {
			int packet_len;
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
					printf
					    ("%s T:%ld read tcp_fd:%d rtu header error, expect 8, get %d, errno=%d, exit thread\n",
					     pname, pthread_self(), tcp_fd, n, errno);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			if (debug)
				printf("%s T:%ld read %d bytes from tcp_fd:%d rtu %s\n", pname,
				       pthread_self(), n, tcp_fd, dump_pkt(strbuf, rtubuf, RTU));
			// expcted_len is the full packet len
			switch (rtubuf[1]) {	//Function code
			case 1:	//Read coils
			case 2:	//Read inputs
			case 3:	//Read holding regs
			case 4:	//Read input regs
			case 5:	//Write coil
			case 6:	//Write holding
				packet_len = 8;
				break;
			case 15:	//Write coils
			case 16:	//Write holdings
				packet_len = 8 + rtubuf[6] + 1;
				break;
			default:
				if (debug)
					printf
					    ("%s T:%ld unsupported function code: %d, exit thread\n",
					     pname, pthread_self(), rtubuf[1]);
				close(tcp_fd);
				pthread_exit(NULL);
			}
			if (packet_len > 8) {	// need read more
				n = read(tcp_fd, rtubuf + 8, packet_len - 8);
				if (debug)
					printf("%s T:%ld read %d bytes from tcp_fd:%d rtu\n",
					       pname, pthread_self(), n, tcp_fd);
				if (n != packet_len - 8) {
					if (debug)
						printf
						    ("%s T:%ld read tcp_fd:%d error, expect %d, get %d, exit thread\n",
						     pname, pthread_self(), tcp_fd, packet_len - 8,
						     n);
					close(tcp_fd);
					pthread_exit(NULL);
				}
				n = packet_len;
			} else
				n = 8;

			uint16_t crc = crc16(rtubuf, n - 2);
			if ((rtubuf[n - 2] != (crc >> 8)) || (rtubuf[n - 1] != (crc & 0x00FF))) {
				if (debug)
					printf
					    ("%s T:%ld read tcp_fd:%d CRC error, expect %02X%02X, get %02X%02X, exit thread\n",
					     pname, pthread_self(), tcp_fd, crc >> 8, crc & 0xff,
					     rtubuf[n - 2], rtubuf[n - 1]);
				close(tcp_fd);
				pthread_exit(NULL);
			};
		}

		pthread_mutex_lock(&mutex);

		//
		// now,  data read from s_socket in rtubuf, len is n
		//

		//===============================
		// STEP 2: write request to dev_fd
		//===============================
		if (r_type == TCP) {
			*((unsigned short *)(tcpbuf + 4)) = htons(n - 2);
			memcpy(tcpbuf + 6, rtubuf, n - 2);
			nw = write(dev_fd, tcpbuf, n - 2 + 6);
			if (debug)
				printf("%s T:%ld write %d bytes to dev_fd:%d, return %d\n",
				       pname, pthread_self(), n - 2 + 6, dev_fd, nw);
		} else if (r_type == RTU) {
			nw = write(dev_fd, rtubuf, n);
			if (debug)
				printf("%s T:%ld write %d bytes to dev_fd:%d, return %d\n",
				       pname, pthread_self(), n, dev_fd, nw);
		}
		//==================================
		// STEP 3: read response from dev_fd
		//==================================
		if (r_type == TCP) {
			n = read(dev_fd, tcpbuf, 8);
			if ((n == -1) && (errno == EAGAIN)) {
				pthread_mutex_unlock(&mutex);
				if (timeout_exit) {
					printf("%s T:%ld read timeout dev_fd:%d tcp, exit all\n",
					       pname, pthread_self(), dev_fd);
					exit(0);
				}
				printf("%s T:%ld read timeout dev_fd:%d tcp, continue\n", pname,
				       pthread_self(), dev_fd);
				continue;
			}
			if (n != 8) {
				if (debug)
					printf
					    ("%s T:%ld read dev_fd:%d MBAP error, expect 8, get %d, errno=%d, exit all\n",
					     pname, pthread_self(), dev_fd, n, errno);
				exit(0);
			}
			if (debug)
				printf("%s T:%ld read %d bytes from dev_fd:%d tcp %s\n", pname,
				       pthread_self(), n, dev_fd, dump_pkt(strbuf, tcpbuf, TCP));
			expected_len = htons(*((unsigned short *)(tcpbuf + 4)));
			if (expected_len > MAXRTULEN - 2) {
				if (debug)
					printf
					    ("%s T:%ld expected_len %d too large dev_fd:%d, exit all\n",
					     pname, pthread_self(), expected_len, dev_fd);
				exit(0);
			}
			memcpy(rtubuf, tcpbuf + 6, 2);
			n = read(dev_fd, rtubuf + 2, expected_len - 2);
			if (debug)
				printf("%s T:%ld read %d bytes from dev_fd:%d tcp\n", pname,
				       pthread_self(), n, dev_fd);
			pthread_mutex_unlock(&mutex);

			if (n != expected_len - 2) {
				if (debug)
					printf
					    ("%s T:%ld read dev_fd:%d error, expect %d, get %d, exit all\n",
					     pname, pthread_self(), dev_fd, expected_len - 2, n);
				exit(0);
			}
			n = n + 2;
			uint16_t crc = crc16(rtubuf, n);
			rtubuf[n] = crc >> 8;
			rtubuf[n + 1] = crc & 0x00FF;
			n = n + 2;
		} else if (r_type == RTU) {
			n = read(dev_fd, rtubuf, 3);
			if ((n == -1) && (errno == EAGAIN)) {
				pthread_mutex_unlock(&mutex);
				printf("%s T:%ld read timeout dev_fd:%d rtu, continue\n", pname,
				       pthread_self(), dev_fd);
				continue;
			}
			if (n != 3) {
				if (debug)
					printf
					    ("%s T:%ld read dev_fd:%d rtu header error, expect 3, get %d, errno=%d, exit all\n",
					     pname, pthread_self(), dev_fd, n, errno);
				exit(0);
			}
			if (debug)
				printf("%s T:%ld read %d bytes from dev_fd:%d rtu %s\n", pname,
				       pthread_self(), n, dev_fd, dump_pkt(strbuf, rtubuf, RTU));
			// expcted_len is the full packet len
			switch (rtubuf[1]) {	//Function code
			case 1:	//Read coils
			case 2:	//Read inputs
			case 3:	//Read holding regs
			case 4:	//Read input regs
				expected_len = 5 + rtubuf[2];
				break;
			case 5:	//Write coil
			case 6:	//Write holding
			case 15:	//Write coils
			case 16:	//Write holdings
				expected_len = 8;
				break;
			case 0x81:	// Exception
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
				if (debug)
					printf("%s T:%ld unsupported function code: %d, exit all\n",
					       pname, pthread_self(), rtubuf[1]);
				exit(0);
			}

			n = read(dev_fd, rtubuf + 3, expected_len - 3);
			if (debug)
				printf("%s T:%ld read %d bytes from dev_fd:%d rtu\n", pname,
				       pthread_self(), n, dev_fd);

			pthread_mutex_unlock(&mutex);

			if (n != expected_len - 3) {
				if (debug)
					printf
					    ("%s T:%ld read dev_fd:%d error, expect %d, get %d, exit all\n",
					     pname, pthread_self(), dev_fd, expected_len - 3, n);
				exit(0);
			}
			n = expected_len;
			uint16_t crc_calculated;
			uint16_t crc_received;
			crc_calculated = crc16(rtubuf, n - 2);
			crc_received = (rtubuf[n - 2] << 8) | rtubuf[n - 1];
			if (crc_calculated != crc_received) {
				if (debug)
					printf("%s T:%ld dev_fd:%d CRC error, exit all\n",
					       pname, pthread_self(), dev_fd);
				exit(0);
			}
		}
		//=================================
		// STEP 4: write response to tcp_fd
		//=================================
		if (s_type == TCP) {
			memcpy(tcpbuf + 6, rtubuf, n - 2);
			*((unsigned short *)(tcpbuf + 4)) = htons(n - 2);
			nw = write(tcp_fd, tcpbuf, n - 2 + 6);
			if (debug)
				printf("%s T:%ld write %d bytes to tcp_fd:%d, return %d\n",
				       pname, pthread_self(), n - 2 + 6, tcp_fd, nw);
		} else if (s_type == RTU) {
			nw = write(tcp_fd, rtubuf, n);
			if (debug)
				printf("%s T:%ld write %d bytes to tcp_fd:%d, return %d\n",
				       pname, pthread_self(), tcp_fd, n, nw);
		}
	}
}

int tcp_connect(const char *host, const char *serv)
{
	int sockfd, n;
	struct addrinfo hints, *res, *ressave;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((n = getaddrinfo(host, serv, &hints, &res)) != 0)
		exit(0);
	ressave = res;

	do {
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sockfd < 0)
			continue;	/* ignore this one */

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
			break;	/* success */

		close(sockfd);	/* ignore this one */
	} while ((res = res->ai_next) != NULL);

	if (res == NULL)	/* errno set from final connect() */
		exit(0);

	freeaddrinfo(ressave);

	return (sockfd);
}

void usage()
{
	printf("\nmodbus-multiplexer v1.0 by james@ustc.edu.cn\n");
	printf
	    ("modbus-multiplexer [ -s tcp | rtu ] [ -r tcp | rtu ] [ -e ] listen_port remote_ip remote_port\n\n");
	printf("      -n name\n");
	printf("      -d debug\n");
	printf("      -e when read from remote time out, exit all (default is continue)\n");
	printf("      -s tcp_server type\n");
	printf("      -r remote type\n");
	printf("        tcp means modbustcp frame\n");
	printf("        rtu means modbus rtu over tcp frame\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int lfd;
	int optval;
	socklen_t optlen = sizeof(optval);
	int c;
	strcpy(pname, "modbus-multiplexer");
	while ((c = getopt(argc, argv, "n:s:r:hed")) != EOF)
		switch (c) {
		case 'h':
			usage();
		case 's':
			if (strcmp(optarg, "tcp") == 0)
				s_type = TCP;
			else if (strcmp(optarg, "rtu") == 0)
				s_type = RTU;
			else
				printf("unknown s_type %s\n", optarg);
			break;
		case 'r':
			if (strcmp(optarg, "tcp") == 0)
				r_type = TCP;
			else if (strcmp(optarg, "rtu") == 0)
				r_type = RTU;
			else
				printf("unknown r_type %s\n", optarg);
			break;
		case 'n':
			strncpy(pname, optarg, MAXLEN);
			break;
		case 'e':
			timeout_exit = 1;
			break;
		case 'd':
			debug = 1;
			break;
		}

	if (argc - optind != 3) {
		usage();
		exit(0);
	}
	printf("%s starting\n", pname);

	signal(SIGCHLD, SIG_IGN);

	if (debug != 1) {
		daemon_init();
		while (1) {
			int pid;
			pid = fork();
			if (pid == 0)	// i am child, will do the job
				break;
			else if (pid == -1)	// error
				exit(0);
			else
				wait(NULL);
			sleep(2);	// if child exit, wait 2 second, and rerun
		}
	}

	optval = 1;
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
	setsockopt(lfd, IPPROTO_TCP, TCP_NODELAY, &optval, optlen);
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[optind]));
	if (bind(lfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		if (debug)
			printf("%s bind error\n", pname);
		exit(-1);
	}
	if (listen(lfd, 64) < 0) {
		if (debug)
			printf("%s listen error\n", pname);
		exit(-1);
	}
	dev_fd = tcp_connect(argv[optind + 1], argv[optind + 2]);

	setsockopt(dev_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
	optval = 3;
	setsockopt(dev_fd, SOL_TCP, TCP_KEEPCNT, &optval, optlen);
	optval = 2;
	setsockopt(dev_fd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen);
	optval = 2;
	setsockopt(dev_fd, SOL_TCP, TCP_KEEPINTVL, &optval, optlen);

	struct timeval timeout = { 3, 0 };	// 3秒 超时时间
	setsockopt(dev_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	setsockopt(dev_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	while (1) {
		pthread_t thread_id;
		int tcp_fd = accept(lfd, NULL, NULL);
		pthread_create(&thread_id, NULL, Process, &tcp_fd);
	}
	return (0);
}
