#define _GNU_SOURCE

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>

#include "logging.h"

#define PREENY_MAX_FD 8192
#define PREENY_SOCKET_OFFSET 500

//
// originals
//
int (*original_socket)(int, int, int);
int (*original_close)(int);
int (*original_select)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int (*original_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int (*original_sendto)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen);

struct sockaddr_in *addrs[PREENY_MAX_FD] = {0};
int fds[PREENY_MAX_FD] = {0};
int udp_fds[PREENY_MAX_FD] = {0};
fd_set r_fds;

__attribute__((destructor)) void preeny_desock_shutdown()
{
	int i;
	preeny_debug("shutting down desock...\n");

	for (i = 0; i < PREENY_MAX_FD; i++)
	{
		if (addrs[i] != NULL)
		{
			free(addrs[i]);
			original_close(fds[i]);
		}
	}

	preeny_debug("... shutdown complete!\n");
}
__attribute__((constructor)) void preeny_desock_orig()
{
	original_socket = dlsym(RTLD_NEXT, "socket");
	original_close = dlsym(RTLD_NEXT, "close");
	original_sendto = dlsym(RTLD_NEXT, "sendto");
	original_select = dlsym(RTLD_NEXT, "select");
	original_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
}

int get_fd(struct sockaddr_in *addr)
{
	if (addr->sin_addr.s_addr != NULL)
		preeny_info("Getting fd for: %s:%d\n", inet_ntoa(addr->sin_addr), addr->sin_port);
	for (int i = 0; i < PREENY_MAX_FD; i++)
	{
		if (addrs[i] == NULL)
			continue;

		if (addr->sin_addr.s_addr != NULL)
			preeny_info("Looking at: %s:%d with FD %d\n", inet_ntoa(addrs[i]->sin_addr), addrs[i]->sin_port, fds[i]);
		if (addrs[i]->sin_addr.s_addr == addr->sin_addr.s_addr && addrs[i]->sin_port == addr->sin_port)
		{
			return fds[i];
		}
	}

	return -1;
}

void set_fd(struct sockaddr_in *addr, int fd, int udp_fd)
{
	preeny_info("setting fd %d and udp_fd %d for: %s:%d\n", fd, udp_fd, inet_ntoa(addr->sin_addr), addr->sin_port);
	if (addrs[fd] != NULL)
		free(addrs[fd]);

	struct sockaddr_in *peer_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(peer_addr, '0', sizeof(struct sockaddr_in));
	// Set the contents in the peer's sock_addr.
	// Make sure the contents will simulate a real client that connects with the intercepted server, as the server may depend on the contents to make further decisions.
	// The followings set-up should be fine with Nginx.
	peer_addr->sin_family = AF_INET;
	peer_addr->sin_addr.s_addr = addr->sin_addr.s_addr;
	peer_addr->sin_port = addr->sin_port;

	addrs[fd] = peer_addr;
	fds[udp_fd] = fd;
	udp_fds[fd] = udp_fd;
	FD_SET(fd, &r_fds);
}

int socket(int domain, int type, int protocol)
{
	preeny_info(" --------------------- Calling socket ---------------------\n");
	if (type == SOCK_DGRAM)
	{
		type = SOCK_STREAM;
		preeny_info("Setting socket to SOCK_STREAM\n");
	}

	return original_socket(domain, type, protocol);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	preeny_info(" --------------------- Calling recvfrom ---------------------\n");
	int recv_fd = fds[sockfd];
	if (recv_fd <= 0)
		recv_fd = get_fd(src_addr);
	if (recv_fd <= 0)
	{
		if (listen(sockfd, PREENY_MAX_FD) != 0)
		{
			return -1;
		}
		preeny_info("Listening on socket: %d\n", sockfd);

		int new_fd = accept(sockfd, src_addr, addrlen);
		preeny_info("Accepting on socket: %d\n", sockfd);
		// original_close(sockfd);
		// dup2(new_fd, sockfd);
		preeny_info("Returned fd: %d\n", new_fd);
		if (new_fd < 0)
		{
			return -1;
		}
		set_fd(src_addr, new_fd, sockfd);
		recv_fd = new_fd;
	}
	// initialize a sockaddr_in for the peer
	preeny_info("Max read amount: %d\n", len);
	char tmp_buf[len + 2];
	int read_amount = read(recv_fd, tmp_buf, len + 2);
	memcpy(buf, &tmp_buf[2], read_amount);

	preeny_info("Read Amount: %d\n", read_amount);
	log_bytes(buf, len);

	return read_amount;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dst_addr, socklen_t addrlen)
{
	preeny_info(" --------------------- Calling sendto ---------------------\n");
	preeny_info("Sending: %d\n", len);
	preeny_info("Sent: %s\n", buf);
	int send_fd = fds[sockfd];
	if (send_fd <= 0)
		send_fd = get_fd(dst_addr);
	preeny_info("Send fd: %d\n", send_fd);
	if (send_fd <= 0)
	{
		return -1;
	}
	int amount_written = write(send_fd, buf, len);
	preeny_info("Amount Sent: %d\n", amount_written);
	log_bytes(buf, len);
	return amount_written;
}

void log_bytes(char *buf, int len)
{
	preeny_info("String: %s\n", buf);
	if (len > 0)
	{
		char new_buf[(len * 2) + 1];
		for (int i = 0; i < len; i++)
		{
			sprintf(new_buf + (i * 2), "%02hhx", buf[i]);
		}
		new_buf[len * 2] = 0;
		preeny_info("Bytes: 0x%s\n", new_buf);
	}
}
int close(int sockfd)
{
	preeny_info(" --------------------- Calling close ---------------------\n");
	preeny_info("Closing FD: %d\n", sockfd);
	if (fds[sockfd] > 0)
	{
		int old_fd = fds[sockfd];
		original_close(fds[sockfd]);
		addrs[old_fd] = NULL;
		return original_close(udp_fds[old_fd]);
	}

	return original_close(sockfd);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	preeny_info(" --------------------- Calling select ---------------------\n");
	int ready_fds = original_select(nfds, readfds, writefds, exceptfds, timeout);
	preeny_info("READY FDS: %d\n", ready_fds);
	// for (int udp_fd = 2; udp_fd < FD_SETSIZE; udp_fd++)
	//{
	//	if (FD_ISSET(fds[udp_fd], &r_fds))
	//	{
	//		preeny_info("Setting fd %d -> %d\n", fds[udp_fd], udp_fd);
	//		FD_SET(udp_fd, readfds);
	//	}
	//	else if (FD_ISSET(udp_fd, readfds))
	//	{
	//		preeny_info("Clearing fd %d -> %d\n", fds[udp_fd], udp_fd);
	//		FD_CLR(udp_fd, readfds);
	//	}
	// }

	return ready_fds;
}