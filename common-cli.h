#pragma once

#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#define DBG_PREFIX "- "
#define ERR_PREFIX "-! "

#include "common.h"

static int writeU32(const int sock, const uint32_t v) {
	return writeAll(sock, &v, sizeof(v));
}

static int writeString(const int sock, const char *const v) {
	const uint16_t len = strlen(v);
	if (writeAll(sock, &len, sizeof(len)) != 0)
		return -1;
	if (writeAll(sock, v, len) != 0)
		return -1;
	return 0;
}

static int writeCommand(const int sock, const uint8_t cmd) {
	return writeAll(sock, &cmd, sizeof(cmd));
}

static inline X_ToAbstract(connect)

static int connectToServer() {
	const char *const sockName = getServSockName();
	if (sockName == NULL) {
		errno = EACCES;
		return -1;
	}
	const int sock = connectToAbstract(sockName);
	if (sock == -1) {
		errno = EACCES;
		return -1;
	}
	if (checkClientSocket(sock) != 0) {
		close(sock);
		errno = EACCES;
		return -1;
	}
	return sock;
}

static int processError(const int sock) {
	int err;
	if (readAll(sock, &err, sizeof(err)) != 0) {
		close(sock);
		errno = EACCES;
		return -1;
	}
	close(sock);
	errno = err;
	return 0;
}

#define Write(P, V) if (write##P(sock, (V)) != 0) {\
	close(sock);\
	errno = EACCES;\
	return -1;\
}

#define WriteR(P, V, R) if (write##P(sock, (V)) != 0) {\
	close(sock);\
	errno = EACCES;\
	return R;\
}

#define ReadBuf(V, L) if (readAll(sock, (V), (L)) != 0) {\
	close(sock);\
	errno = EACCES;\
	return -1;\
}

#define WriteBuf(V, L) if (writeAll(sock, (V), (L)) != 0) {\
	close(sock);\
	errno = EACCES;\
	return -1;\
}
