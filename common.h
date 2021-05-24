#pragma once

#include <sys/types.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <stdio.h>

#define SERV_SOCK_VAR_NAME "LIBWRAPDROID_SOCKET_NAME"
#define SERV_AUTH_VAR_NAME "LIBWRAPDROID_AUTH_KEY"

typedef uint32_t sock_auth_key_field_t;

typedef union __attribute__((packed)) {
	uint64_t v;
	struct __attribute__((packed)) {
		sock_auth_key_field_t key1;
		sock_auth_key_field_t key2;
	};
} sock_auth_key_t;

#define C_SHM_OPEN 1
#define C_SHM_UNLINK 2

#define C_SHMCTL 0x10
#define C_SHMGET 0x11
#define C_SHMAT 0x12
#define C_SHMDT 0x13

#define ERRSTR_PROTO "Protocol failure"

#ifdef DBG_QUIET
#define DBG_PERROR(M)
#define DBG_FMT(...)
#define DBG_STR(M)
#endif

#ifndef DBG_PREFIX
#define DBG_PREFIX "~ "
#endif

#ifndef DBG_PERROR
#define DBG_PERROR(M) perror(DBG_PREFIX M)
#endif

#ifndef DBG_FMT
#define DBG_FMT(F, ...) fprintf(stderr, DBG_PREFIX F "\n", ##__VA_ARGS__)
#endif

#ifndef DBG_STR
#define DBG_STR(M) fputs(DBG_PREFIX M "\n", stderr)
#endif

#ifdef ERR_QUIET
#define ERR_PERROR(M)
#define ERR_FMT(...)
#define ERR_STR(M)
#endif

#ifndef ERR_PREFIX
#define ERR_PREFIX "~! "
#endif

#ifndef ERR_PERROR
#define ERR_PERROR(M) perror(ERR_PREFIX M)
#endif

#ifndef ERR_FMT
#define ERR_FMT(F, ...) fprintf(stderr, ERR_PREFIX F "\n", ##__VA_ARGS__)
#endif

#ifndef ERR_STR
#define ERR_STR(M) fputs(ERR_PREFIX M "\n", stderr)
#endif

/* <=---=> */

/* Hello, Musl C! (Alpine Linux at least) */

/* Evaluate EXPRESSION, and repeat as long as it returns -1 with `errno'
   set to EINTR. */

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression)\
  (__extension__\
    ({ long int __result;\
       do __result = (long int) (expression);\
       while (__result == -1L && errno == EINTR);\
       __result; }))
#endif

/* <=---=> */

ssize_t recvFds(const int sockfd,
                void *data, size_t len,
                int *fds, size_t *fdsc);

ssize_t sendFds(const int sockfd,
                const void *data, size_t len,
                const int *fds, size_t fdsc);

int readAll(int sock, void *buf, size_t len);

int writeAll(int sock, const void *buf, size_t len);

static inline const char *getEnvVar(const char *const name) {
	const char *const v = getenv(name);
	if (v == NULL || *v == '\0') {
		ERR_FMT("%s is not set!", name);
		return NULL;
	}
	return v;
}

static inline const char *getServSockName(void) {
	return getEnvVar(SERV_SOCK_VAR_NAME);
}

static inline int getClientKey(sock_auth_key_t *const key) {
	const char *const key_s = getEnvVar(SERV_AUTH_VAR_NAME);
	if (key_s == NULL)
		return -1;
	if (strlen(key_s) < 16) {
		ERR_STR(SERV_AUTH_VAR_NAME " is shorter than 16 symbols!");
		return -1;
	}
	char _key_s[17];
	memcpy(_key_s, key_s, 16);
	_key_s[16] = '\0';
	char *key_e;
	const uint64_t v = strtoull(_key_s, &key_e, 16);
	if (*key_e != 0) {
		return -1;
	}
	key->v = v;
	return 0;
}

static inline int getServerKey(sock_auth_key_t *const key) {
	sock_auth_key_t k;
	if (getClientKey(&k) != 0) return -1;
	key->key1 = k.key2;
	key->key2 = k.key1;
	return 0;
}

static inline int authSocketByKey(const int sock, const sock_auth_key_t *const key) {
	sock_auth_key_field_t peer_key;
	if (writeAll(sock, &key->key2, sizeof(key->key2)) != 0) {
		ERR_PERROR(ERRSTR_PROTO);
		return -1;
	}
	if (readAll(sock, &peer_key, sizeof(peer_key)) != 0) {
		ERR_PERROR(ERRSTR_PROTO);
		return -1;
	}
	if (peer_key != key->key1) {
		ERR_STR("Spoofing detected!");
		return -1;
	}
	return 0;
}

static inline int checkClientSocket(const int sock) {
	sock_auth_key_t key;
	if (getClientKey(&key) != 0) return -1;
	return authSocketByKey(sock, &key);
}

static inline int checkServerSocket(const int sock) {
	sock_auth_key_t key;
	if (getServerKey(&key) != 0) return -1;
	return authSocketByKey(sock, &key);
}

static inline int checkSocketCreds(const struct ucred *creds) {
	uid_t uid;
	const char *const uid_s = getenv("TERMSH_UID");
	if (uid_s == NULL || *uid_s == '\0') uid = getuid();
	else {
		char *uid_e;
		uid = (uid_t) strtoul(uid_s, &uid_e, 0);
		if (*uid_e != '\0') {
			ERR_FMT("Bad TERMSH_UID value: `%s'", uid_s);
			return -1;
		}
	}
	if (creds->uid != uid) {
		ERR_STR("Spoofing detected!");
		return -1;
	}
	return 0;
}

#define X_ToAbstract(F) int F##ToAbstract(const char *name) {\
	const size_t nameLen = strlen(name);\
	if (nameLen + 2 > sizeof(((struct sockaddr_un *) NULL)->sun_path)) {\
		errno = ENAMETOOLONG;\
		ERR_PERROR("Bad socket name");\
		return -1;\
	}\
	const int sock = socket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);\
	if (sock == -1) {\
		ERR_PERROR("Unable to create socket");\
		return -1;\
	}\
	struct sockaddr_un sockAddr;\
	memset(&sockAddr, 0, sizeof(sockAddr));\
	sockAddr.sun_family = AF_LOCAL;\
	memcpy(sockAddr.sun_path + 1, name, nameLen);\
	if (F(sock, (struct sockaddr*) &sockAddr,\
			nameLen + offsetof(struct sockaddr_un, sun_path))\
			!= 0) {\
		ERR_PERROR("Unable to " #F "()");\
		close(sock);\
		return -1;\
	}\
	return sock;\
}

typedef struct __attribute__((packed)) { // `packed' is not default for ARMs in GCC
	size_t size;
	int shmflg;
} shm_sysv_at_t;

typedef struct __attribute__((packed)) { // `packed' is not default for ARMs in GCC
	key_t key;
	shm_sysv_at_t at;
	int state;
	size_t ref_cnt;
	time_t atime;
	time_t dtime;
	time_t ctime;
	pid_t cpid;
	pid_t lpid;
} shm_sysv_ctl_t;

#define SHMSYSV_ST_RM 1
