#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/stat.h>
//#include <sys/memfd.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <pthread.h>

#define DBG_PREFIX "= "
#define ERR_PREFIX "=! "

#include "common.h"

#define uthash_fatal(msg) do { ERR_FMT("%s", (msg)); exit(1); } while(0)
#include "uthash.h"

#define exitWithError(EN, MSG, EC) {\
	errno = (EN);\
	ERR_PERROR(MSG);\
	exit(EC);\
}

typedef struct {
	const char *name;
	int fd;
	UT_hash_handle hh;
} shm_posix_alloc_t;

typedef struct {
	int id;
	int fd;
	shm_sysv_ctl_t ctl;
	UT_hash_handle hh;
} shm_sysv_alloc_t;

static int returnErrno(const int sock, const int err) {
	const int buf[] = {-1, err};
	if (writeAll(sock, (void *) buf, sizeof(buf)) != 0)
		return -1;
	return 0;
}

static int returnValue(const int sock, const int v) {
	const int ret = v;
	return writeAll(sock, &ret, sizeof(ret));
}

static int returnOk(const int sock) {
	return returnValue(sock, 0);
}

static int readField(const int sock, void *const v, const size_t l) {
	return readAll(sock, v, l);
}

static int writeField(const int sock, const void *const v, const size_t l) {
	return writeAll(sock, v, l);
}

static int readString(const int sock, char *const buf, const uint16_t len) {
	uint16_t l;
	if (readAll(sock, &l, sizeof(l)) != 0)
		return -1;
	if (l >= len) {
		errno = ENAMETOOLONG;
		return -1;
	}
	if (readAll(sock, buf, l) != 0)
		return -1;
	buf[l] = '\0';
	return 0;
}

static char *readStringEx(const int sock, const uint16_t limit) {
	uint16_t len;
	if (readAll(sock, &len, sizeof(len)) != 0)
		return NULL;
	if (len >= limit) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	char *const str = (char *) malloc(len + 1);
	if (str == NULL)
		uthash_fatal("OOM!");
	str[len] = '\0';
	if (readAll(sock, str, len) != 0) {
		free(str);
		return NULL;
	}
	return str;
}

static volatile shm_posix_alloc_t *g_shm_posix_reg = NULL;
static pthread_mutex_t g_shm_posix_lock = PTHREAD_MUTEX_INITIALIZER;

static volatile shm_sysv_alloc_t *g_shm_sysv_reg = NULL;
static pthread_mutex_t g_shm_sysv_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_shm_sysv_id = 0;
static volatile shm_sysv_alloc_t *g_shm_sysv_id_reg = NULL;

#define ReadNewString(N, L) char *const N = readStringEx(sock, (L));\
if (N == NULL) {\
	ERR_PERROR(ERRSTR_PROTO);\
	return;\
}

#define ReadN(P, V) if (read##P(sock, &(V), sizeof(V)) != 0) {\
	ERR_PERROR(ERRSTR_PROTO);\
	free((void*)name);\
	return;\
}

#define Read(P, V) if (read##P(sock, &(V), sizeof(V)) != 0) {\
	ERR_PERROR(ERRSTR_PROTO);\
	return;\
}

#define Write(P, V) if (write##P(sock, &(V), sizeof(V)) != 0) {\
	ERR_PERROR(ERRSTR_PROTO);\
	return;\
}

static void sysvShm_rm(shm_sysv_alloc_t *const rec) {
	close(rec->fd);
	if (rec->ctl.key != IPC_PRIVATE)
		HASH_DEL(g_shm_sysv_reg, rec);
	HASH_DEL(g_shm_sysv_id_reg, rec);
	DBG_FMT("SysV shm id %d has been removed", rec->id);
	free(rec);
}

sock_auth_key_t auth_key;

static void handleRequest(const int sock) {
	struct ucred cr;
	socklen_t cr_len;
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) != 0) {
		ERR_PERROR("Can't get peer creds");
		return;
	}
	if (authSocketByKey(sock, &auth_key) != 0) return;
	uint8_t cmd;
	if (readAll(sock, &cmd, sizeof(cmd))) {
		ERR_PERROR(ERRSTR_PROTO);
		return;
	}
	switch(cmd) {
		case C_SHM_OPEN: {
			char doTrunc = 0;
			const ReadNewString(name, PATH_MAX);
			uint32_t oflag;
			ReadN(Field, oflag);
			uint32_t mode;
			ReadN(Field, mode);
			DBG_FMT("A new Posix shm fragment at `%s'...", name);
			shm_posix_alloc_t *rec;
			pthread_mutex_lock(&g_shm_posix_lock);
			HASH_FIND_STR(g_shm_posix_reg, name, rec);
			if (rec == NULL) {
				if (!(oflag & O_CREAT)) {
					pthread_mutex_unlock(&g_shm_posix_lock);
					free((void*)name);
					returnErrno(sock, ENOENT);
					return;
				}
				const int fd = memfd_create("shm-posix-alloc-emu", MFD_CLOEXEC);
				if (fd == -1) {
					const int err = errno;
					pthread_mutex_unlock(&g_shm_posix_lock);
					ERR_PERROR("memfd_create() fails");
					free((void*)name);
					returnErrno(sock, err);
					return;
				}
				rec = malloc(sizeof(*rec));
				if (rec == NULL) {
					pthread_mutex_unlock(&g_shm_posix_lock);
					uthash_fatal("OOM!");
				}
				rec->name = name;
				rec->fd = fd;
				HASH_ADD_KEYPTR(hh, g_shm_posix_reg, name, strlen(name), rec);
				pthread_mutex_unlock(&g_shm_posix_lock);
			} else {
				pthread_mutex_unlock(&g_shm_posix_lock);
				free((void*)name);
				if ((oflag & O_CREAT) && (oflag & O_EXCL)) {
					returnErrno(sock, EEXIST);
					return;
				}
				if (oflag & O_TRUNC)
					doTrunc = 1;
			}
			if (doTrunc)
				if (ftruncate(rec->fd, 0) != 0) {
					returnErrno(sock, EACCES);
					return;
				}
			DBG_FMT("Posix shm fragment at `%s' has been created", name);
			const int ret = 0;
			sendFds(sock, &ret, sizeof(ret), &(rec->fd), 1);
			return;
		}
		case C_SHM_UNLINK: {
			const ReadNewString(name, PATH_MAX);
			DBG_FMT("Unlinking Posix shm fragment at `%s'", name);
			shm_posix_alloc_t *rec;
			pthread_mutex_lock(&g_shm_posix_lock);
			HASH_FIND_STR(g_shm_posix_reg, name, rec);
			if (rec == NULL) {
				pthread_mutex_unlock(&g_shm_posix_lock);
				free((void*)name);
				returnErrno(sock, ENOENT);
				return;
			}
			HASH_DEL(g_shm_posix_reg, rec);
			pthread_mutex_unlock(&g_shm_posix_lock);
			close(rec->fd);
			free((void*)(rec->name));
			free(rec);
			free((void*)name);
			const int ret = 0;
			writeAll(sock, &ret, sizeof(ret));
			return;
		}
		case C_SHMCTL: {
			int id;
			Read(Field, id);
			int cmd;
			Read(Field, cmd);
			switch (cmd) {
				case IPC_STAT: {
					DBG_FMT("IPC_STAT for SysV shm fragment %d", id);
					shm_sysv_alloc_t *rec;
					pthread_mutex_lock(&g_shm_sysv_lock);
					HASH_FIND_INT(g_shm_sysv_id_reg, &id, rec);
					pthread_mutex_unlock(&g_shm_sysv_lock);
					if (rec == NULL) {
						returnErrno(sock, EINVAL);
						return;
					}
					returnOk(sock);
					writeAll(sock, &rec->ctl, sizeof(rec->ctl));
					return;
				}
				case IPC_RMID: {
					DBG_FMT("Removing SysV shm fragment %d", id);
					shm_sysv_alloc_t *rec;
					pthread_mutex_lock(&g_shm_sysv_lock);
					HASH_FIND_INT(g_shm_sysv_id_reg, &id, rec);
					if (rec != NULL) {
						rec->ctl.ctime = time(NULL);
						rec->ctl.state |= SHMSYSV_ST_RM;
						if (rec->ctl.ref_cnt == 0)
							sysvShm_rm(rec);
					}
					pthread_mutex_unlock(&g_shm_sysv_lock);
					returnOk(sock);
					return;
				}
			}
			ERR_FMT("Unknown command %d on SysV shm fragment %d", cmd, id);
			returnErrno(sock, EINVAL);
			return;
		}
		case C_SHMGET: {
			key_t key;
			Read(Field, key);
			size_t size;
			Read(Field, size);
			int shmflg;
			Read(Field, shmflg);
			DBG_FMT("A new SysV shm fragment at key %d...", key);
			shm_sysv_alloc_t *rec;
			pthread_mutex_lock(&g_shm_sysv_lock);
			HASH_FIND(hh, g_shm_sysv_reg, &key, sizeof(key), rec);
			if (rec == NULL) {
				if (!(shmflg & IPC_CREAT)) {
					pthread_mutex_unlock(&g_shm_sysv_lock);
					returnErrno(sock, ENOENT);
					return;
				}
				const int fd = memfd_create("shm-sysv-alloc-emu", MFD_CLOEXEC);
				if (fd == -1) {
					const int err = errno;
					pthread_mutex_unlock(&g_shm_sysv_lock);
					ERR_PERROR("memfd_create() fails");
					returnErrno(sock, err);
					return;
				}
				if (ftruncate(fd, size) != 0) {
					const int err = errno;
					pthread_mutex_unlock(&g_shm_sysv_lock);
					ERR_PERROR("ftruncate() fails");
					returnErrno(sock, err);
					return;
				}
				rec = malloc(sizeof(*rec));
				if (rec == NULL) {
					pthread_mutex_unlock(&g_shm_sysv_lock);
					uthash_fatal("OOM!");
				}
				rec->ctl.state = 0;
				rec->ctl.ref_cnt = 0;
				rec->ctl.key = key;
				rec->ctl.atime =
				rec->ctl.dtime =
				rec->ctl.ctime = time(NULL);
				rec->ctl.cpid =
				rec->ctl.lpid = cr.pid;
				rec->id = g_shm_sysv_id++ & (((int) -1) >> 1);
				rec->fd = fd;
				rec->ctl.at.size = size;
				rec->ctl.at.shmflg = shmflg;
				if (key != IPC_PRIVATE)
					HASH_ADD(hh, g_shm_sysv_reg, ctl.key, sizeof(rec->ctl.key), rec);
				HASH_ADD_INT(g_shm_sysv_id_reg, id, rec);
				pthread_mutex_unlock(&g_shm_sysv_lock);
			} else {
				pthread_mutex_unlock(&g_shm_sysv_lock);
				if ((shmflg & IPC_CREAT) && (shmflg & IPC_EXCL)) {
					returnErrno(sock, EEXIST);
					return;
				}
			}
			DBG_FMT("SysV shm fragment at key %d has been created with id %d", key, rec->id);
			returnValue(sock, rec->id);
			return;
		}
		case C_SHMAT: {
			int id;
			Read(Field, id);
			DBG_FMT("Attaching SysV shm fragment id %d", id);
			shm_sysv_alloc_t *rec;
			pthread_mutex_lock(&g_shm_sysv_lock);
			HASH_FIND_INT(g_shm_sysv_id_reg, &id, rec);
			if (rec == NULL) {
				pthread_mutex_unlock(&g_shm_sysv_lock);
				returnErrno(sock, EINVAL);
				return;
			}
			rec->ctl.atime = time(NULL);
			rec->ctl.lpid = cr.pid;
			rec->ctl.ref_cnt += 1;
			pthread_mutex_unlock(&g_shm_sysv_lock);
			const int ret = 0;
			sendFds(sock, &ret, sizeof(ret), &(rec->fd), 1);
			writeAll(sock, &rec->ctl.at, sizeof(rec->ctl.at));
			return;
		}
		case C_SHMDT: {
			int id;
			Read(Field, id);
			DBG_FMT("Detaching SysV shm fragment id %d", id);
			shm_sysv_alloc_t *rec;
			pthread_mutex_lock(&g_shm_sysv_lock);
			HASH_FIND_INT(g_shm_sysv_id_reg, &id, rec);
			if (rec != NULL) {
				if (rec->ctl.ref_cnt != 0) { // it happens...
					rec->ctl.dtime = time(NULL);
					rec->ctl.lpid = cr.pid;
					rec->ctl.ref_cnt -= 1;
				}
				if (rec->ctl.ref_cnt == 0 &&
						(rec->ctl.state & SHMSYSV_ST_RM)) {
					sysvShm_rm(rec);
				}
			}
			pthread_mutex_unlock(&g_shm_sysv_lock);
			returnOk(sock);
			return;
		}
		default:
			ERR_STR(ERRSTR_PROTO ": bad command");
	}
}

static void *clientHandler(void *const arg) {
	const int sock = (int) arg;
	handleRequest(sock);
	close(sock);
	return NULL;
}

static inline X_ToAbstract(bind)

int main(const int argc, char **const argv) {
	if (getServerKey(&auth_key) != 0) return 1;
	const char *const sockName = getServSockName();
	if (sockName == NULL) return 1;
	const int servSock = bindToAbstract(sockName);
	if (servSock == -1) return 1;
	if (listen(servSock, 16) != 0) {
		ERR_PERROR(ERRSTR_PROTO);
		return 1;
	}
	int err;
	pthread_attr_t threadAttrs;
	err = pthread_attr_init(&threadAttrs);
	if (err != 0) {
		exitWithError(err, "Oof", 1);
	}
	err = pthread_attr_setdetachstate(&threadAttrs, PTHREAD_CREATE_DETACHED);
	if (err != 0) {
		exitWithError(err, "Oof", 1);
	}
	while (1) {
		const int sock = accept(servSock, NULL, NULL);
		if (sock == -1) {
			ERR_PERROR("Error receiving connection");
			continue;
		}
		pthread_t thread;
		err = pthread_create(&thread, &threadAttrs, clientHandler, (void *) sock);
		if (err != 0) {
			exitWithError(err, "Oof", 1);
		}
	}
	return 0;
}
