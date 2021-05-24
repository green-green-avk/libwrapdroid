#include <string.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

#include "common-cli.h"

#define uthash_fatal(msg) do { ERR_FMT("%s", (msg)); exit(1); } while(0)
#include "uthash.h"

typedef struct {
	void *addr;
	size_t size;
	int id;
	UT_hash_handle hh;
} shm_sysv_map_t;

static volatile shm_sysv_map_t *g_shm_sysv_map_reg = NULL;
static pthread_mutex_t g_shm_sysv_map_lock = PTHREAD_MUTEX_INITIALIZER;

#define WriteField(V) if (writeAll(sock, &(V), sizeof(V)) != 0) {\
	close(sock);\
	DBG_FMT("Error posting " #V);\
	errno = EACCES;\
	return -1;\
}

int shmctl(const int shmid, const int cmd, struct shmid_ds *const buf) {
	switch(cmd) {
		case IPC_STAT: {
			const int sock = connectToServer();
			if (sock == -1) return -1;
			Write(Command, C_SHMCTL);
			WriteField(shmid);
			WriteField(cmd);
			int retCode;
			if (readAll(sock, &retCode, sizeof(retCode)) != 0) {
				close(sock);
				errno = EACCES;
				return -1;
			}
			if (retCode != 0) {
				processError(sock);
				return retCode;
			}
			shm_sysv_ctl_t rec_ctl;
			if (readAll(sock, &rec_ctl, sizeof(rec_ctl)) != 0) {
				close(sock);
				errno = EACCES;
				return -1;
			}
			close(sock);
			/* Report max permissive mode */
			memset(buf, 0, sizeof(struct shmid_ds));
			buf->shm_segsz = rec_ctl.at.size;
			buf->shm_atime = rec_ctl.atime;
			buf->shm_dtime = rec_ctl.dtime;
			buf->shm_ctime = rec_ctl.ctime;
			buf->shm_cpid = rec_ctl.cpid;
			buf->shm_lpid = rec_ctl.lpid;
			buf->shm_nattch = rec_ctl.ref_cnt;
			buf->shm_perm.__key = rec_ctl.key;
			buf->shm_perm.uid = geteuid();
			buf->shm_perm.gid = getegid();
			buf->shm_perm.cuid = geteuid();
			buf->shm_perm.cgid = getegid();
			buf->shm_perm.mode = 0666;
			buf->shm_perm.__seq = 1;
			return 0;
		}
		case IPC_RMID: {
			DBG_FMT("Deleting SysV key id %d...", shmid);
			const int sock = connectToServer();
			if (sock == -1) return -1;
			Write(Command, C_SHMCTL);
			WriteField(shmid);
			WriteField(cmd);
			int retCode;
			if (readAll(sock, &retCode, sizeof(retCode)) != 0) {
				close(sock);
				errno = EACCES;
				return -1;
			}
			if (retCode != 0) {
				processError(sock);
				return retCode;
			}
			close(sock);
			return 0;
		}
		default:
			errno = EINVAL;
			return -1;
	}
}

int shmget(const key_t key, const size_t size, const int shmflg) {
	DBG_FMT("SysV key %d for size %lu...", key, size);
	const int sock = connectToServer();
	if (sock == -1) return -1;
	Write(Command, C_SHMGET);
	WriteField(key);
	WriteField(size);
	WriteField(shmflg);
	int retCode;
	if (readAll(sock, &retCode, sizeof(retCode)) != 0) {
		close(sock);
		ERR_FMT("Protocol error");
		errno = EACCES;
		return -1;
	}
	if (retCode == -1) {
		ERR_FMT("Error from server");
		processError(sock);
		return retCode;
	}
	close(sock);
	DBG_FMT("SysV key %d id: %d", key, retCode);
	return retCode;
}

typedef struct __attribute__((packed)) { // `packed' is not default for ARMs in GCC
	uint8_t cmd;
	int id;
} shm_sysv_op_t;

static int sysvSendOp(const int sock, const uint8_t cmd, const int shmid) {
	const shm_sysv_op_t buf = {cmd, shmid};
	return writeAll(sock, &buf, sizeof(buf));
}

static int shmdtById(const int shmid) {
	const int sock = connectToServer();
	if (sock == -1) return -1;
	if (sysvSendOp(sock, C_SHMDT, shmid) != 0) {
		close(sock);
		ERR_FMT("Protocol error");
		errno = EACCES;
		return -1;
	}
	int retCode;
	if (readAll(sock, &retCode, sizeof(retCode)) != 0) {
		close(sock);
		ERR_FMT("Protocol error");
		errno = EACCES;
		return -1;
	}
	if (retCode != 0) {
		ERR_FMT("Error from server");
		processError(sock);
		return -1;
	}
	return 0;
}

void *shmat(const int shmid, const void *const shmaddr, const int shmflg) {
	DBG_FMT("Attaching SysV key id %d... (pid: %d)", shmid, getpid());
	const int sock = connectToServer();
	if (sock == -1) return (void *) -1;
	if (sysvSendOp(sock, C_SHMAT, shmid) != 0) {
		close(sock);
		ERR_FMT("Protocol error");
		errno = EACCES;
		return (void *) -1;
	}
	int fd;
	size_t fdsc = 1;
	int retCode;
	if (recvFds(sock, &retCode, sizeof(retCode), &fd, &fdsc) != sizeof(retCode)) {
		close(sock);
		ERR_FMT("Protocol error");
		errno = EACCES;
		return (void *) -1;
	}
	if (retCode != 0) {
		ERR_FMT("Error from server");
		processError(sock);
		return (void *) -1;
	}
	if (fdsc != 1) {
		close(sock);
		ERR_FMT("No FD");
		errno = EACCES;
		return (void *) -1;
	}
	shm_sysv_at_t rec_at;
	if (readAll(sock, &rec_at, sizeof(rec_at)) != 0) {
		close(sock);
		close(fd);
		ERR_FMT("Protocol error");
		errno = EACCES;
		return (void *) -1;
	}
	int prot = (shmflg & SHM_RDONLY) ?
		PROT_READ : (PROT_READ | PROT_WRITE);
	if (shmflg & SHM_EXEC)
		prot |= PROT_EXEC;
	int flags = MAP_SHARED;
	if (rec_at.shmflg & SHM_NORESERVE)
		flags |= MAP_NORESERVE;
	shm_sysv_map_t *map_rec = NULL;
	pthread_mutex_lock(&g_shm_sysv_map_lock);
	if (shmaddr != NULL) {
		HASH_FIND_PTR(g_shm_sysv_map_reg, &shmaddr, map_rec);
	}
	if (map_rec != NULL) {
		if (shmflg & SHM_REMAP) {
			munmap(map_rec->addr, map_rec->size);
			HASH_DEL(g_shm_sysv_map_reg, map_rec);
		} else {
			pthread_mutex_unlock(&g_shm_sysv_map_lock);
			close(fd);
			ERR_FMT("%d already mapped at address %p", shmid, shmaddr);
			errno = EINVAL;
			return (void *) -1;
		}
	} else {
		map_rec = malloc(sizeof(*map_rec));
		if (map_rec == NULL)
			uthash_fatal("OOM!");
	}
	void *const r = mmap((void *) shmaddr, rec_at.size, prot, flags, fd, 0);
	if (r == MAP_FAILED) {
		const int err = errno;
		pthread_mutex_unlock(&g_shm_sysv_map_lock);
		close(fd);
		free(map_rec);
		ERR_FMT("%d: mmap(%p, %lu, %08X, %08X, %d, 0) failed", shmid, shmaddr, rec_at.size, prot, flags, fd);
		shmdtById(shmid);
		errno = err;
		return (void *) -1;
	}
	close(fd);
	map_rec->addr = r;
	map_rec->size = rec_at.size;
	map_rec->id = shmid;
	HASH_ADD_PTR(g_shm_sysv_map_reg, addr, map_rec);
	pthread_mutex_unlock(&g_shm_sysv_map_lock);
	DBG_FMT("Attached SysV key id %d at %p (pid: %d)", shmid, r, getpid());
	return r;
}

int shmdt(const void *const shmaddr) {
	DBG_FMT("Detaching SysV key id at %p... (pid: %d)", shmaddr, getpid());
	shm_sysv_map_t *map_rec;
	pthread_mutex_lock(&g_shm_sysv_map_lock);
	HASH_FIND_PTR(g_shm_sysv_map_reg, &shmaddr, map_rec);
	if (map_rec == NULL) {
		pthread_mutex_unlock(&g_shm_sysv_map_lock);
		errno = EINVAL;
		return -1;
	}
	munmap(map_rec->addr, map_rec->size);
	HASH_DEL(g_shm_sysv_map_reg, map_rec);
	pthread_mutex_unlock(&g_shm_sysv_map_lock);
	const int id = map_rec->id;
	free(map_rec);
	return shmdtById(id);
}
