#ifndef _SYS_SHM_SYSV_H
#define _SYS_SHM_SYSV_H

#include <linux/shm.h>
#include <stdint.h>
#include <sys/types.h>

__BEGIN_DECLS

#ifndef shmid_ds
# define shmid_ds shmid64_ds
#endif

extern int shmctl(int shmid, int cmd, struct shmid_ds* buf);

extern int shmget(key_t key, size_t size, int shmflg);

extern void *shmat(int shmid, const void *shmaddr, int shmflg);

extern int shmdt(const void *shmaddr);

__END_DECLS

#endif
