#ifndef _SYS_SHM_POSIX_H
#define _SYS_SHM_POSIX_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

__BEGIN_DECLS

extern int shm_open(const char *name, int oflag, mode_t mode);

extern int shm_unlink(const char *name);

__END_DECLS

#endif
