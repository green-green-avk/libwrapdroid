TGT_NAME = libwrapdroid
TGT_SERVER = $(TGT_NAME)-server
TGT_SHM_POSIX = $(TGT_NAME)-shm-posix.so
TGT_SHM_SYSV = $(TGT_NAME)-shm-sysv.so

CFLAGS += -D_GNU_SOURCE -pthread -fpic -shared -std=c11 -Wall -Wextra -O3
LDFLAGS += -pthread -O3

all: $(TGT_SERVER) $(TGT_SHM_POSIX) $(TGT_SHM_SYSV)

$(TGT_SERVER): server.o common.o
	$(CC) $(LDFLAGS) $^ -o $@

$(TGT_SHM_POSIX): shm-posix.o common.o
	$(CC) $(LDFLAGS) -Wl,--version-script=exports-shm-posix.txt -shared $^ -o $@

$(TGT_SHM_SYSV): shm-sysv.o common.o
	$(CC) $(LDFLAGS) -Wl,--version-script=exports-shm-sysv.txt -shared $^ -o $@

common.o: common.c common.h
	$(CC) $(CFLAGS) -c $< -o $@

server.o: server.c common.h
	$(CC) $(CFLAGS) -DDBG_QUIET -c $< -o $@

shm-posix.o: shm-posix.c common.h common-cli.h shm-posix.h
	$(CC) $(CFLAGS) -DDBG_QUIET -DERR_QUIET -c $< -o $@

shm-sysv.o: shm-sysv.c common.h common-cli.h shm-sysv.h
	$(CC) $(CFLAGS) -DDBG_QUIET -DERR_QUIET -c $< -o $@

install: $(TGT_SERVER) $(TGT_SHM_POSIX) $(TGT_SHM_SYSV)
	install -s -D $(TGT_SERVER) $(PREFIX)/bin/$(TGT_SERVER)
	install -s -D $(TGT_SHM_POSIX) $(PREFIX)/lib/$(TGT_SHM_POSIX)
	install -s -D $(TGT_SHM_SYSV) $(PREFIX)/lib/$(TGT_SHM_SYSV)

clean:
	rm -f \
	$(TGT_SERVER) \
	$(TGT_SHM_POSIX) \
	$(TGT_SHM_SYSV) \
	*.o

.PHONY: clean install all
