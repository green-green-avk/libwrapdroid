#include "common-cli.h"

int shm_open(const char *const name, const int oflag, const mode_t mode) {
	const int sock = connectToServer();
	if (sock == -1) return -1;
	Write(Command, C_SHM_OPEN);
	Write(String, name);
	Write(U32, oflag);
	Write(U32, mode);
	int fd;
	size_t fdsc = 1;
	int retCode;
	if (recvFds(sock, &retCode, sizeof(retCode), &fd, &fdsc) != sizeof(retCode)) {
		close(sock);
		errno = EACCES;
		return -1;
	}
	if (retCode == 0) {
		if (fdsc != 1) {
			close(sock);
			errno = EACCES;
			return -1;
		}
		close(sock);
		return fd;
	}
	processError(sock);
	return retCode;
}

int shm_unlink(const char *const name) {
	const int sock = connectToServer();
	if (sock == -1) return -1;
	Write(Command, C_SHM_UNLINK);
	Write(String, name);
	int retCode;
	if (readAll(sock, &retCode, sizeof(retCode)) != 0) {
		close(sock);
		errno = EACCES;
		return -1;
	}
	if (retCode == 0) {
		close(sock);
		return 0;
	}
	processError(sock);
	return retCode;
}
