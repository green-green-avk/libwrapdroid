#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"

ssize_t recvFds(const int sockfd,
                void *const data, const size_t len,
                int *const fds, size_t *const fdsc) {
    char cmsg_buf[getpagesize()] __attribute__((aligned(_Alignof(struct cmsghdr))));
    struct iovec iov = {.iov_base = (void *) data, .iov_len = len};
    struct msghdr msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = cmsg_buf,
            .msg_controllen = sizeof(cmsg_buf),
            .msg_flags = 0
    };
    const ssize_t r = TEMP_FAILURE_RETRY(recvmsg(sockfd, &msg, MSG_NOSIGNAL));
    if (r < 0) {
        if (errno == EPIPE)
            return 0;
        return r;
    }
    if (msg.msg_flags & (MSG_CTRUNC | MSG_OOB | MSG_ERRQUEUE))
        return -1;
    size_t cmsg_fdsc = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
            continue;
        const size_t n = ((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
        const int *const cmsg_fds = (int *) CMSG_DATA(cmsg);
        for (size_t i = 0; i < n; i++) {
            if (cmsg_fdsc + i >= *fdsc)
                return -1;
            fds[cmsg_fdsc + i] = cmsg_fds[i];
        }
        cmsg_fdsc += n;
    }
    *fdsc = cmsg_fdsc;
    return r;
}

ssize_t sendFds(const int sockfd,
                const void *const data, const size_t len,
                const int *const fds, const size_t fdsc) {
    const size_t cmsg_space = CMSG_SPACE(sizeof(int) * fdsc);
    const size_t cmsg_len = CMSG_LEN(sizeof(int) * fdsc);
    if (cmsg_space >= (size_t) getpagesize()) {
        errno = ENOMEM;
        return -1;
    }
    char cmsg_buf[cmsg_space] __attribute__((aligned(_Alignof(struct cmsghdr))));
    struct iovec iov = {.iov_base = (void *) data, .iov_len = len};
    const struct msghdr msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = cmsg_buf,
            .msg_controllen = sizeof(cmsg_buf),
            .msg_flags = 0
    };
    struct cmsghdr *const cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = cmsg_len;
    int *const cmsg_fds = (int *) CMSG_DATA(cmsg);
    for (size_t i = 0; i < fdsc; ++i) {
        cmsg_fds[i] = fds[i];
    }
    return TEMP_FAILURE_RETRY(sendmsg(sockfd, &msg, MSG_NOSIGNAL));
}

int readAll(const int sock, void *const buf, const size_t len) {
    if (len == 0) return 0;
    size_t offset = 0;
    while (1) {
        const ssize_t r = read(sock, (char *) buf + offset, len - offset);
        if (r <= 0) {
            return -1;
        }
        offset += r;
        if (offset >= len) return 0;
    }
}

int writeAll(const int sock, const void *const buf, const size_t len) {
    if (len == 0) return 0;
    size_t offset = 0;
    while (1) {
        const ssize_t r = write(sock, (char *) buf + offset, len - offset);
        if (r <= 0) {
            return -1;
        }
        offset += r;
        if (offset >= len) return 0;
    }
}
