#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <assert.h>

static void die(const char *msg){
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

static void msg(const char *msg){
    fprintf(stderr, "%s\n", msg);
}

static int32_t read_full(int fd, char *buf, size_t n){
    while(n>0){
        ssize_t rv = read(fd, buf, n);
        if(rv<=0){
            return -1;
        }
        assert((size_t)rv<=n);

        n -= rv;
        buf += rv;
    }

    return 0;
}

static int32_t write_all(int fd, char *buf, size_t n){
    while(n>0){
        ssize_t rv = write(fd, buf, n);
        if(rv<=0){
            return -1;
        }
        assert((size_t)rv<=n);

        n -= rv;
        buf += rv;
    }

    return 0;
}

const size_t k_max_msg = 4096;

static int32_t one_request(int connfd){
    char rbuf[4+k_max_msg];

    errno = 0;
    int32_t err = read_full(connfd, rbuf, 4);

    if(err){
        msg(errno==0 ? "EOF":"read() error");
        return err;
    }

    uint32_t len = 0;
    memcpy(&len, rbuf, 4);

    if(len>k_max_msg){
        msg("too long");
        return -1;
    }

    err = read_full(connfd, &rbuf[4], len);

    if(err){
        msg("read() error");
        return err;
    }

    printf("Client says: %.*s\n", len, &rbuf[4]);

    char reply[] = "world";
    len = (uint32_t)strlen(reply);
    char wbuf[4+len];
    memcpy(wbuf, &len, 4);
    memcpy(&wbuf[4], reply, len);

    return write_all(connfd, wbuf, 4+len);
}

int main(){

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if(fd<0){
        die("socket()");
    }

    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(0);

    int rv = bind(fd, (const struct sockaddr *)&addr, sizeof(addr));

    if(rv){
        die("bind()");
    }

    rv = listen(fd, SOMAXCONN);

    if(rv){
        die("listen()");
    }

    while(true){
        struct sockaddr_in client_addr = {};
        socklen_t sz = sizeof(client_addr);
        int connfd = accept(fd, (struct sockaddr *)&client_addr, &sz);

        if(connfd<0)
            continue;
        
        while(true){
            int32_t err = one_request(connfd);
            if(err)
                break;
        }
        close(connfd);
    }
    
    return 0;
}