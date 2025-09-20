#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string>
#include <vector>



static void msg(const char *msg) {
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

static int32_t read_full(int fd, uint8_t *buf, size_t n) {
    while (n > 0) {
        ssize_t rv = read(fd, buf, n);
        if (rv <= 0) {
            return -1;  // error, or unexpected EOF
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

static int32_t write_all(int fd, const uint8_t *buf, size_t n) {
    while (n > 0) {
        ssize_t rv = write(fd, buf, n);
        if (rv <= 0) {
            return -1;  // error
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

// append to the back
static void
buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

const size_t k_max_msg = 4096;  // likely larger than the kernel buffer

static int32_t send_req(int fd, std::vector<std::string> &cmd) {
    uint32_t len = 4;

    for(std::string &s : cmd){
        len += s.size() + 4;
    }

    if (len > k_max_msg) {
        return -1;
    }

    uint8_t wbuf[len + 4];
    memcpy(&wbuf[0], &len, 4);

    uint32_t nstr = cmd.size();
    memcpy(&wbuf[4], &nstr, 4);

    size_t curr = 8;

    for(std::string &s:cmd){
        uint32_t c_len = s.size();
        memcpy(&wbuf[curr], &c_len, 4);
        memcpy(&wbuf[curr+4], s.data(), s.size());
        curr += (s.size()+4);
    }
    return write_all(fd, wbuf, len+4);
}

static int32_t read_res(int fd) {
    uint8_t rbuf[4+k_max_msg];
    errno = 0;
    int32_t err = read_full(fd, rbuf, 4);
    if (err) {
        if (errno == 0) {
            msg("EOF");
        } else {
            msg("read() error");
        }
        return err;
    }

    uint32_t len = 0;
    memcpy(&len, rbuf, 4);  // assume little endian
    if (len > k_max_msg) {
        msg("too long");
        return -1;
    }

    // reply body
    err = read_full(fd, &rbuf[4], len);
    if (err) {
        msg("read() error");
        return err;
    }

    // do something
    uint32_t res_code = 0;
    if(len<4){
        msg("bad response");
        return -1;
    }

    memcpy(&res_code, &rbuf[4], 4);
    fprintf(stderr, "Server says: [%u] %.*s\n", res_code, len-4, &rbuf[8]);

    return 0;
}

int main(int argc, char **argv) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        die("socket()");
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK);  // 127.0.0.1
    int rv = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rv) {
        die("connect");
    }

    std::vector<std::string> cmd;
    for(int i=1;i<argc;i++){
        cmd.push_back(argv[i]);
    }

    int32_t err = send_req(fd, cmd);
    if(err)
        goto L_DONE;

    err = read_res(fd);
    if(err)
        goto L_DONE;
    
L_DONE:
    close(fd);
    return 0;
}