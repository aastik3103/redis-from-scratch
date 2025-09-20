// stdlib
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
// system
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
// C++
#include <vector>
#include <map>
#include <string>

const size_t k_max_msg = 4096;
const size_t k_max_args = 200*1000;

static std::map<std::string,std::string> g_data;

struct Conn{
    int fd = -1;

    bool want_read = false;
    bool want_write = false;
    bool want_close = false;

    std::vector<uint8_t> incoming;
    std::vector<uint8_t> outgoing;
};

static void die(const char *msg){
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

static void msg(const char *msg){
    fprintf(stderr, "%s\n", msg);
}

static void msg_errno(const char *msg) {
    fprintf(stderr, "[errno:%d] %s\n", errno, msg);
}

static void buf_append(std::vector<uint8_t> &buf, uint8_t *data, size_t len){
    buf.insert(buf.end(), data, data+len);
}

static void buf_consume(std::vector<uint8_t> &buf, size_t len){
    buf.erase(buf.begin(), buf.begin()+len);
}

void fd_set_nb(int fd){
    errno = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if(errno)
        die("fcntl() error");

    flags |= O_NONBLOCK;

    errno = 0;
    fcntl(fd, F_SETFL, flags);
    if(errno)
        die("fcntl() error");
}

Conn* handle_accept(int fd){
    struct sockaddr_in client_addr = {};
    socklen_t len = sizeof(client_addr);
    int connfd = accept(fd, (struct sockaddr *)&client_addr, &len);

    if(connfd<0){
        msg_errno("accept() error");
        return NULL;
    }

    uint32_t ip = client_addr.sin_addr.s_addr;
    fprintf(stderr, "New client from: %u.%u.%u.%u:%u\n", 
    ip & 255, (ip>>8) & 255, (ip>>16) & 255, ip>>24, htons(client_addr.sin_port));

    fd_set_nb(connfd);

    Conn *conn = new Conn();
    conn->fd = connfd;
    conn->want_read = true;
    return conn;
}

static void handle_write(Conn *conn){
    assert(conn->outgoing.size()>0);

    int rv = write(conn->fd, conn->outgoing.data(), conn->outgoing.size());

    if(rv<0 and (errno == EAGAIN || errno == EWOULDBLOCK)){
        return;
    }

    if(rv<0){
        msg_errno("write() error");
        conn->want_close = true;
        return;
    }

    buf_consume(conn->outgoing, (size_t)rv);

    if(conn->outgoing.size()==0){
        conn->want_read = true;
        conn->want_write = false;
    }
}

static bool read_u32(uint8_t *&curr, uint8_t *end, uint32_t &out){
    if(curr+4 > end)
        return false;

    memcpy(&out, curr, 4);
    curr += 4;
    return true;
}   

static bool read_str(uint8_t *&curr, uint8_t *end, size_t n, std::string &out){
    if(curr+n > end)
        return false;

    out.assign(curr, curr+n);
    curr += n;
    return true;
}

static int32_t parse_request(uint8_t *data, size_t n, std::vector<std::string> &out){
    uint8_t *end = data + n;

    uint32_t nstr = 0;
    if(!read_u32(data, end, nstr))
        return -1;

    if(nstr>k_max_args){
        return -1;
    }

    while(out.size()<nstr){
        uint32_t len = 0;
        if(!read_u32(data, end, len))
            return -1;

        out.push_back(std::string());

        if(!read_str(data, end, len, out.back())){
            return -1;
        }
    }

    if(data!=end) 
        return -1; // trailing garbage

    return 0;
}

enum {
    RES_OK = 0,
    RES_ERR = 1,
    RES_NX = 2,
};

struct Response{
    uint32_t status = 0;
    std::vector<uint8_t> data;
};

static void do_request(std::vector<std::string> &cmd, Response &out){
    if(cmd.size()==2 && cmd[0]=="get"){
        auto it = g_data.find(cmd[1]);
        if(it == g_data.end()){
            out.status = RES_NX;
            return;
        }

        std::string &val = it->second;
        out.data.assign(val.begin(), val.end());
    }
    else if(cmd.size()==3 && cmd[0]=="set"){
        g_data[cmd[1]].swap(cmd[2]);
    }
    else if(cmd.size()==2 && cmd[0]=="del"){
        g_data.erase(cmd[1]);
    }
    else
        out.status = RES_ERR; //unrecognised command
}

static void make_response(Response &resp, std::vector<uint8_t> &out){
    uint32_t resp_len = 4 + resp.data.size();
    buf_append(out, (uint8_t *)&resp_len, 4);
    buf_append(out, (uint8_t *)&resp.status, 4);
    buf_append(out, resp.data.data(), resp.data.size());
}

static bool try_one_request(Conn * conn){
    if(conn->incoming.size()<4){
        return false;
    }

    uint32_t len = 0;
    memcpy(&len, conn->incoming.data(), 4);

    if(len>k_max_msg){
        msg("client request too long");
        conn->want_close = true;
        return false;
    }

    if(4+len>conn->incoming.size())
        return false;

    uint8_t *request = &conn->incoming[4];
    // printf("client says: len:%d data:%.*s\n",
    //         len, len<100 ? len : 100, request);

    std::vector<std::string> cmd;
    if(parse_request(request, len, cmd)<0){
        msg("bad request");
        conn->want_close = true;
        return false;
    }

    Response resp;
    do_request(cmd, resp);
    make_response(resp, conn->outgoing);

    buf_consume(conn->incoming, 4+len);

    return true;
}

static void handle_read(Conn *conn){
    uint8_t rbuf[64*1024];
    ssize_t rv = read(conn->fd, rbuf, sizeof(rbuf));

    if(rv<0 and (errno == EAGAIN || errno == EWOULDBLOCK))
        return; // not ready to read

    // handling IO error
    if(rv<0){
        msg_errno("read() error");
        conn->want_close = true;
        return;
    }

    // handling EOF
    if(rv==0){
        if(conn->incoming.size()>0){
            msg("unexpected EOF");
        }
        else{
            msg("client closed");
        }

        conn->want_close = true;
        return;
    }

    buf_append(conn->incoming, rbuf, (size_t)rv);

    while(try_one_request(conn)){};

    if(conn->outgoing.size()>0){
        conn->want_read = false;
        conn->want_write = true;

        // The socket is likely ready to write in a request-response protocol
        // trying to write it without waiting for the next iteration.
        handle_write(conn);
    }
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

    fd_set_nb(fd); // Making the socket non blocking while accepting connections.

    rv = listen(fd, SOMAXCONN);

    if(rv){
        die("listen()");
    }

    printf("Server is running on port: %d\n", htons(addr.sin_port));

    // fd to connection mapping
    std::vector<Conn*> fd2conn;

    // Contains readiness request and response
    std::vector<struct pollfd> poll_args;

    while(true){
        poll_args.clear();

        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);

        for(Conn *conn:fd2conn){
            if(!conn){
                continue;
            }

            struct pollfd pfd = {conn->fd, POLLERR, 0};

            if(conn->want_read)
                pfd.events |= POLLIN;
            
            if(conn->want_write)
                pfd.events |= POLLOUT;
            
            poll_args.push_back(pfd);
        }

        int rv = poll(poll_args.data(), (nfds_t)poll_args.size(), -1);

        if(rv<0 and errno==EINTR)
            continue; // not an error

        if(rv<0)
            die("poll()");
        
        // handling the listening socket
        if(poll_args[0].revents){
            if(Conn *conn = handle_accept(poll_args[0].fd)){
                if((size_t)conn->fd>=fd2conn.size()){
                    fd2conn.resize(conn->fd+1);
                }

                assert(fd2conn[conn->fd]==NULL);

                fd2conn[conn->fd] = conn;
            }
        }

        //  handling connection sockets
        for(size_t i=1;i<poll_args.size();i++){
            struct pollfd pfd = poll_args[i];
            int connfd = pfd.fd;
            Conn *conn = fd2conn[connfd];

            if(pfd.revents&POLLIN){
                assert(conn->want_read);
                handle_read(conn);
            }

            if(pfd.revents&POLLOUT){
                assert(conn->want_write);
                handle_write(conn);
            }

            if((pfd.revents&POLLERR) or conn->want_close){
                close(conn->fd);
                fd2conn[conn->fd] = NULL;
                delete conn;
            }
        }

    } // event loop ends
    
    return 0;
}