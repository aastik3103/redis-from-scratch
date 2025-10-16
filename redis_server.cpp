// stdlib
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>
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
// Project
#include "hashtable.h"
#include "common.h"
#include "zset.h"

const size_t k_max_msg = 4096;
const size_t k_max_args = 200*1000;

typedef std::vector<uint8_t> Buffer;

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

// error code for TAG_ERR
enum {
    ERR_UNKNOWN = 1,    // unknown command
    ERR_TOO_BIG = 2,    // response too big
    ERR_BAD_TYP = 3,    // unexpected value type
    ERR_BAD_ARG = 4,    // bad arguments
};

enum {
    TAG_NIL = 0,
    TAG_ERR = 1,
    TAG_STR = 2,
    TAG_INT = 3,
    TAG_DBL = 4,
    TAG_ARR = 5
};

// helper functions for serialization

static void buf_append_u8(Buffer &buf, uint8_t val){
    buf.push_back(val);
} 

static void buf_append_u32(Buffer &buf, uint32_t val){
    buf_append(buf, (uint8_t *)&val, 4);
}

static void buf_append_i64(Buffer &buf, int64_t val){
    buf_append(buf, (uint8_t *)&val, 8);
}

static void buf_append_dbl(Buffer &buf, double val){
    buf_append(buf, (uint8_t *)&val, 8);
}

// methods for appending TLV response

static void out_nil(Buffer &buf){
    buf_append_u8(buf, TAG_NIL);
}

static void out_int(Buffer &buf, int64_t val){
    buf_append_u8(buf, TAG_INT);
    buf_append_i64(buf, val);
}

static void out_dbl(Buffer &buf, double val){
    buf_append_u8(buf, TAG_DBL);
    buf_append_dbl(buf, val);
}

static void out_str(Buffer &buf, const char *s, size_t size){
    buf_append_u8(buf, TAG_STR);
    buf_append_u32(buf, size);
    buf_append(buf, (uint8_t *)s, size);
}

static void out_err(Buffer &buf, uint32_t code, std::string &msg){
    buf_append_u8(buf, TAG_ERR);
    buf_append_u32(buf, code);
    buf_append_u32(buf, msg.size());
    buf_append(buf, (uint8_t *)msg.data(), msg.size());
}

static void out_arr(Buffer &buf, int n){
    buf_append_u8(buf, TAG_ARR);
    buf_append_u32(buf, n);
}

static size_t out_begin_arr(Buffer &out) {
    out.push_back(TAG_ARR);
    buf_append_u32(out, 0);     
    return out.size() - 4;     
}
static void out_end_arr(Buffer &out, size_t ctx, uint32_t n) {
    assert(out[ctx - 1] == TAG_ARR);
    memcpy(&out[ctx], &n, 4);
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

static struct{
    HMap db; // Top level hash table
} g_data;

enum {
    T_INIT  = 0,
    T_STR   = 1,    // string
    T_ZSET  = 2,    // sorted set
};

struct Entry{
    struct HNode node;
    std::string key;

    uint32_t type = 0;

    std::string str;
    ZSet zset;
};

static Entry *entry_new(uint32_t type){
    Entry *ent = new Entry();
    ent->type = type;
    return ent;
}

static void entry_del(Entry *ent){
    if(ent->type == T_ZSET)
        zset_clear(&ent->zset);
    delete ent;
}

struct LookupKey{
    struct HNode node;
    std::string key;
};

static bool entry_eq(HNode *node, HNode *key){
    struct Entry *node_data = container_of(node, struct Entry, node);
    struct LookupKey *key_data = container_of(key, struct LookupKey, node);
    return node_data->key == key_data->key;
}

static void do_get(std::vector<std::string> &cmd, Buffer &out) {
    LookupKey key;
    key.key.swap(cmd[1]);
    key.node.h_code = str_hash((uint8_t *)key.key.data(), key.key.size());
    
    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (!node) {
        return out_nil(out);
    }
    
    Entry *ent = container_of(node, Entry, node);
    if (ent->type != T_STR) {
        std::string msg = "not a string value";
        return out_err(out, ERR_BAD_TYP, msg);
    }
    return out_str(out, ent->str.data(), ent->str.size());
}

static void do_set(std::vector<std::string> &cmd, Buffer &out) {
    LookupKey key;
    key.key.swap(cmd[1]);
    key.node.h_code = str_hash((uint8_t *)key.key.data(), key.key.size());
    
    HNode *node = hm_lookup(&g_data.db, &key.node, &entry_eq);
    if (node) {
        Entry *ent = container_of(node, Entry, node);
        if (ent->type != T_STR) {
            std::string msg = "a non-string value exists";
            return out_err(out, ERR_BAD_TYP, msg);
        }
        ent->str.swap(cmd[2]);
    } else {
        Entry *ent = entry_new(T_STR);
        ent->key.swap(key.key);
        ent->node.h_code = key.node.h_code;
        ent->str.swap(cmd[2]);
        hm_insert(&g_data.db, &ent->node);
    }
    return out_nil(out);
}

static void do_del(std::vector<std::string> &cmd, Buffer &out) {
    LookupKey key;
    key.key.swap(cmd[1]);
    key.node.h_code = str_hash((uint8_t *)key.key.data(), key.key.size());
    HNode *node = hm_delete(&g_data.db, &key.node, &entry_eq);
    if (node) { 
        entry_del(container_of(node, Entry, node));
    }
    return out_int(out, node ? 1 : 0);
}

static bool cb_keys(HNode *node, void *arg){
    Buffer &out = *(Buffer *)arg;
    std::string &key = container_of(node, Entry, node)->key;
    out_str(out, key.data(), key.size());
    return true;
}

static void do_keys(Buffer &out){
    out_arr(out, (uint32_t)hm_size(&g_data.db));
    hm_foreach(&g_data.db, &cb_keys, (void *)&out);
}

static bool str2dbl(std::string &str, double &out){
    char *endp = NULL;
    out = strtod(str.c_str(), &endp);
    return endp == str.c_str() + str.size() && !isnan(out);
}

static bool str2int(std::string &str, int64_t &out){
    char *endp = NULL;
    out = strtoll(str.c_str(), &endp, 10);
    return endp == str.c_str() + str.size();
}

// zadd key score name
static void do_zadd(std::vector<std::string> &cmd, Buffer &out){
    fprintf(stderr,"inside zadd");
    double score = 0;
    if(!str2dbl(cmd[2], score)){
        std::string msg = "expected float";
        return out_err(out, ERR_BAD_ARG, msg);
    }

    LookupKey key;
    key.key.swap(cmd[1]);
    key.node.h_code = str_hash((uint8_t *)key.key.data(), key.key.size());
    HNode *hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);
    
    Entry *ent = NULL;
    if(!hnode){
        ent = entry_new(T_ZSET);
        ent->key.swap(key.key);
        ent->node.h_code = key.node.h_code;
        hm_insert(&g_data.db, &ent->node);
    }
    else{
        ent = container_of(hnode, struct Entry, node);
        if(ent->type != T_ZSET){
            std::string msg = "expected zset";
            return out_err(out, ERR_BAD_TYP, msg);
        }
    }

    const std::string &name = cmd[3];
    fprintf(stderr, "output start");
    bool added = zset_insert(&ent->zset, name.data(), name.size(), score);
    fprintf(stderr, "output done");
    return out_int(out, (int64_t)added);
}

static const ZSet k_empty_zset;

static ZSet *expect_zset(std::string &s){
    LookupKey key;
    key.key.swap(s);
    key.node.h_code = str_hash((uint8_t *)key.key.data(), key.key.size());
    HNode *hnode = hm_lookup(&g_data.db, &key.node, &entry_eq);

    if(!hnode)
        return (ZSet *)&k_empty_zset;

    Entry *ent = container_of(hnode, Entry, node);
    return ent->type == T_ZSET ? &ent->zset : NULL;
}

// zrem key name
static void do_zrem(std::vector<std::string> &cmd, Buffer &out){
    ZSet *zset = expect_zset(cmd[1]);
    if(!zset){
        std::string msg = "expected zset";
        return out_err(out, ERR_BAD_TYP, msg);
    }

    std::string &name = cmd[2];
    ZNode *znode = zset_lookup(zset, name.data(), name.size());
    if(znode){
        zset_delete(zset, znode);
    }

    return out_int(out, znode ? 1 : 0);
}

// zscore key name
static void do_zscore(std::vector<std::string> &cmd, Buffer &out){
    ZSet *zset = expect_zset(cmd[1]);
    if(!zset){
        std::string msg = "expected zset";
        return out_err(out, ERR_BAD_TYP, msg);
    }

    std::string &name = cmd[2];
    ZNode *znode = zset_lookup(zset, name.data(), name.size());
    return znode ? out_dbl(out, znode->score) : out_nil(out);
}

// zquery key score name offset limit
static void do_zquery(std::vector<std::string> &cmd, Buffer &out){
    double score = 0;
    if(!str2dbl(cmd[2], score)){
        std::string msg = "expected float";
        return out_err(out, ERR_BAD_ARG, msg);
    }
    
    int64_t offset = 0, limit = 0;
    if(!str2int(cmd[4], offset) || !str2int(cmd[5], limit)){
        std::string msg = "expected int";
        return out_err(out, ERR_BAD_ARG, msg);
    }

    ZSet *zset = expect_zset(cmd[1]);
    if(!zset){
        std::string msg = "expected zset";
        return out_err(out, ERR_BAD_TYP, msg);
    }

    std::string &name = cmd[3];

    if(limit <= 0)
        return out_arr(out, 0);
    
    fprintf(stderr, "before zseek");
    ZNode *znode = zset_seekge(zset, score, name.data(), name.size());
    fprintf(stderr, "after zseek");
    fprintf(stderr, "before znode_offset");
    znode = znode_offset(znode, offset);
    fprintf(stderr, "after znode_offset");

    size_t ctx = out_begin_arr(out);
    int64_t n = 0;
    while(znode && n < limit){
        out_str(out, znode->name, znode->len);
        out_dbl(out, znode->score);
        znode = znode_offset(znode, 1);
        n += 2;
    }

    out_end_arr(out, ctx, (uint32_t)n);
}

static void do_request(std::vector<std::string> &cmd, Buffer &out){
    if(cmd.size()==2 && cmd[0]=="get"){
        return do_get(cmd, out);
    }
    else if(cmd.size()==3 && cmd[0]=="set"){
        return do_set(cmd, out);
    }
    else if(cmd.size()==2 && cmd[0]=="del"){
        return do_del(cmd, out);
    }
    else if(cmd.size()==1 && cmd[0]=="keys"){
        return do_keys(out);
    }
    else if (cmd.size() == 4 && cmd[0] == "zadd") {
        return do_zadd(cmd, out);
    } 
    else if (cmd.size() == 3 && cmd[0] == "zrem") {
        return do_zrem(cmd, out);
    } 
    else if (cmd.size() == 3 && cmd[0] == "zscore") {
        return do_zscore(cmd, out);
    } 
    else if (cmd.size() == 6 && cmd[0] == "zquery") {
        return do_zquery(cmd, out);
    }
    else{
        std::string msg = "unknown command";
        return out_err(out, ERR_UNKNOWN, msg);
    }
}

static void response_begin(Buffer &out, size_t *header){
    *header = out.size();
    buf_append_u32(out, 0);
}

static size_t response_size(Buffer &out, size_t header){
    return out.size() - header - 4;
}

static void response_end(Buffer &out, size_t header){
    size_t msg_size = response_size(out, header);
    if(msg_size>k_max_msg){
        out.resize(header+4);
        std::string msg = "response too big";
        out_err(out, ERR_TOO_BIG, msg);
        msg_size = response_size(out, header);
    }

    uint32_t len = (uint32_t)msg_size;
    memcpy(&out[header], &len, 4);
}

// static void make_response(Response &resp, std::vector<uint8_t> &out){
//     uint32_t resp_len = 4 + resp.data.size();
//     buf_append(out, (uint8_t *)&resp_len, 4);
//     buf_append(out, (uint8_t *)&resp.status, 4);
//     buf_append(out, resp.data.data(), resp.data.size());
// }

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

    size_t header_pos = 0;
    response_begin(conn->outgoing, &header_pos);
    do_request(cmd, conn->outgoing);
    response_end(conn->outgoing, header_pos);

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