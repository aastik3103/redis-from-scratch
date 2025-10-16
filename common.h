#pragma once

#include <stdint.h>
#include <stddef.h>

// Intrusive Data Structure
#define container_of(ptr, T, member) \
    ((T *)((char *)ptr - offsetof(T, member)))

// #define container_of(ptr, type, member) ({                  \
//     const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
//     (type *)( (char *)__mptr - offsetof(type, member) );})

// FNV Hash
static uint64_t str_hash(uint8_t *data, size_t len){
    uint32_t h = 0x811C9DC5;
    for(int i=0;i<len;i++){
        h = (h+data[i])*0x01000193;
    }
    return h;
}