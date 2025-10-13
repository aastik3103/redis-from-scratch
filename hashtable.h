#pragma once

#include<stddef.h>
#include<stdint.h>

struct HNode{
    HNode *next = NULL;
    uint64_t h_code;
};

struct HTab{
    HNode **tab = NULL;
    size_t mask = 0;
    size_t size = 0;
};

struct HMap{
    HTab older;
    HTab newer;
    size_t migrate_pos = 0;
};

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *));
void hm_insert(HMap *hmap, HNode *node);
HNode * hm_delete(HMap * hmap, HNode * key, bool(*eq)(HNode *,HNode *));
void hm_clear(HMap *hmap);
size_t hm_size(HMap *hmap);
void hm_foreach(HMap *hmap, bool (*f)(HNode *, void *), void *arg);

