#include <assert.h>
#include <stdlib.h>     // calloc(), free()
#include "hashtable.h"

const size_t k_rehashing_work = 128;
const size_t k_max_load_factor = 8;

static void h_init(HTab *htab, size_t n){
    assert(n>0 && (n&(n-1))==0);
    htab->tab = (HNode **)calloc(n, sizeof(HNode *));
    htab->mask = n-1;
    htab->size = 0;
}

static void h_insert(HTab *htab, HNode *node){
    size_t pos = node->h_code & (htab->mask);
    HNode *next = htab->tab[pos];
    node->next = next;
    htab->tab[pos] = node;
    htab->size++;
}

static HNode **h_lookup(HTab *htab, HNode *key, bool (*eq)(HNode *, HNode *)){
    if(!htab->tab)
        return NULL;
    
    size_t pos = key->h_code & htab->mask;
    HNode **from = &htab->tab[pos];

    for(HNode *cur=*from; cur!=NULL; from=&cur->next){
        if(key->h_code==cur->h_code && eq(key, cur))
            return from;
    }

    return NULL;
}

static HNode *h_detach(HTab *htab, HNode **from){
    HNode *node = *from;
    *from = node->next;
    htab->size--;
    return node;
}

static void hm_help_rehashing(HMap *hmap){
    size_t nwork = 0;
    while(nwork<k_rehashing_work && hmap->older.size>0){
        HNode **from = &hmap->older.tab[hmap->migrate_pos];
        if(!*from){
            hmap->migrate_pos++;
            continue;
        }
        h_insert(&hmap->newer, h_detach(&hmap->older, from));
        nwork++;
    }

    if(hmap->older.size==0 && hmap->older.tab){
        free(hmap->older.tab);
        hmap->older = HTab{};
    }
}

static void hm_trigger_rehashing(HMap *hmap){
    assert(!hmap->older.tab);
    hmap->older = hmap->newer;
    h_init(&hmap->newer, (hmap->newer.mask+1)*2);
    hmap->migrate_pos = 0;
}

HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)){
    hm_help_rehashing(hmap);
    HNode **from = h_lookup(&hmap->newer, key, eq);
    if(!from){
        from = h_lookup(&hmap->older, key, eq);
    }
    return from ? *from : NULL;
}

void hm_insert(HMap *hmap, HNode *node){
    if(!hmap->newer.tab)
        h_init(&hmap->newer, 4);

    h_insert(&hmap->newer, node);

    if(!hmap->older.tab){
        size_t threshold = (hmap->newer.mask+1)*k_max_load_factor;
        if(hmap->newer.size>=threshold)
            hm_trigger_rehashing(hmap);
    }

    hm_help_rehashing(hmap);
}

HNode *hm_delete(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)){
    hm_help_rehashing(hmap);
    if(HNode **from = h_lookup(&hmap->newer, key, eq))
        return h_detach(&hmap->newer, from);
    if(HNode **from = h_lookup(&hmap->older, key, eq))
        return h_detach(&hmap->older, from);
    
    return NULL;
}

void hm_clear(HMap *hmap){
    free(hmap->newer.tab);
    free(hmap->older.tab);
    *hmap = HMap{};
}

size_t hm_size(HMap *hmap){
    return (hmap->newer.size + hmap->older.size);
}