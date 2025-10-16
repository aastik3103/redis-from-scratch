#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "zset.h"
#include "common.h"

static ZNode *znode_new(const char *name, size_t len, double score){
    ZNode *node = (ZNode *)malloc(sizeof(ZNode) + len);
    assert(node);
    avl_init(&node->tree_node);
    node->hnode.next = NULL;
    node->hnode.h_code =  str_hash((uint8_t *)name, len);
    node->score = score;
    node->len = len;
    memcpy(&node->name[0], name, len);
    return node;
}

static void znode_del(ZNode *node){
    free(node);
}

static size_t min(size_t lhs, size_t rhs){
    return lhs<rhs ? lhs : rhs;
}

static bool zless(AVLNode *lhs, double score, const char *name, size_t len){
    ZNode *l_node = container_of(lhs, ZNode, tree_node);
    if(l_node->score != score){
        return l_node->score < score;
    }

    int rv = memcmp(l_node->name, name, min(l_node->len, len));

    if(rv!=0)
        return rv < 0;
    
    return l_node->len < len;
}

static bool zless(AVLNode *lhs, AVLNode *rhs){
    ZNode *r_node = container_of(rhs, ZNode, tree_node);
    return zless(lhs, r_node->score, r_node->name, r_node->len);
}

static void tree_insert(ZSet *zset, ZNode *node){
    AVLNode *parent = NULL;
    AVLNode **from = &zset->root;

    while(*from){
        fprintf(stderr, "hello tree insert");
        parent = *from;
        from = zless(&node->tree_node, parent) ? &parent->left : &parent->right;
    }

    *from = &node->tree_node;
    node->tree_node.parent = parent;
    zset->root = avl_fix(&node->tree_node);
}

// update the score of an existing node
static void zset_update(ZSet *zset, ZNode *node, double score){
    if(node->score == score)
        return;
    
    zset->root = avl_del(&node->tree_node);
    avl_init(&node->tree_node);
    node->score = score;
    tree_insert(zset, node);
}

// add a new (score, name) tuple, or update the score of the existing tuple
bool zset_insert(ZSet *zset, const char *name, size_t len, double score){
    fprintf(stderr, "Before lookup");
    ZNode *node = zset_lookup(zset, name, len);
    fprintf(stderr, "After lookup");
    if(node){
        zset_update(zset, node, score);
        return false;
    }
    else{
        fprintf(stderr, "Before znew");
        node = znode_new(name, len, score);
        fprintf(stderr, "After znew");
        hm_insert(&zset->hmap, &node->hnode);
        fprintf(stderr, "Before tree insert");
        tree_insert(zset, node);
        return true;
    }
}

struct HKey{
    HNode node;
    const char *name = NULL;
    size_t len = 0;
};

static bool hcmp(HNode *key, HNode *node){
    ZNode *znode = container_of(node, ZNode, hnode);
    HKey *hkey = container_of(key, HKey, node);
    if(hkey->len != znode->len)
        return false;
    
    return 0 == memcmp(hkey->name, znode->name, znode->len);
}

// lookup by name
ZNode *zset_lookup(ZSet *zset, const char *name, size_t len){
    if(!zset->root)
        return NULL;

    HKey key;
    key.node.h_code = str_hash((uint8_t *)name, len);
    key.name = name;
    key.len = len;
    fprintf(stderr, "Before hm_lookup");
    HNode *found = hm_lookup(&zset->hmap, &key.node, &hcmp);
    fprintf(stderr, "After hm_lookup");
    return found ? container_of(found, ZNode, hnode) : NULL;
}

void zset_delete(ZSet *zset, ZNode *node){
    HKey key;
    key.node.h_code = node->hnode.h_code;
    key.name = node->name;
    key.len = node->len;
    HNode *found = hm_delete(&zset->hmap, &key.node, &hcmp);
    assert(found);

    zset->root = avl_del(&node->tree_node);
    znode_del(node);
}

// find the first (score, name) tuple that is >= key.
ZNode *zset_seekge(ZSet *zset, double score, const char *name, size_t len){
    AVLNode *found = NULL;
    for(AVLNode *node=zset->root; node; ){
        if(zless(node, score, name, len))
            node = node->right;
        else{
            found = node;
            node = node->left;
        }
    }

    return found ? container_of(found, ZNode, tree_node) : NULL;
}

// offset into the succeeding or preceding node.
ZNode *znode_offset(ZNode *node, int64_t offset){
    AVLNode *t_node = node ? avl_offset(&node->tree_node, offset) : NULL;
    return t_node ? container_of(t_node, ZNode, tree_node) : NULL;
}

static void tree_dispose(AVLNode *node) {
    if (!node) {
        return;
    }
    tree_dispose(node->left);
    tree_dispose(node->right);
    znode_del(container_of(node, ZNode, tree_node));
}

void zset_clear(ZSet *zset){
    hm_clear(&zset->hmap);
    tree_dispose(zset->root);
    zset->root = NULL;
}







