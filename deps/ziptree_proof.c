/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2021-2023 (c) Julius Pfrommer
 */

/* This file contains a simplified version of ziptree.c/.h for a specific target
 * structure to store in the tree. This is done to make it self-contained and to
 * reduce the macro-magic and integer-pointer-conversions for the analysis. */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#define ZIP_HEAD(name, type)                    \
struct name {                                   \
    struct type *root;                          \
}

#define ZIP_ENTRY(type)                         \
struct {                                        \
    struct type *left;                          \
    struct type *right;                         \
}

enum ZIP_CMP {
    ZIP_CMP_LESS = -1,
    ZIP_CMP_EQ = 0,
    ZIP_CMP_MORE = 1
};

/* Dummy types */
struct elem {
    unsigned int key;
    ZIP_ENTRY(elem) fields;
};

ZIP_HEAD(tree, elem);

typedef struct elem elem;
typedef struct tree tree;

/* Hash pointers to keep the tie-breeaking of equal keys (mostly) uncorrelated
 * from the rank (pointer order). Hashing code taken from sdbm-hash
 * (http://www.cse.yorku.ca/~oz/hash.html). */
static unsigned int
ZIP_PTR_HASH(const elem *p) {
    unsigned int h = 0;
    const unsigned char *data = (const unsigned char*)&p;
    for(size_t i = 0; i < (sizeof(void*) / sizeof(char)); i++)
        h = data[i] + (h << 6) + (h << 16) - h;
    return h;
}

static enum ZIP_CMP
ZIP_RANK_CMP(const elem *p1, const elem *p2) {
    assert(p1 != p2);
    unsigned int h1 = ZIP_PTR_HASH(p1);
    unsigned int h2 = ZIP_PTR_HASH(p2);
    if(h1 == h2)
        return ((uintptr_t)p1 < (uintptr_t)p2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
    return (h1 < h2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
}

static enum ZIP_CMP
ZIP_CMP(unsigned int k1, unsigned int k2) {
    if(k1 == k2)
        return ZIP_CMP_EQ;
    return (k1 < k2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
}

static enum ZIP_CMP
ZIP_UNIQUE_CMP(const unsigned int *k1, const unsigned int *k2) {
    if(k1 == k2)
        return ZIP_CMP_EQ;
    if(*k1 == *k2)
        return ((uintptr_t)k1 < (uintptr_t)k2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
    return (*k1 < *k2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
}

static elem *
ZIP_ZIP(elem *l, elem *r) {
    if(!l)
        return r;
    if(!r)
        return l;
    elem *root = NULL;
    elem **prev_edge = &root;
    while(l && r) {
        if(ZIP_RANK_CMP(l, r) == ZIP_CMP_LESS) {
            *prev_edge = r;
            prev_edge = &r->fields.left;
            r = r->fields.left;
        } else {
            *prev_edge = l;
            prev_edge = &l->fields.right;
            l = l->fields.right;
        }
    }
    *prev_edge = (l) ? l : r;
    return root;
}

void
ZIP_UNZIP(tree *head, unsigned int key, tree *left, tree *right) {
    if(!head->root) {
        left->root = NULL;
        right->root = NULL;
        return;
    }

    elem *prev;
    elem *cur = head->root;
    enum ZIP_CMP head_order = ZIP_CMP(key, cur->key);
    if(head_order != ZIP_CMP_LESS) {
        left->root = cur;
        do {
            prev = cur;
            cur = cur->fields.right;
            if(!cur) {
                right->root = NULL;
                return;
            }
        } while(ZIP_CMP(key, cur->key) != ZIP_CMP_LESS);
        right->root = cur;
        prev->fields.right = NULL;
        elem *left_rightmost = prev;
        while(cur->fields.left) {
            prev = cur;
            cur = cur->fields.left;
            if(ZIP_CMP(key, cur->key) != ZIP_CMP_LESS) {
                prev->fields.left = cur->fields.right;
                cur->fields.right = NULL;
                left_rightmost->fields.right = cur;
                left_rightmost = cur;
                cur = prev;
            }
        }
    } else {
        right->root = cur;
        do {
            prev = cur;
            cur = cur->fields.left;
            if(!cur) {
                left->root = NULL;
                return;
            }
        } while(ZIP_CMP(key, cur->key) == ZIP_CMP_LESS);
        left->root = cur;
        prev->fields.left = NULL;
        elem *right_leftmost = prev;
        while(cur->fields.right) {
            prev = cur;
            cur = cur->fields.right;
            if(ZIP_CMP(key, cur->key) == ZIP_CMP_LESS) {
                prev->fields.right = cur->fields.left;
                cur->fields.left = NULL;
                right_leftmost->fields.left = cur;
                right_leftmost = cur;
                cur = prev;
            }
        }
    }
}

static void
ZIP_INSERT(tree *head, elem *x) {
    x->fields.left = NULL;
    x->fields.right = NULL;

    const unsigned int x_key = x->key;
    if(!head->root) {
        head->root = x;
        return;
    }

    elem *prev = NULL;
    elem *cur = head->root;
    enum ZIP_CMP cur_order, prev_order;
    do {
        if(x == cur)
            return;
        cur_order = ZIP_CMP(x_key, cur->key);
        if(ZIP_RANK_CMP(x, cur) == ZIP_CMP_MORE)
            break;
        prev = cur;
        prev_order = cur_order;
        cur = (cur_order == ZIP_CMP_MORE) ? cur->fields.right : cur->fields.left;
    } while(cur);

    if(cur == head->root) {
        head->root = x;
    } else {
        if(prev_order == ZIP_CMP_MORE)
            prev->fields.right = x;
        else
            prev->fields.left = x;
    }

    if(!cur)
        return;

    if(cur_order != ZIP_CMP_LESS) {
        x->fields.left = cur;
    } else {
        x->fields.right = cur;
    }

    prev = x;
    do {
        elem *fix = prev;
        if(cur_order == ZIP_CMP_MORE) {
            do {
                prev = cur;
                cur = cur->fields.right;
                if(!cur)
                    break;
                cur_order = ZIP_UNIQUE_CMP(&x_key, &cur->key);
            } while(cur_order == ZIP_CMP_MORE);
        } else {
            do {
                prev = cur;
                cur = cur->fields.left;
                if(!cur)
                    break;
                cur_order = ZIP_UNIQUE_CMP(&x_key, &cur->key);
            } while(cur_order == ZIP_CMP_LESS);
        }

        if(ZIP_UNIQUE_CMP(&x_key, &fix->key) == ZIP_CMP_LESS ||
           (fix == x && ZIP_UNIQUE_CMP(&x_key, &prev->key) == ZIP_CMP_LESS))
            fix->fields.left = cur;
        else
            fix->fields.right = cur;
    } while(cur);
}

static void
ZIP_REMOVE(tree *head, elem *x) {
    elem *cur = head->root;
    if(!cur)
        return;
    const unsigned int *x_key = &x->key;
    elem **prev_edge = &head->root;
    enum ZIP_CMP cur_order = ZIP_UNIQUE_CMP(x_key, &cur->key);
    while(cur_order != ZIP_CMP_EQ) {
        prev_edge = (cur_order == ZIP_CMP_LESS) ? &cur->fields.left : &cur->fields.right;
        cur = *prev_edge;
        if(!cur)
            return;
        cur_order = ZIP_UNIQUE_CMP(x_key, &cur->key);
    }
    *prev_edge = ZIP_ZIP(cur->fields.left, cur->fields.right);
}

static elem *
ZIP_FIND(tree *head, unsigned int key) {
    elem *cur = head->root;
    while(cur) {
        if(cur->key == key)
            return cur;
        cur = (key < cur->key) ? cur->fields.left : cur->fields.right;
    }
    return NULL;
}

static elem *
ZIP_MIN(tree *head) {
    elem *cur = head->root;
    if(!cur)
        return NULL;
    while(cur->fields.left)
        cur = cur->fields.left;
    return cur;
}

static elem *
ZIP_MAX(tree *head) {
    elem *cur = head->root;
    if(!cur)
        return NULL;
    while(cur->fields.right)
        cur = cur->fields.right;
    return cur;
}

/* Verification */

static void
checkTreeInternal(elem *e,
                  unsigned int min_key, unsigned int max_key) {
    assert(e->key >= min_key);
    assert(e->key <= max_key);

    elem *left = e->fields.left;
    if(left) {
        assert(left->key <= e->key);
        checkTreeInternal(left, min_key, e->key);
    }

    elem *right = e->fields.right;
    if(right) {
        assert(right->key >= e->key);
        checkTreeInternal(right, e->key, max_key);
    }
}

static void
checkTree(tree *t) {
    if(!t->root)
        return;
    elem *max_entry = ZIP_MAX(t);
    elem *min_entry = ZIP_MIN(t);
    checkTreeInternal(t->root, min_entry->key, max_entry->key);
}

/* Example */

#define ELEMS 3

int main(void) {
    elem elems[ELEMS];

    tree t1 = {NULL};
    for(unsigned int i = 0; i < ELEMS; i++) {
        elem *e = &elems[i];
        //e->key = nondet();
        ZIP_INSERT(&t1, e);
    }

    checkTree(&t1);

    /* for(unsigned int split_key = 0; split_key < ELEMS ; split_key++) { */
    /*     tree t2; */
    /*     tree t3; */
    /*     ZIP_UNZIP(&t1, split_key, &t2, &t3); */
    /*     checkTree(&t2); */
    /*     checkTree(&t3); */

    /*     elem *find_right = ZIP_FIND(&t3, split_key); */
    /*     assert(find_right == NULL); */
    /*     elem *smallest_right = ZIP_MIN(&t3); */
    /*     if(smallest_right) */
    /*         assert(smallest_right->key >= split_key); */

    /*     elem *largest_left = ZIP_MAX(&t2); */
    /*     if(largest_left) */
    /*         assert(largest_left->key <= split_key); */

    /*     t1.root = ZIP_ZIP(t2.root, t3.root); */
    /*     checkTree(&t1); */
    /* } */

    /* while(t1.root) { */
    /*     checkTree(&t1); */
    /*     elem *left = t1.root->fields.left; */
    /*     elem *right = t1.root->fields.right; */
    /*     t1.root = ZIP_ZIP(left, right); */
    /* } */
}
