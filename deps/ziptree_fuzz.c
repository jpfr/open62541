/* This Source Code Form is edsubject to the terms of the Mozilla Public
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
#include <assert.h>

enum ZIP_CMP {
    ZIP_CMP_LESS = -1,
    ZIP_CMP_EQ = 0,
    ZIP_CMP_MORE = 1
};

typedef struct elem {
    unsigned int key;
    unsigned int rank;
    struct elem *left;
    struct elem *right;
} elem;

typedef struct tree {
    struct elem *root;
} tree;

static enum ZIP_CMP
ZIP_RANK_CMP(const elem *p1, const elem *p2) {
    unsigned int h1 = p1->rank;
    unsigned int h2 = p2->rank;
    if(h1 == h2)
        return (p1 < p2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
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
        return (k1 < k2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
    return (*k1 < *k2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
}

static elem *
ZIP_FIND(tree *head, unsigned int key) {
    elem *cur = head->root;
    while(cur) {
        if(cur->key == key)
            return cur;
        cur = (key < cur->key) ? cur->left : cur->right;
    }
    return NULL;
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
            prev_edge = &r->left;
            r = r->left;
        } else {
            *prev_edge = l;
            prev_edge = &l->right;
            l = l->right;
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
            cur = cur->right;
            if(!cur) {
                right->root = NULL;
                return;
            }
        } while(ZIP_UNIQUE_CMP(&key, &cur->key) != ZIP_CMP_LESS);
        right->root = cur;
        prev->right = NULL;
        elem *left_rightmost = prev;
        while(cur->left) {
            prev = cur;
            cur = cur->left;
            if(ZIP_CMP(key, cur->key) != ZIP_CMP_LESS) {
                prev->left = cur->right;
                cur->right = NULL;
                left_rightmost->right = cur;
                left_rightmost = cur;
                cur = prev;
            }
        }
    } else {
        right->root = cur;
        do {
            prev = cur;
            cur = cur->left;
            if(!cur) {
                left->root = NULL;
                return;
            }
        } while(ZIP_CMP(key, cur->key) == ZIP_CMP_LESS);
        left->root = cur;
        prev->left = NULL;
        elem *right_leftmost = prev;
        while(cur->right) {
            prev = cur;
            cur = cur->right;
            if(ZIP_UNIQUE_CMP(&key, &cur->key) == ZIP_CMP_LESS) {
                prev->right = cur->left;
                cur->left = NULL;
                right_leftmost->left = cur;
                right_leftmost = cur;
                cur = prev;
            }
        }
    }
}

static void
ZIP_INSERT(tree *head, elem *x) {
    x->left = NULL;
    x->right = NULL;

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
        cur = (cur_order == ZIP_CMP_MORE) ? cur->right : cur->left;
    } while(cur);

    if(cur == head->root) {
        head->root = x;
    } else {
        if(prev_order == ZIP_CMP_MORE)
            prev->right = x;
        else
            prev->left = x;
    }

    if(!cur)
        return;

    if(cur_order != ZIP_CMP_LESS) {
        x->left = cur;
    } else {
        x->right = cur;
    }

    prev = x;
    do {
        elem *fix = prev;
        if(cur_order == ZIP_CMP_MORE) {
            do {
                prev = cur;
                cur = cur->right;
                if(!cur)
                    break;
                cur_order = ZIP_UNIQUE_CMP(&x_key, &cur->key);
            } while(cur_order == ZIP_CMP_MORE);
        } else {
            do {
                prev = cur;
                cur = cur->left;
                if(!cur)
                    break;
                cur_order = ZIP_UNIQUE_CMP(&x_key, &cur->key);
            } while(cur_order == ZIP_CMP_LESS);
        }

        if(ZIP_UNIQUE_CMP(&x_key, &fix->key) == ZIP_CMP_LESS ||
           (fix == x && ZIP_UNIQUE_CMP(&x_key, &prev->key) == ZIP_CMP_LESS))
            fix->left = cur;
        else
            fix->right = cur;
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
        prev_edge = (cur_order == ZIP_CMP_LESS) ? &cur->left : &cur->right;
        cur = *prev_edge;
        if(!cur)
            return;
        cur_order = ZIP_UNIQUE_CMP(x_key, &cur->key);
    }
    *prev_edge = ZIP_ZIP(cur->left, cur->right);
}

static elem *
ZIP_MIN(tree *head) {
    elem *cur = head->root;
    if(!cur)
        return NULL;
    while(cur->left)
        cur = cur->left;
    return cur;
}

static elem *
ZIP_MAX(tree *head) {
    elem *cur = head->root;
    if(!cur)
        return NULL;
    while(cur->right)
        cur = cur->right;
    return cur;
}

#define ELEMS 5

/*
** Main entry point. The fuzzer invokes this function with each fuzzed input.
*/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(size != (2*ELEMS)+1)
        return 0;

    elem elems[ELEMS];
    tree t1 = {NULL};
    for(size_t i = 0; i < ELEMS; i++){
        struct elem *e = &elems[0];
        e->key = data[2*i];
        e->rank = data[(2*i)+1];
        ZIP_INSERT(&t1, e);
    }

    tree tleft, tright;
    unsigned split_key = data[2*ELEMS];
    ZIP_UNZIP(&t1, split_key, &tleft, &tright);

    elem *min_right = ZIP_MIN(&tright);
    assert(!min_right || split_key < min_right->key);

    elem *max_left= ZIP_MAX(&tleft);
    assert(!max_left || split_key >= max_left->key);

    return 0;
}
