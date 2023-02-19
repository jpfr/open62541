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

//&& p1 != p2;
/*@ requires \valid(p1) && \valid(p2); */
static enum ZIP_CMP
ZIP_RANK_CMP(const elem *p1, const elem *p2) {
    unsigned int h1 = p1->rank;
    unsigned int h2 = p2->rank;
    if(h1 == h2)
        return (p1 < p2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
    return (h1 < h2) ? ZIP_CMP_LESS : ZIP_CMP_MORE;
}

/*@
  inductive reachable(elem *root, elem *to) {
    case reachable_direct: \forall elem *p; reachable(p, p);
    case reachable_left: \forall elem *root, *target;
        \valid(root) && (root->left == target) ==> reachable(root, target);
    case reachable_right: \forall elem *root, *target;
        \valid(root) && (root->right == target) ==> reachable(root, target);
    case reachable_bottom_up_left: \forall elem *root, *target;
        \valid(root) && reachable(root->left, target) ==> reachable(root, target);
    case reachable_bottom_up_right: \forall elem *root, *target;
        \valid(root) && reachable(root->right, target) ==> reachable(root, target);
    case reachable_top_down_left: \forall elem *root, *parent, *target;
        \valid(parent) && parent->left == target && reachable(root, parent)
            ==> reachable(root, target);
    case reachable_top_down_right: \forall elem *root, *parent, *target;
        \valid(parent) && parent->right == target && reachable(root, parent)
            ==> reachable(root, target);
  }
*/

/*@
  inductive null_leaves(elem *root) {
    case null_leaves_direct: \forall elem *p; p == \null ==> null_leaves(p);
    case null_leaves_bottom_up: \forall elem *p;
        \valid(p) && null_leaves(p->right) && null_leaves(p->left) ==> null_leaves(p);
    case null_leaves_top_down_left: \forall elem *p;
        \valid(p) && null_leaves(p) ==> null_leaves(p->left);
    case null_leaves_top_down_right: \forall elem *p;
        \valid(p) && null_leaves(p) ==> null_leaves(p->right);
}
*/

/*@
requires \valid(head);
requires null_leaves(head->root);
assigns \nothing;
ensures reachable(head->root, \result);
*/
static elem *
ZIP_FIND(tree *head, unsigned int key) {
    elem *cur = head->root;
    /*@ assert \valid(cur) || cur == \null; */
    /*@ assert reachable(head->root, cur); */
    /*@ assert null_leaves(cur); */

    /*@ loop invariant null_leaves(cur);
        loop invariant reachable(head->root, cur);
        loop invariant \valid(cur) || cur == \null;
        loop assigns cur; */
    while(cur) {
        if(cur->key == key)
            return cur;
        cur = (key < cur->key) ? cur->left : cur->right;
    }

    /*@ assert cur == \null; */
    return NULL;
}

/*@ inductive tree_sorted(elem *root) {
    case null: \forall elem *p; p == \null ==> tree_sorted(p);
    case non_null: \forall elem *p, *l, *r;
        \valid(p) && tree_sorted(p->left) && tree_sorted(p->right) &&
        (p->left == \null || p->left->key <= p->key) &&
        (p->right == \null || p->right->key >= p->key)
        ==> tree_sorted(r);
    }
*/


// memory is either null or valid
/*@
inductive tree_valid(elem *root) {
  case tree_valid_direct: \forall elem *p; p == \null ==> tree_valid(p);
  case tree_valid_bottom_up: \forall elem *p;
    \valid(p) && tree_valid(p->left) && tree_valid(p->right) ==> tree_valid(p);
  case tree_valid_top_down_left: \forall elem *p;
    \valid(p) && tree_valid(p) ==> tree_valid(p->left);
  case tree_valid_top_down_right: \forall elem *p;
    \valid(p) && tree_valid(p) ==> tree_valid(p->right);
}
*/

//assigns \nothing;
//ensures null_leaves(\result);
/*@
requires tree_valid(l);
requires tree_valid(r);
*/
static elem *
ZIP_ZIP(elem *l, elem *r) {
    if(!l)
        return r;
    if(!r)
        return l;
    /*@ assert tree_valid(l); */
    /*@ assert tree_valid(r); */
    elem *root = NULL;
    elem **prev_edge = &root;

    /*@ loop invariant tree_valid(l);
        loop invariant tree_valid(r); */
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
