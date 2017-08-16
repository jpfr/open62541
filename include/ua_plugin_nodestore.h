/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef UA_NODES_H_
#define UA_NODES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_types_generated.h"

/* Forward declarations */
struct UA_Node;
typedef struct UA_Node UA_Node;

/**
 * Nodestore
 * =========
 * The following definitions are used for implementing node storage plugins.
 * Most users will want to use one of the predefined Nodestores.
 *
 * Warning! Endusers should not manually edit nodes. Please use the server API
 * for that. Otherwise, the consistency checks of the server are omitted. This
 * can crash the application eventually. */

typedef void
(*UA_NodestoreVisitor)(void *visitorContext, const UA_Node *node);

typedef struct {
    /* Nodestore context and lifecycle */
    void *context;
    void (*deleteNodestore)(void *nodestoreContext);

    /* For non-multithreaded access, some nodestore allow that nodes are edited
     * without a copy/replace. This is not possible when the node is only an
     * intermediate representation and stored e.g. in a database backend. */
    UA_Boolean inPlaceEditAllowed;

    /* The following definitions are used to create empty nodes of the different
     * node types. The memory is managed by the nodestore. Therefore, the node
     * has to be removed via a special deleteNode function. (If the new node is
     * not added to the nodestore.) */
    UA_Node * (*newNode)(void *nodestoreContext, UA_NodeClass nodeClass);

    void (*deleteNode)(void *nodestoreContext, UA_Node *node);

    /* ``Get`` returns a pointer to an immutable node. ``Release`` indicates
     * that the pointer is no longer accessed afterwards. */

    const UA_Node * (*getNode)(void *nodestoreContext, const UA_NodeId *nodeId);

    void (*releaseNode)(void *nodestoreContext, const UA_Node *node);

    /* Returns an editable copy of a node (needs to be deleted with the
     * deleteNode function or inserted / replaced into the nodestore). */
    UA_Node * (*getNodeCopy)(void *nodestoreContext, const UA_NodeId *nodeId);

    /* Inserts a new node into the nodestore. If the NodeId is zero, then a
     * fresh numeric NodeId is assigned. If insertion fails, the node is
     * deleted. */
    UA_StatusCode (*insertNode)(void *nodestoreContext, UA_Node *node,
                                UA_NodeId *addedNodeId);

    /* To replace a node, get an editable copy of the node, edit and replace
     * with this function. If the node was already replaced since the copy was
     * made, UA_STATUSCODE_BADINTERNALERROR is returned. If the NodeId is not
     * found, UA_STATUSCODE_BADNODEIDUNKNOWN is returned. In both error cases,
     * the editable node is deleted. */
    UA_StatusCode (*replaceNode)(void *nodestoreContext, UA_Node *node);

    /* Removes a node from the nodestore. */
    UA_StatusCode (*removeNode)(void *nodestoreContext, const UA_NodeId *nodeId);

    /* Execute a callback for every node in the nodestore. */
    void (*iterate)(void *nodestoreContext, void* visitorContext,
                    UA_NodestoreVisitor visitor);
} UA_Nodestore;

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* UA_NODES_H_ */
