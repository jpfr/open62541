/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ua_nodestore_default.h"
#include "ua_plugin_nodestore_nodes.h"

/* The default Nodestore is simply a hash-map from NodeIds to Nodes */

#ifndef UA_ENABLE_MULTITHREADING /* conditional compilation */

#define UA_NODEMAP_MINSIZE 64

typedef struct UA_NodeMapEntry {
    struct UA_NodeMapEntry *orig; // the version this is a copy from (or NULL)
    UA_UInt16 refCount; /* How many consumers have a reference to the node? */
    UA_Boolean deleted; /* Node was marked as deleted and can be deleted when refCount == 0 */
    UA_Node node;
} UA_NodeMapEntry;

#define UA_NODEMAP_TOMBSTONE ((UA_NodeMapEntry*)0x01)

/* To find an entry, iterate over candidate positions according to the NodeId
 * hash.
 *
 * - Tombstone or non-matching NodeId: continue searching
 * - Matching NodeId: Return the entry
 * - NULL: Abort the search */

typedef struct {
    UA_NodeMapEntry **entries;
    UA_UInt32 size;
    UA_UInt32 count;
    UA_UInt32 sizePrimeIndex;
} UA_NodeMap;

/*********************/
/* HashMap Utilities */
/*********************/

/* The size of the hash-map is always a prime number. They are chosen to be
 * close to the next power of 2. So the size ca. doubles with each prime. */
static UA_UInt32 const primes[] = {
    7,         13,         31,         61,         127,         251,
    509,       1021,       2039,       4093,       8191,        16381,
    32749,     65521,      131071,     262139,     524287,      1048573,
    2097143,   4194301,    8388593,    16777213,   33554393,    67108859,
    134217689, 268435399,  536870909,  1073741789, 2147483647,  4294967291
};

static UA_UInt32 mod(UA_UInt32 h, UA_UInt32 size) { return h % size; }
static UA_UInt32 mod2(UA_UInt32 h, UA_UInt32 size) { return 1 + (h % (size - 2)); }

static UA_UInt16
higher_prime_index(UA_UInt32 n) {
    UA_UInt16 low  = 0;
    UA_UInt16 high = (UA_UInt16)(sizeof(primes) / sizeof(UA_UInt32));
    while(low != high) {
        UA_UInt16 mid = (UA_UInt16)(low + ((high - low) / 2));
        if(n > primes[mid])
            low = (UA_UInt16)(mid + 1);
        else
            high = mid;
    }
    return low;
}

static UA_NodeMapEntry *
instantiateEntry(UA_NodeClass nodeClass) {
    size_t size = sizeof(UA_NodeMapEntry) - sizeof(UA_Node);
    switch(nodeClass) {
    case UA_NODECLASS_OBJECT:
        size += sizeof(UA_ObjectNode);
        break;
    case UA_NODECLASS_VARIABLE:
        size += sizeof(UA_VariableNode);
        break;
    case UA_NODECLASS_METHOD:
        size += sizeof(UA_MethodNode);
        break;
    case UA_NODECLASS_OBJECTTYPE:
        size += sizeof(UA_ObjectTypeNode);
        break;
    case UA_NODECLASS_VARIABLETYPE:
        size += sizeof(UA_VariableTypeNode);
        break;
    case UA_NODECLASS_REFERENCETYPE:
        size += sizeof(UA_ReferenceTypeNode);
        break;
    case UA_NODECLASS_DATATYPE:
        size += sizeof(UA_DataTypeNode);
        break;
    case UA_NODECLASS_VIEW:
        size += sizeof(UA_ViewNode);
        break;
    default:
        return NULL;
    }
    UA_NodeMapEntry *entry = (UA_NodeMapEntry*)UA_calloc(1, size);
    if(!entry)
        return NULL;
    entry->node.nodeClass = nodeClass;
    return entry;
}

static void
deleteEntry(UA_NodeMapEntry *entry) {
    UA_Node_deleteMembersAnyNodeClass(&entry->node);
    UA_free(entry);
}

static void
deleteEntryDelayed(UA_NodeMapEntry *entry) {
    if(!entry->deleted || entry->refCount > 0)
        return;
    deleteEntry(entry);
}

/* returns slot of a valid node or null */
static UA_NodeMapEntry **
findNode(const UA_NodeMap *ns, const UA_NodeId *nodeid) {
    UA_UInt32 h = UA_NodeId_hash(nodeid);
    UA_UInt32 size = ns->size;
    UA_UInt32 idx = mod(h, size);
    UA_UInt32 hash2 = mod2(h, size);

    while(true) {
        UA_NodeMapEntry *e = ns->entries[idx];
        if(!e)
            return NULL;
        if(e > UA_NODEMAP_TOMBSTONE &&
           UA_NodeId_equal(&e->node.nodeId, nodeid))
            return &ns->entries[idx];
        idx += hash2;
        if(idx >= size)
            idx -= size;
    }

    /* NOTREACHED */
    return NULL;
}

/* returns an empty slot or null if the nodeid exists */
static UA_NodeMapEntry **
findSlot(const UA_NodeMap *ns, const UA_NodeId *nodeid) {
    UA_UInt32 h = UA_NodeId_hash(nodeid);
    UA_UInt32 size = ns->size;
    UA_UInt32 idx = mod(h, size);
    UA_UInt32 hash2 = mod2(h, size);

    while(true) {
        UA_NodeMapEntry *e = ns->entries[idx];
        if(e > UA_NODEMAP_TOMBSTONE &&
           UA_NodeId_equal(&e->node.nodeId, nodeid))
            return NULL;
        if(ns->entries[idx] <= UA_NODEMAP_TOMBSTONE)
            return &ns->entries[idx];
        idx += hash2;
        if(idx >= size)
            idx -= size;
    }

    /* NOTREACHED */
    return NULL;
}

/* The occupancy of the table after the call will be about 50% */
static UA_StatusCode
expand(UA_NodeMap *ns) {
    UA_UInt32 osize = ns->size;
    UA_UInt32 count = ns->count;
    /* Resize only when table after removal of unused elements is either too
       full or too empty */
    if(count * 2 < osize && (count * 8 > osize || osize <= UA_NODEMAP_MINSIZE))
        return UA_STATUSCODE_GOOD;

    UA_NodeMapEntry **oentries = ns->entries;
    UA_UInt32 nindex = higher_prime_index(count * 2);
    UA_UInt32 nsize = primes[nindex];
    UA_NodeMapEntry **nentries = (UA_NodeMapEntry **)UA_calloc(nsize, sizeof(UA_NodeMapEntry*));
    if(!nentries)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    ns->entries = nentries;
    ns->size = nsize;
    ns->sizePrimeIndex = nindex;

    /* recompute the position of every entry and insert the pointer */
    for(size_t i = 0, j = 0; i < osize && j < count; ++i) {
        if(oentries[i] <= UA_NODEMAP_TOMBSTONE)
            continue;
        UA_NodeMapEntry **e = findSlot(ns, &oentries[i]->node.nodeId);
        UA_assert(e);
        *e = oentries[i];
        ++j;
    }

    UA_free(oentries);
    return UA_STATUSCODE_GOOD;
}

/***********************/
/* Interface functions */
/***********************/

static void
UA_NodeMap_delete(void *context) {
    UA_NodeMap *ns = (UA_NodeMap*)context;
    UA_UInt32 size = ns->size;
    UA_NodeMapEntry **entries = ns->entries;
    for(UA_UInt32 i = 0; i < size; ++i) {
        if(entries[i] > UA_NODEMAP_TOMBSTONE)
            deleteEntry(entries[i]);
    }
    UA_free(ns->entries);
    UA_free(ns);
}

static UA_Node *
UA_NodeMap_newNode(void *context, UA_NodeClass nodeClass) {
    UA_NodeMapEntry *entry = instantiateEntry(nodeClass);
    if(!entry)
        return NULL;
    return &entry->node;
}

static void
UA_NodeMap_deleteNode(void *context, UA_Node *node) {
    UA_NodeMapEntry *entry = container_of(node, UA_NodeMapEntry, node);
    UA_assert(&entry->node == node);
    deleteEntry(entry);
}

static const UA_Node *
UA_NodeMap_getNode(void *context, const UA_NodeId *nodeid) {
    UA_NodeMap *ns = (UA_NodeMap*)context;
    UA_NodeMapEntry **entry = findNode(ns, nodeid);
    if(!entry)
        return NULL;
    ++(*entry)->refCount;
    return (const UA_Node*)&(*entry)->node;
}

static void
UA_NodeMap_releaseNode(void *context, const UA_Node *node) {
    UA_NodeMapEntry *entry = container_of(node, UA_NodeMapEntry, node);
    UA_assert(&entry->node == node);
    UA_assert(entry->refCount > 0);

    /* Decrease the refcount */
    --entry->refCount;

    /* Delete if the node is no longer in the map and no other consumer holds a
     * reference */
    deleteEntryDelayed(entry);
}

static UA_Node *
UA_NodeMap_getNodeCopy(void *context, const UA_NodeId *nodeid) {
    UA_NodeMap *ns = (UA_NodeMap*)context;
    UA_NodeMapEntry **slot = findNode(ns, nodeid);
    if(!slot)
        return NULL;
    UA_NodeMapEntry *entry = *slot;
    UA_NodeMapEntry *newItem = instantiateEntry(entry->node.nodeClass);
    if(!newItem)
        return NULL;
    if(UA_Node_copyAnyNodeClass(&entry->node, &newItem->node) != UA_STATUSCODE_GOOD) {
        deleteEntry(newItem);
        return NULL;
    }
    newItem->orig = entry; // store the pointer to the original
    return &newItem->node;
}

static UA_StatusCode
UA_NodeMap_removeNode(void *context, const UA_NodeId *nodeid) {
    UA_NodeMap *ns = (UA_NodeMap*)context;
    UA_NodeMapEntry **slot = findNode(ns, nodeid);
    if(!slot)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    (*slot)->deleted = true;
    deleteEntryDelayed(*slot);
    *slot = UA_NODEMAP_TOMBSTONE;
    --ns->count;
    /* Downsize the hashmap if it is very empty */
    if(ns->count * 8 < ns->size && ns->size > 32)
        expand(ns); // this can fail. we just continue with the bigger hashmap.
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_NodeMap_insertNode(void *context, UA_Node *node,
                      UA_NodeId *addedNodeId) {
    UA_NodeMap *ns = (UA_NodeMap*)context;
    if(ns->size * 3 <= ns->count * 4) {
        if(expand(ns) != UA_STATUSCODE_GOOD)
            return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_NodeId tempNodeid;
    tempNodeid = node->nodeId;
    tempNodeid.namespaceIndex = 0;
    UA_NodeMapEntry **entry;
    if(UA_NodeId_isNull(&tempNodeid)) {
        /* create a random nodeid */
        if(node->nodeId.namespaceIndex == 0)
            node->nodeId.namespaceIndex = 1;
        UA_UInt32 identifier = ns->count+1; // start value
        UA_UInt32 size = ns->size;
        UA_UInt32 increase = mod2(identifier, size);
        while(true) {
            node->nodeId.identifier.numeric = identifier;
            entry = findSlot(ns, &node->nodeId);
            if(entry)
                break;
            identifier += increase;
            if(identifier >= size)
                identifier -= size;
        }
    } else {
        entry = findSlot(ns, &node->nodeId);
        if(!entry) {
            deleteEntry(container_of(node, UA_NodeMapEntry, node));
            return UA_STATUSCODE_BADNODEIDEXISTS;
        }
    }

    *entry = container_of(node, UA_NodeMapEntry, node);
    ++ns->count;
    UA_assert(&(*entry)->node == node);

    if(addedNodeId) {
        UA_StatusCode retval = UA_NodeId_copy(&node->nodeId, addedNodeId);
        if(retval != UA_STATUSCODE_GOOD)
            UA_NodeMap_removeNode(ns, &node->nodeId);
        return retval;
    }
    
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_NodeMap_replaceNode(void *context, UA_Node *node) {
    UA_NodeMap *ns = (UA_NodeMap*)context;
    UA_NodeMapEntry **slot= findNode(ns, &node->nodeId);
    if(!slot)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    UA_NodeMapEntry *newEntry = container_of(node, UA_NodeMapEntry, node);
    if(*slot != newEntry->orig) {
        // the node was replaced since the copy was made
        deleteEntry(newEntry);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    (*slot)->deleted = true;
    deleteEntryDelayed(*slot);
    *slot = newEntry;
    return UA_STATUSCODE_GOOD;
}

static void
UA_NodeMap_iterate(void *context, void *visitorContext,
                   UA_NodestoreVisitor visitor) {
    UA_NodeMap *ns = (UA_NodeMap*)context;
    for(UA_UInt32 i = 0; i < ns->size; ++i) {
        if(ns->entries[i] > UA_NODEMAP_TOMBSTONE)
            visitor(visitorContext, &ns->entries[i]->node);
    }
}

UA_StatusCode
UA_Nodestore_default_new(UA_Nodestore *ns) {
    /* Allocate and initialize the nodemap */
    UA_NodeMap *nodemap = (UA_NodeMap*)UA_malloc(sizeof(UA_NodeMap));
    if(!nodemap)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    nodemap->sizePrimeIndex = higher_prime_index(UA_NODEMAP_MINSIZE);
    nodemap->size = primes[nodemap->sizePrimeIndex];
    nodemap->count = 0;
    nodemap->entries = (UA_NodeMapEntry**)
        UA_calloc(nodemap->size, sizeof(UA_NodeMapEntry*));
    if(!nodemap->entries) {
        UA_free(nodemap);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* Populate the nodestore */
    ns->context = nodemap;
    ns->deleteNodestore = UA_NodeMap_delete;
    ns->inPlaceEditAllowed = true;
    ns->newNode = UA_NodeMap_newNode;
    ns->deleteNode = UA_NodeMap_deleteNode;
    ns->getNode = UA_NodeMap_getNode;
    ns->releaseNode = UA_NodeMap_releaseNode;
    ns->getNodeCopy = UA_NodeMap_getNodeCopy;
    ns->insertNode = UA_NodeMap_insertNode;
    ns->replaceNode = UA_NodeMap_replaceNode;
    ns->removeNode = UA_NodeMap_removeNode;
    ns->iterate = UA_NodeMap_iterate;

    return UA_STATUSCODE_GOOD;
}

#endif /* UA_ENABLE_MULTITHREADING */
