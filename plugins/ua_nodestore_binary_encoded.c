/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2014-2020 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Julian Grothoff
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2020 (c) Kalycito Infotech Pvt Ltd (Author: Jayanth Velusamy)
 *
 *    This nodestore contains the copy of zipTree to hold the MINIMAL nodes
 */

#define _GNU_SOURCE

#include <open62541/plugin/nodestore_default.h>
#include <open62541/plugin/log_stdout.h>
#include "ziptree.h"
#include <open62541/types_generated_encoding_binary.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>

#ifdef UA_ENABLE_USE_ENCODED_NODES

#ifndef UA_ENABLE_IMMUTABLE_NODES
#error The ROM-based Nodestore requires nodes to be replaced on write
#endif

typedef struct {
    UA_NodeId nodeId;
    size_t nodePosition;
    size_t nodeSize;
} lookUpTable;

static UA_StatusCode
commonVariableAttributeEncode(const UA_VariableNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_NodeId_encodeBinary(&node->dataType, bufPos, bufEnd);
    retval |= UA_Int32_encodeBinary(&node->valueRank, bufPos, bufEnd);
    retval |= UA_UInt64_encodeBinary(&node->arrayDimensionsSize, bufPos, bufEnd);
    if(node->arrayDimensionsSize) {
        retval |= UA_UInt32_encodeBinary(node->arrayDimensions, bufPos, bufEnd);
    }
    retval |= UA_UInt32_encodeBinary((const UA_UInt32*)&node->valueSource, bufPos, bufEnd);
    UA_DataValue v2 = node->value.data.value;
    retval |= UA_DataValue_encodeBinary(&v2, bufPos, bufEnd);
    return retval;
}

static UA_StatusCode
objectNodeEncode(const UA_ObjectNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    return UA_Byte_encodeBinary(&node->eventNotifier, bufPos, bufEnd);
}

static UA_StatusCode
variableNodeEncode(const UA_VariableNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Byte_encodeBinary(&node->accessLevel, bufPos, bufEnd);
    retval |= UA_Double_encodeBinary(&node->minimumSamplingInterval, bufPos, bufEnd);
    retval |= UA_Boolean_encodeBinary(&node->historizing, bufPos, bufEnd);
    retval |= commonVariableAttributeEncode(node, bufPos, bufEnd);
    return retval;
}

static UA_StatusCode
methodNodeEncode(const UA_MethodNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    return UA_Boolean_encodeBinary(&node->executable, bufPos, bufEnd);
}

static UA_StatusCode
objectTypeNodeEncode(const UA_ObjectTypeNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    return UA_Boolean_encodeBinary(&node->isAbstract, bufPos, bufEnd);
}

static UA_StatusCode
variableTypeNodeEncode(const UA_VariableTypeNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Boolean_encodeBinary(&node->isAbstract, bufPos, bufEnd);
    retval |= commonVariableAttributeEncode((const UA_VariableNode*)node, bufPos, bufEnd);
    return retval;
}

static UA_StatusCode
ReferenceTypeNodeEncode(const UA_ReferenceTypeNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Boolean_encodeBinary(&node->isAbstract, bufPos, bufEnd);
    retval |= UA_Boolean_encodeBinary(&node->symmetric, bufPos, bufEnd);
    retval |= UA_LocalizedText_encodeBinary(&node->inverseName, bufPos, bufEnd);
    return retval;
}

static UA_StatusCode
dataTypeNodeEncode(const UA_DataTypeNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    return UA_Boolean_encodeBinary(&node->isAbstract, bufPos, bufEnd);
}

static UA_StatusCode
viewNodeEncode(const UA_ViewNode *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Byte_encodeBinary(&node->eventNotifier, bufPos, bufEnd);
    retval |= UA_Boolean_encodeBinary(&node->containsNoLoops, bufPos, bufEnd);
    return retval;
}

static UA_StatusCode
UA_NodeReferenceKind_encodeBinary(const UA_NodeReferenceKind *references,
                                  UA_Byte **bufPos, const UA_Byte *bufEnd) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_NodeId_encodeBinary(&references->referenceTypeId, bufPos, bufEnd);
    retval |= UA_Boolean_encodeBinary(&references->isInverse, bufPos, bufEnd);
    UA_UInt64 targetSize = (UA_UInt64)references->refTargetsSize;
    retval |= UA_UInt64_encodeBinary(&targetSize, bufPos, bufEnd);
    for(size_t i = 0; i < references->refTargetsSize; i++) {
        UA_ReferenceTarget *refTarget = &references->refTargets[i];
        retval |= UA_UInt32_encodeBinary(&refTarget->targetHash, bufPos, bufEnd);
        retval |= UA_ExpandedNodeId_encodeBinary(&refTarget->target, bufPos, bufEnd);
    }
    return retval;
}

static UA_StatusCode
UA_Node_encodeBinary(const UA_Node *node, UA_Byte **bufPos, const UA_Byte *bufEnd) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_NodeId_encodeBinary(&node->nodeId, bufPos, bufEnd);
    retval |= UA_NodeClass_encodeBinary(&node->nodeClass, bufPos, bufEnd);
    UA_assert(node->nodeClass != UA_NODECLASS_UNSPECIFIED);
    retval |= UA_QualifiedName_encodeBinary(&node->browseName, bufPos, bufEnd);
    retval |= UA_LocalizedText_encodeBinary(&node->displayName, bufPos, bufEnd);
    retval |= UA_LocalizedText_encodeBinary(&node->description, bufPos, bufEnd);
    retval |= UA_UInt32_encodeBinary(&node->writeMask, bufPos, bufEnd);
    UA_UInt64 refSize = (UA_UInt64)node->referencesSize;
    retval |= UA_UInt64_encodeBinary(&refSize, bufPos, bufEnd);
    for(size_t i = 0; i < node->referencesSize; i++) {
        retval |= UA_NodeReferenceKind_encodeBinary(&node->references[i], bufPos, bufEnd);
    }

    switch(node->nodeClass) {
    case UA_NODECLASS_OBJECT:
        retval |= objectNodeEncode((const UA_ObjectNode*)node, bufPos, bufEnd);
        break;
    case UA_NODECLASS_VARIABLE:
        retval |= variableNodeEncode((const UA_VariableNode*)node, bufPos, bufEnd);
        break;
    case UA_NODECLASS_METHOD:
        retval |= methodNodeEncode((const UA_MethodNode*)node, bufPos, bufEnd);
        break;
    case UA_NODECLASS_OBJECTTYPE:
        retval |= objectTypeNodeEncode((const UA_ObjectTypeNode*)node, bufPos, bufEnd);
        break;
    case UA_NODECLASS_VARIABLETYPE:
        retval |= variableTypeNodeEncode((const UA_VariableTypeNode*)node, bufPos, bufEnd);
        break;
    case UA_NODECLASS_REFERENCETYPE:
        retval |= ReferenceTypeNodeEncode((const UA_ReferenceTypeNode*)node, bufPos, bufEnd);
        break;
    case UA_NODECLASS_DATATYPE:
        retval |= dataTypeNodeEncode((const UA_DataTypeNode*)node, bufPos, bufEnd);
        break;
    case UA_NODECLASS_VIEW:
        retval |= viewNodeEncode((const UA_ViewNode*)node, bufPos, bufEnd);
        break;
    default:
        break;
    }

    return retval;
}

static UA_StatusCode
objectNodeDecode(const UA_ByteString *src, size_t *offset, UA_ObjectNode* objectNode) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Byte_decodeBinary(src, offset, &objectNode->eventNotifier);
    return retval;
}

static UA_StatusCode
variableNodeDecode(const UA_ByteString *src, size_t *offset, UA_VariableNode* variableNode) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Byte_decodeBinary(src, offset, &variableNode->accessLevel);
    retval |= UA_Double_decodeBinary(src, offset, &variableNode->minimumSamplingInterval);
    retval |= UA_Boolean_decodeBinary(src, offset, &variableNode->historizing);
    retval |= UA_NodeId_decodeBinary(src, offset, &variableNode->dataType);
    retval |= UA_Int32_decodeBinary(src, offset, &variableNode->valueRank);
    retval |= UA_UInt64_decodeBinary(src, offset, &variableNode->arrayDimensionsSize);
    if(variableNode->arrayDimensionsSize) {
        variableNode->arrayDimensions = (UA_UInt32 *)
            UA_calloc(variableNode->arrayDimensionsSize, sizeof(UA_UInt32));
        retval |= UA_UInt32_decodeBinary(src, offset, variableNode->arrayDimensions);
    }
    retval |= UA_UInt32_decodeBinary(src, offset, (UA_UInt32*)&variableNode->valueSource);
    retval |= UA_DataValue_decodeBinary(src, offset, &variableNode->value.data.value);
    return retval;
}

static UA_StatusCode
methodNodeDecode(const UA_ByteString *src, size_t *offset, UA_MethodNode* methodNode) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Boolean_decodeBinary(src, offset, &methodNode->executable);
    return retval;
}

static UA_StatusCode
objectTypeNodeDecode(const UA_ByteString *src, size_t *offset, UA_ObjectTypeNode* objTypeNode) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Boolean_decodeBinary(src, offset, &objTypeNode->isAbstract);
    return retval;
}

static UA_StatusCode
variableTypeNodeDecode(const UA_ByteString *src, size_t *offset,
                       UA_VariableTypeNode* varTypeNode) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Boolean_decodeBinary(src, offset, &varTypeNode->isAbstract);
    retval |= UA_NodeId_decodeBinary(src, offset, &varTypeNode->dataType);
    retval |= UA_Int32_decodeBinary(src, offset, &varTypeNode->valueRank);
    retval |= UA_UInt64_decodeBinary(src, offset, &varTypeNode->arrayDimensionsSize);
    if(varTypeNode->arrayDimensionsSize) {
        retval |= UA_UInt32_decodeBinary(src, offset, &varTypeNode->arrayDimensions[0]);
    }
    retval |= UA_UInt32_decodeBinary(src, offset, (UA_UInt32*)&varTypeNode->valueSource);
    retval |= UA_DataValue_decodeBinary(src, offset, &varTypeNode->value.data.value);

    return retval;
}

static UA_StatusCode
ReferenceTypeNodeDecode(const UA_ByteString *src, size_t *offset,
                        UA_ReferenceTypeNode* refTypeNode) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Boolean_decodeBinary(src, offset, &refTypeNode->isAbstract);
    retval |= UA_Boolean_decodeBinary(src, offset, &refTypeNode->symmetric);
    retval |= UA_LocalizedText_decodeBinary(src, offset, &refTypeNode->inverseName);
    return retval;
}

static UA_StatusCode
dataTypeNodeDecode(const UA_ByteString *src, size_t *offset,
                   UA_DataTypeNode* dataTypeNode) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Boolean_decodeBinary(src, offset, &dataTypeNode->isAbstract);
    return retval;
}

static UA_StatusCode
viewNodeDecode(const UA_ByteString *src, size_t *offset, UA_ViewNode* viewNode) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Byte_decodeBinary(src, offset, &viewNode->eventNotifier);
    retval |= UA_Boolean_decodeBinary(src, offset, &viewNode->containsNoLoops);
    return retval;
}

#define MAX_ROW_LENGTH         30  // Maximum length of a row in lookup table

static void
readRowLookuptable(char ltRow [], int length, lookUpTable *lt, int row) {
    /**
     * There are four contents per row
     * |IdentifierType|Identifier|nodePosition|nodeSize|
     * Each data is separated by space
     */
    size_t index = 0;
    int column = 1;
    char ltTemp[MAX_ROW_LENGTH] = {0};
    for (int j = 0 ; j < length; j++) {
        if(ltRow[j] != ' ') {
            ltTemp[index] = ltRow[j];
            index++;
        }
        if(ltRow[j] == ' ' || j == length - 1) {
            switch(column) {
            case 1:
                if(strtol(ltTemp, NULL, 10) == UA_NODEIDTYPE_NUMERIC) {
                    lt[row].nodeId.identifierType = UA_NODEIDTYPE_NUMERIC;
                }
                if(strtol(ltTemp, NULL, 10) == UA_NODEIDTYPE_STRING) {
                    lt[row].nodeId.identifierType = UA_NODEIDTYPE_STRING;
                }
                break;
            case 2:
                if(lt[row].nodeId.identifierType == UA_NODEIDTYPE_NUMERIC) {
                    lt[row].nodeId.identifier.numeric = (UA_UInt32)strtol(ltTemp, NULL, 10);
                }
                if(lt[row].nodeId.identifierType == UA_NODEIDTYPE_STRING) {
                    lt[row].nodeId.identifier.string = UA_STRING_NULL;
                    lt[row].nodeId.identifier.string.length = index;
                    ltTemp[index] = '\0';
                    lt[row].nodeId.identifier.string = UA_String_fromChars(&ltTemp[0]);
                }
                break;
            case 3:
                lt[row].nodePosition = (size_t) strtol(ltTemp, NULL, 10);
                break;
            case 4:
                lt[row].nodeSize = (size_t) strtol(ltTemp, NULL, 10);
                break;
            default:
                break;
            }
            /* Clear the array contents */
            for(int i = 0; i < MAX_ROW_LENGTH; i++) {
                ltTemp[i] = 0;
            }
            column++;
            index = 0;
        }
    }
}

static lookUpTable*
UA_Lookuptable_Initialize(size_t *ltSize, const char *const path) {
    int ch;
    size_t nodeCount = 0; // To count the number of nodes
    FILE *fpLookuptable;
    fpLookuptable = fopen(path, "r");
    if(!fpLookuptable) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "The opening of file lookupTable.bin failed");
    }
    while((ch = fgetc(fpLookuptable)) != EOF) {
        if(ch == '\n') {
            nodeCount++;
        }
    }
    fclose(fpLookuptable);
    *ltSize = nodeCount;
    lookUpTable *lt = (lookUpTable *)UA_calloc(*ltSize, sizeof(lookUpTable));
    return lt;
}

static void
UA_Read_LookUpTable(lookUpTable *lt, size_t ltSize, const char* const path){
    int ch;
    int length = 0;
    int row = 0;
    char ltRow[MAX_ROW_LENGTH] = {0};
    FILE *fpLookuptable  = fopen(path, "r");
    if(!fpLookuptable) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "The opening of file lookupTable.bin failed");
    }
    while((ch = fgetc(fpLookuptable)) != EOF) {
        switch(ch) {
        case '\n':
            readRowLookuptable(ltRow, length, lt, row); //separate lookuptable content from each row and populate
            for(int i = 0; i < MAX_ROW_LENGTH; i++) {
                  ltRow[i]= 0;
            }
            length = 0;
            row++;
            break;
        default:
            ltRow[length] = (char)ch; // Read each character until a newline is found
            length++;
            break;
        }
    }
    fclose(fpLookuptable);
}

static UA_StatusCode
UA_Read_Encoded_Binary(UA_ByteString *encodedBin, const char *path) {
    /* Open file */
    int fdEncoded = open(path, 0, O_RDONLY);
    if(fdEncoded < 0) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "The opening of file encodedNode.bin failed");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* Get the file size */
    struct stat filestat;
    if(fstat(fdEncoded, &filestat) !=0) {
        close(fdEncoded);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* mmap file for direct access */
    void *mmapped = mmap(NULL, (size_t)filestat.st_size, PROT_READ, MAP_PRIVATE, fdEncoded, 0);
    if(!mmapped) {
        close(fdEncoded);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    encodedBin->data = (UA_Byte*)mmapped;
    encodedBin->length = (size_t)filestat.st_size;
    close(fdEncoded);
    return UA_STATUSCODE_GOOD;
}

/* container_of */
#define container_of(ptr, type, member) \
    (type *)((uintptr_t)ptr - offsetof(type,member))

struct NodeEntry;
typedef struct NodeEntry NodeEntry;

struct NodeEntry {
    ZIP_ENTRY(NodeEntry) zipfields;
    UA_UInt32 nodeIdHash;
    UA_UInt16 refCount; /* How many consumers have a reference to the node? */
    UA_Boolean deleted; /* Node was marked as deleted and can be deleted when refCount == 0 */
    NodeEntry *orig;    /* If a copy is made to replace a node, track that we
                         * replace only the node from which the copy was made.
                         * Important for concurrent operations. */
    UA_NodeId nodeId; /* This is actually a UA_Node that also starts with a NodeId */
};

/* Absolute ordering for NodeIds */
static enum ZIP_CMP
cmpNodeId(const void *a, const void *b) {
    const NodeEntry *aa = (const NodeEntry*)a;
    const NodeEntry *bb = (const NodeEntry*)b;

    /* Compare hash */
    if(aa->nodeIdHash < bb->nodeIdHash)
        return ZIP_CMP_LESS;
    if(aa->nodeIdHash > bb->nodeIdHash)
        return ZIP_CMP_MORE;

    /* Compore nodes in detail */
    return (enum ZIP_CMP)UA_NodeId_order(&aa->nodeId, &bb->nodeId);
}

ZIP_HEAD(NodeTreeBin, NodeEntry);
typedef struct NodeTreeBin NodeTreeBin;

typedef struct {
    NodeTreeBin root;
    lookUpTable *ltRead;
    size_t ltSizeRead;
    UA_ByteString encodeBin;
} ZipContext;

ZIP_PROTTYPE(NodeTreeBin, NodeEntry, NodeEntry)
ZIP_IMPL(NodeTreeBin, NodeEntry, zipfields, NodeEntry, zipfields, cmpNodeId)

static NodeEntry *
newEntry(UA_NodeClass nodeClass) {
    size_t size = sizeof(NodeEntry) - sizeof(UA_NodeId);
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
    NodeEntry *entry = (NodeEntry*)UA_calloc(1, size);
    if(!entry)
        return NULL;
    UA_Node *node = (UA_Node*)&entry->nodeId;
    node->nodeClass = nodeClass;
    return entry;
}

static void
deleteEntry(NodeEntry *entry) {
    UA_Node_clear((UA_Node*)&entry->nodeId);
    UA_free(entry);
}

static void
cleanupEntry(NodeEntry *entry) {
    if(entry->deleted && entry->refCount == 0)
        deleteEntry(entry);
}

/***********************/
/* Interface functions */
/***********************/

/* Not yet inserted into the ZipContext */
static UA_Node *
zipNsNewNode(void *nsCtx, UA_NodeClass nodeClass) {
    NodeEntry *entry = newEntry(nodeClass);
    if(!entry)
        return NULL;
    return (UA_Node*)&entry->nodeId;
}

/* Not yet inserted into the ZipContext */
static void
zipNsDeleteNode(void *nsCtx, UA_Node *node) {
    NodeEntry *entry = container_of(node, NodeEntry, nodeId);
    entry->deleted = true;
}

static void
zipNsReleaseNode(void *nsCtx, const UA_Node *node) {
    if(!node)
        return;
    NodeEntry *entry = container_of(node, NodeEntry, nodeId);
    UA_assert(entry->refCount > 0);
    --entry->refCount;
    cleanupEntry(entry);
}

static UA_Node *
UA_Node_decodeBinary(void *ctx, const UA_ByteString encodedBin, size_t offset) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_NodeId nodeID;
    retval |= UA_NodeId_decodeBinary(&encodedBin, &offset, &nodeID);
    UA_NodeClass nodeClass;
    retval |= UA_NodeClass_decodeBinary(&encodedBin, &offset, &nodeClass);
    UA_Node* node = NULL;
    if(ctx)
        node = zipNsNewNode(ctx, nodeClass);
    else {
        NodeEntry *e = newEntry(nodeClass);
        node = (UA_Node*)&e->nodeId;
    }
    if(!node) {
        UA_NodeId_clear(&nodeID);
        return NULL;
    }

    memcpy(&node->nodeId, &nodeID, sizeof(UA_NodeId));
    node->nodeClass = nodeClass;

    retval |= UA_QualifiedName_decodeBinary(&encodedBin, &offset, &node->browseName);
    retval |= UA_LocalizedText_decodeBinary(&encodedBin, &offset, &node->displayName);
    retval |= UA_LocalizedText_decodeBinary(&encodedBin, &offset, &node->description);
    retval |= UA_UInt32_decodeBinary(&encodedBin, &offset, &node->writeMask);
    UA_UInt64 referencesSize;
    retval |= UA_UInt64_decodeBinary(&encodedBin, &offset, &referencesSize);
    node->referencesSize = referencesSize;

    node->references = (UA_NodeReferenceKind*)
        UA_calloc(referencesSize, sizeof(UA_NodeReferenceKind));
    for (size_t i = 0; i < referencesSize; i++) {
        UA_NodeId referenceTypeId;
        retval |= UA_NodeId_decodeBinary(&encodedBin, &offset, &referenceTypeId);
        UA_Boolean isInverse;
        retval |= UA_Boolean_decodeBinary(&encodedBin, &offset, &isInverse);
        memcpy(&node->references[i].referenceTypeId, &referenceTypeId, sizeof(UA_NodeId));
        node->references[i].isInverse = isInverse;

        size_t refTargetsSize;
        retval |= UA_UInt64_decodeBinary(&encodedBin, &offset, (UA_UInt64 *)&refTargetsSize);
        node->references[i].refTargetsSize = refTargetsSize;
        node->references[i].refTargets = (UA_ReferenceTarget*)
            UA_calloc(node->references[i].refTargetsSize, sizeof(UA_ReferenceTarget));
        for (size_t j = 0; j < refTargetsSize; j++) {
            UA_UInt32 targetHash;
            retval |= UA_UInt32_decodeBinary(&encodedBin, &offset, &targetHash);
            UA_ExpandedNodeId target;
            retval |= UA_ExpandedNodeId_decodeBinary(&encodedBin, &offset, &target);
            node->references[i].refTargets[j].targetHash = targetHash;
            memcpy(&node->references[i].refTargets[j].target, &target, sizeof(UA_ExpandedNodeId));
        }
    }

    switch(nodeClass) {
    case UA_NODECLASS_OBJECT:
        retval |= objectNodeDecode(&encodedBin, &offset, (UA_ObjectNode*) node);
        break;
    case UA_NODECLASS_VARIABLE:
        retval |= variableNodeDecode(&encodedBin, &offset, (UA_VariableNode*) node);
        break;
    case UA_NODECLASS_METHOD:
        retval |= methodNodeDecode(&encodedBin, &offset, (UA_MethodNode*) node);
        break;
    case UA_NODECLASS_OBJECTTYPE:
        retval |= objectTypeNodeDecode(&encodedBin, &offset, (UA_ObjectTypeNode*) node);
        break;
    case UA_NODECLASS_VARIABLETYPE:
        retval |= variableTypeNodeDecode(&encodedBin, &offset, (UA_VariableTypeNode*) node);
        break;
    case UA_NODECLASS_REFERENCETYPE:
        retval |= ReferenceTypeNodeDecode(&encodedBin, &offset, (UA_ReferenceTypeNode*) node);
        break;
    case UA_NODECLASS_DATATYPE:
        retval |= dataTypeNodeDecode(&encodedBin, &offset, (UA_DataTypeNode*) node);
        break;
    case UA_NODECLASS_VIEW:
        retval |= viewNodeDecode(&encodedBin, &offset, (UA_ViewNode*) node);
        break;
    default:
        break;
    }

    NodeEntry *entry = container_of(node, NodeEntry, nodeId);

    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER,
                     "The decodeNode failed with error : %s",
                     UA_StatusCode_name(retval));
        deleteEntry(entry);
        return NULL;
    }

    ++entry->refCount;
    entry->deleted = true; // remove the decoded node from the memory when release is called!
    return node;
}

static const UA_Node *
zipNsGetNode(void *nsCtx, const UA_NodeId *nodeId) {
    ZipContext *ns = (ZipContext*)nsCtx;
    NodeEntry dummy;
    dummy.nodeIdHash = UA_NodeId_hash(nodeId);
    dummy.nodeId = *nodeId;
    NodeEntry *entry = ZIP_FIND(NodeTreeBin, &ns->root, &dummy);
    if(entry) {
        ++entry->refCount;
        return (const UA_Node*)&entry->nodeId;
    }

    for(size_t i = 0; i < ns->ltSizeRead; i++) {
        if(UA_NodeId_equal(nodeId, &ns->ltRead[i].nodeId))
            return UA_Node_decodeBinary(nsCtx, ns->encodeBin, ns->ltRead[i].nodePosition);
    }
    return NULL;
}

static UA_StatusCode
zipNsGetNodeCopy(void *nsCtx, const UA_NodeId *nodeId,
                         UA_Node **outNode) {
    /* Find the node */
    const UA_Node *node = zipNsGetNode(nsCtx, nodeId);
    if(!node)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;

    /* Create the new entry */
    NodeEntry *ne = newEntry(node->nodeClass);
    if(!ne) {
        zipNsReleaseNode(nsCtx, node);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* Copy the node content */
    UA_Node *nnode = (UA_Node*)&ne->nodeId;
    UA_StatusCode retval = UA_Node_copy(node, nnode);
    zipNsReleaseNode(nsCtx, node);
    if(retval != UA_STATUSCODE_GOOD) {
        deleteEntry(ne);
        return retval;
    }

    ne->orig = container_of(node, NodeEntry, nodeId);
    *outNode = nnode;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
zipNsInsertNode(void *nsCtx, UA_Node *node, UA_NodeId *addedNodeId) {
    NodeEntry *entry = container_of(node, NodeEntry, nodeId);
    ZipContext *ns = (ZipContext*)nsCtx;

    /* Ensure that the NodeId is unique */
    NodeEntry dummy;
    dummy.nodeId = node->nodeId;
    if(node->nodeId.identifierType == UA_NODEIDTYPE_NUMERIC &&
       node->nodeId.identifier.numeric == 0) {
        do { /* Create a random nodeid until we find an unoccupied id */
            node->nodeId.identifier.numeric = UA_UInt32_random();
            dummy.nodeId.identifier.numeric = node->nodeId.identifier.numeric;
            dummy.nodeIdHash = UA_NodeId_hash(&node->nodeId);
        } while(ZIP_FIND(NodeTreeBin, &ns->root, &dummy));
    } else {
        dummy.nodeIdHash = UA_NodeId_hash(&node->nodeId);
        if(ZIP_FIND(NodeTreeBin, &ns->root, &dummy)) { /* The nodeid exists */
            deleteEntry(entry);
            return UA_STATUSCODE_BADNODEIDEXISTS;
        }
    }

    /* Copy the NodeId */
    if(addedNodeId) {
        UA_StatusCode retval = UA_NodeId_copy(&node->nodeId, addedNodeId);
        if(retval != UA_STATUSCODE_GOOD) {
            deleteEntry(entry);
            return retval;
        }
    }

    /* Insert the node */
    entry->nodeIdHash = dummy.nodeIdHash;
    ZIP_INSERT(NodeTreeBin, &ns->root, entry, ZIP_FFS32(UA_UInt32_random()));
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
zipNsReplaceNode(void *nsCtx, UA_Node *node) {
    ZipContext *ns = (ZipContext*)nsCtx;
    NodeEntry *entry = container_of(node, NodeEntry, nodeId);

    /* Find the node */
    const UA_Node *oldNode = zipNsGetNode(nsCtx, &node->nodeId);
    if(!oldNode) {
        deleteEntry(container_of(node, NodeEntry, nodeId));
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    }

    NodeEntry *oldEntry = container_of(oldNode, NodeEntry, nodeId);
    if(!oldEntry->deleted) {
        /* The nold version is not from the binfile */
        if(oldEntry != entry->orig) {
            /* The node was already updated since the copy was made */
            deleteEntry(entry);
            zipNsReleaseNode(nsCtx, oldNode);
            return UA_STATUSCODE_BADINTERNALERROR;
        }
        ZIP_REMOVE(NodeTreeBin, &ns->root, oldEntry);
        entry->nodeIdHash = oldEntry->nodeIdHash;
        oldEntry->deleted = true;
    } else {
        entry->nodeIdHash = UA_NodeId_hash(&node->nodeId);
    }

    /* Replace */
    ZIP_INSERT(NodeTreeBin, &ns->root, entry, ZIP_RANK(entry, zipfields));

    zipNsReleaseNode(nsCtx, oldNode);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
zipNsRemoveNode(void *nsCtx, const UA_NodeId *nodeId) {
    ZipContext *ns = (ZipContext*)nsCtx;
    NodeEntry dummy;
    dummy.nodeIdHash = UA_NodeId_hash(nodeId);
    dummy.nodeId = *nodeId;
    NodeEntry *entry = ZIP_FIND(NodeTreeBin, &ns->root, &dummy);
    if(!entry)
        return UA_STATUSCODE_BADNODEIDUNKNOWN;
    ZIP_REMOVE(NodeTreeBin, &ns->root, entry);
    entry->deleted = true;
    cleanupEntry(entry);
    return UA_STATUSCODE_GOOD;
}

struct VisitorData {
    UA_NodestoreVisitor visitor;
    void *visitorContext;
};

static void
nodeVisitor(NodeEntry *entry, void *data) {
    struct VisitorData *d = (struct VisitorData*)data;
    d->visitor(d->visitorContext, (UA_Node*)&entry->nodeId);
}

static void
zipNsIterate(void *nsCtx, UA_NodestoreVisitor visitor,
             void *visitorCtx) {
    struct VisitorData d;
    d.visitor = visitor;
    d.visitorContext = visitorCtx;
    ZipContext *ns = (ZipContext*)nsCtx;
    ZIP_ITER(NodeTreeBin, &ns->root, nodeVisitor, &d);
}

static void
deleteNodeVisitor(NodeEntry *entry, void *data) {
    deleteEntry(entry);
}

/***********************/
/* Nodestore Lifecycle */
/***********************/

static void
zipNsClear(void *nsCtx) {
    if (!nsCtx)
        return;
    ZipContext *ns = (ZipContext*)nsCtx;
    ZIP_ITER(NodeTreeBin, &ns->root, deleteNodeVisitor, NULL);
    UA_free(ns);

    /* Clear encoded node contents */
    for(size_t i = 0; i < ns->ltSizeRead; i++) {
        UA_NodeId_clear(&ns->ltRead[i].nodeId);
    }
    UA_free(ns->ltRead);
}

UA_StatusCode
UA_Nodestore_BinaryEncoded(UA_Nodestore *ns, const char *const lookupTablePath,
		                   const char *const enocdedBinPath) {
    /* Allocate and initialize the context */
    ZipContext *ctx = (ZipContext*)UA_malloc(sizeof(ZipContext));
    if(!ctx)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    ZIP_INIT(&ctx->root);

    /* Populate the nodestore */
    ns->context = (void*)ctx;
    ns->clear = zipNsClear;
    ns->newNode = zipNsNewNode;
    ns->deleteNode = zipNsDeleteNode;
    ns->getNode = zipNsGetNode;
    ns->releaseNode = zipNsReleaseNode;
    ns->getNodeCopy = zipNsGetNodeCopy;
    ns->insertNode = zipNsInsertNode;
    ns->replaceNode = zipNsReplaceNode;
    ns->removeNode = zipNsRemoveNode;
    ns->iterate = zipNsIterate;

    /* Initialize binary enocded nodes and lookuptable */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Read_Encoded_Binary(&ctx->encodeBin, enocdedBinPath);
    ctx->ltRead = UA_Lookuptable_Initialize(&ctx->ltSizeRead, lookupTablePath);
    UA_Read_LookUpTable(ctx->ltRead, ctx->ltSizeRead, lookupTablePath);

    return retval;
}
#endif

typedef struct {
    UA_ByteString nodeFile;
    size_t nodeFileOffset;
    FILE *tableFile;
    int nodefd;
} DumpFileCtx;

#define NODEFILE_INITSIZE (1024 * 1024)

void *
UA_Nodestore_dumpFileContext_open(const char *table_file, const char *node_file) {
    mode_t mode = S_IRUSR | S_IWUSR;
    int nodefd = open(node_file,  O_RDWR|O_CREAT|O_TRUNC, mode);
    int tablefd = open(table_file,  O_RDWR|O_CREAT|O_TRUNC, mode);
    FILE *tablefp = fdopen(tablefd, "w");
    if(!tablefp || nodefd < 0) {
        fclose(tablefp);
        close(nodefd);
        return NULL;
    }

    DumpFileCtx *dfctx = (DumpFileCtx*)UA_malloc(sizeof(DumpFileCtx));
    fallocate(nodefd, 0, 0, NODEFILE_INITSIZE);
    dfctx->nodeFile.data = (UA_Byte*)
        mmap(NULL, NODEFILE_INITSIZE, PROT_WRITE, MAP_PRIVATE, nodefd, 0);
    dfctx->nodeFile.length = NODEFILE_INITSIZE;
    dfctx->nodeFileOffset = 0;

    dfctx->tableFile = tablefp;
    dfctx->nodefd = nodefd;
    return dfctx;
}

void UA_Nodestore_dumpFileContext_close(void *dumpFileContext) {
    DumpFileCtx *dfctx = (DumpFileCtx*)dumpFileContext;
    munmap(dfctx->nodeFile.data, dfctx->nodeFileOffset);
    ftruncate(dfctx->nodefd, (off_t)dfctx->nodeFileOffset);
    close(dfctx->nodefd);
    fclose(dfctx->tableFile);
    UA_free(dfctx);
}

void
UA_Nodestore_dumpNodeCallback(void *dumpFileContext, const UA_Node *node) {
    DumpFileCtx *dfctx = (DumpFileCtx*)dumpFileContext;

    /* Encode the node */
    size_t nodesize = 0;
    while(true) {
        UA_Byte *bufPos = &dfctx->nodeFile.data[dfctx->nodeFileOffset];
        const UA_Byte *bufEnd = &dfctx->nodeFile.data[dfctx->nodeFile.length];
        UA_StatusCode retval = UA_Node_encodeBinary(node, &bufPos, bufEnd);
        if(retval == UA_STATUSCODE_GOOD) {
            nodesize = (size_t)((uintptr_t)bufPos -
                                (uintptr_t)&dfctx->nodeFile.data[dfctx->nodeFileOffset]);
            break;
        }
        /* Not enough space .. make a larger mmap */
        munmap(dfctx->nodeFile.data, dfctx->nodeFile.length);
        fallocate(dfctx->nodefd, 0,
                  (off_t)dfctx->nodeFile.length, (off_t)dfctx->nodeFile.length);
        dfctx->nodeFile.data = (UA_Byte*)
            mmap(NULL, dfctx->nodeFile.length * 2, PROT_WRITE, MAP_PRIVATE, dfctx->nodefd, 0);
        dfctx->nodeFile.length *= 2;
    }

    /* Debug: Check if we get back the same encoded by decoding first */
    UA_Node *test = UA_Node_decodeBinary(NULL, dfctx->nodeFile, dfctx->nodeFileOffset);
    UA_assert(test);
    deleteEntry(container_of(test, NodeEntry, nodeId));

    /* Encode the table */
    if(node->nodeId.identifierType == UA_NODEIDTYPE_NUMERIC) {
        fprintf(dfctx->tableFile, "%d %u %lu %lu\n",
                node->nodeId.identifierType, node->nodeId.identifier.numeric,
                dfctx->nodeFileOffset, nodesize);
    }
    if(node->nodeId.identifierType == UA_NODEIDTYPE_STRING) {
        fprintf(dfctx->tableFile, "%d %s %lu %lu\n",
                node->nodeId.identifierType, node->nodeId.identifier.string.data,
                dfctx->nodeFileOffset, nodesize);
    }

    /* Forward the offset for the next node */
    dfctx->nodeFileOffset += nodesize;
}
