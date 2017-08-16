/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ua_server_internal.h"
#include "ua_services.h"
#ifdef UA_ENABLE_NONSTANDARD_STATELESS
#include "ua_types_encoding_binary.h"
#endif

/* Force cast from const data for zero-copy reading. The storage type is set to
   nodelete. So the value is not deleted. Use with care! */
static void
forceVariantSetScalar(UA_Variant *v, const void *p, const UA_DataType *t) {
    UA_Variant_init(v);
    v->type = t;
    v->data = (void*)(uintptr_t)p;
    v->storageType = UA_VARIANT_DATA_NODELETE;
}

static UA_UInt32
getUserWriteMask(UA_Server *server, const UA_Session *session,
                 const UA_Node *node) {
    if(session == &adminSession)
        return 0xFFFFFFFF; /* the local admin user has all rights */
    return node->writeMask &
        server->config.accessControl.getUserRightsMask(&session->sessionId,
                                                       session->sessionHandle,
                                                       &node->nodeId);
}

static UA_Byte
getUserAccessLevel(UA_Server *server, const UA_Session *session,
                   const UA_VariableNode *node) {
    if(session == &adminSession)
        return 0xFF; /* the local admin user has all rights */
    return node->accessLevel &
        server->config.accessControl.getUserAccessLevel(&session->sessionId,
                                                        session->sessionHandle,
                                                        &node->nodeId);
}

static UA_Boolean
getUserExecutable(UA_Server *server, const UA_Session *session,
                  const UA_MethodNode *node) {
    if(session == &adminSession)
        return true; /* the local admin user has all rights */
    return node->executable &
        server->config.accessControl.getUserExecutable(&session->sessionId,
                                                       session->sessionHandle,
                                                       &node->nodeId);
}

/*****************/
/* Type Checking */
/*****************/

enum type_equivalence {
    TYPE_EQUIVALENCE_NONE,
    TYPE_EQUIVALENCE_ENUM,
    TYPE_EQUIVALENCE_OPAQUE
};

static enum type_equivalence
typeEquivalence(const UA_DataType *t) {
    if(t->membersSize != 1 || !t->members[0].namespaceZero)
        return TYPE_EQUIVALENCE_NONE;
    if(t->members[0].memberTypeIndex == UA_TYPES_INT32)
        return TYPE_EQUIVALENCE_ENUM;
    if(t->members[0].memberTypeIndex == UA_TYPES_BYTE && t->members[0].isArray)
        return TYPE_EQUIVALENCE_OPAQUE;
    return TYPE_EQUIVALENCE_NONE;
}

UA_Boolean
compatibleDataType(UA_Server *server, const UA_NodeId *dataType,
                   const UA_NodeId *constraintDataType) {
    const UA_NodeId subtypeId = UA_NODEID_NUMERIC(0, UA_NS0ID_HASSUBTYPE);

    /* Do not allow empty datatypes */
    if(UA_NodeId_isNull(dataType))
       return false;

    /* No constraint (TODO: use variant instead) */
    if(UA_NodeId_isNull(constraintDataType))
        return true;

    /* Variant allows any subtype */
    if(UA_NodeId_equal(constraintDataType, &UA_TYPES[UA_TYPES_VARIANT].typeId))
        return true;

    /* Enum allows Int32 (only) */
    UA_NodeId enumNodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_ENUMERATION);
    if(isNodeInTree(&server->config.nodestore, constraintDataType, &enumNodeId, &subtypeId, 1))
        return UA_NodeId_equal(dataType, &UA_TYPES[UA_TYPES_INT32].typeId);

    return isNodeInTree(&server->config.nodestore, dataType, constraintDataType, &subtypeId, 1);
}

/* Test whether a valurank and the given arraydimensions are compatible. zero
 * array dimensions indicate a scalar */
UA_StatusCode
compatibleValueRankArrayDimensions(UA_Int32 valueRank, size_t arrayDimensionsSize) {
    switch(valueRank) {
    case -3: /* the value can be a scalar or a one dimensional array */
        if(arrayDimensionsSize > 1)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        break;
    case -2: /* the value can be a scalar or an array with any number of dimensions */
        break;
    case -1: /* the value is a scalar */
        if(arrayDimensionsSize > 0)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        break;
    case 0: /* the value is an array with one or more dimensions */
        if(arrayDimensionsSize < 1)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        break;
    default: /* >= 1: the value is an array with the specified number of dimensions */
        if(valueRank < 0)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        /* Must hold if the array has a defined length. Null arrays (length -1)
         * need to be caught before. */
        if(arrayDimensionsSize != (size_t)valueRank)
            return UA_STATUSCODE_BADTYPEMISMATCH;
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
compatibleValueRanks(UA_Int32 valueRank, UA_Int32 constraintValueRank) {
    /* Check if the valuerank of the variabletype allows the change. */
    switch(constraintValueRank) {
    case -3: /* the value can be a scalar or a one dimensional array */
        if(valueRank != -1 && valueRank != 1)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        break;
    case -2: /* the value can be a scalar or an array with any number of dimensions */
        break;
    case -1: /* the value is a scalar */
        if(valueRank != -1)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        break;
    case 0: /* the value is an array with one or more dimensions */
        if(valueRank < 0)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        break;
    default: /* >= 1: the value is an array with the specified number of dimensions */
        if(valueRank != constraintValueRank)
            return UA_STATUSCODE_BADTYPEMISMATCH;
        break;
    }
    return UA_STATUSCODE_GOOD;
}

/* Check if the valuerank allows for the value dimension */
static UA_StatusCode
compatibleValueRankValue(UA_Int32 valueRank, const UA_Variant *value) {
    /* empty arrays (-1) always match */
    if(!value->data)
        return UA_STATUSCODE_GOOD;

    size_t arrayDims = value->arrayDimensionsSize;
    if(!UA_Variant_isScalar(value))
        arrayDims = 1; /* array but no arraydimensions -> implicit array dimension 1 */
    return compatibleValueRankArrayDimensions(valueRank, arrayDims);
}

UA_StatusCode
compatibleArrayDimensions(size_t constraintArrayDimensionsSize,
                          const UA_UInt32 *constraintArrayDimensions,
                          size_t testArrayDimensionsSize,
                          const UA_UInt32 *testArrayDimensions) {
    /* No array dimensions defined -> everything is permitted if the value rank fits */
    if(constraintArrayDimensionsSize == 0)
        return UA_STATUSCODE_GOOD;

    /* Dimension count must match */
    if(testArrayDimensionsSize != constraintArrayDimensionsSize)
        return UA_STATUSCODE_BADTYPEMISMATCH;

    /* Dimension lengths must match; zero in the constraint is a wildcard */
    for(size_t i = 0; i < constraintArrayDimensionsSize; ++i) {
        if(constraintArrayDimensions[i] != testArrayDimensions[i] &&
           constraintArrayDimensions[i] != 0)
            return UA_STATUSCODE_BADTYPEMISMATCH;
    }
    return UA_STATUSCODE_GOOD;
}

/* Returns a variant with the pointers of "value" and the content matched to the
 * target type if possible. Sometimes it can be necessary to transform the
 * content of the value, e.g. byte array to bytestring or uint32 to some enum.
 * Returns a straight copy of value when this fails. Careful! The returned
 * DataValue must only be used as long as "value" is still in scope. */
static UA_DataValue
adjustValue(UA_Server *server, const UA_DataValue *value,
            const UA_NodeId *targetDataTypeId) {
    UA_DataValue adjusted = *value;
    adjusted.value.storageType = UA_VARIANT_DATA_NODELETE;
    const UA_DataType *targetDataType = UA_findDataType(targetDataTypeId);
    if(!targetDataType)
        return adjusted;

    /* A string is written to a byte array. the valuerank and array dimensions
     * are checked later */
    if(targetDataType == &UA_TYPES[UA_TYPES_BYTE] &&
       adjusted.value.type == &UA_TYPES[UA_TYPES_BYTESTRING] &&
       UA_Variant_isScalar(&adjusted.value)) {
        UA_ByteString *str = (UA_ByteString*)adjusted.value.data;
        adjusted.value.type = &UA_TYPES[UA_TYPES_BYTE];
        adjusted.value.arrayLength = str->length;
        adjusted.value.data = str->data;
    } else {
        /* An enum was sent as an int32, or an opaque type as a bytestring. This
         * is detected with the typeIndex indicating the "true" datatype. */
        enum type_equivalence te1 = typeEquivalence(targetDataType);
        enum type_equivalence te2 = typeEquivalence(adjusted.value.type);
        if(te1 != TYPE_EQUIVALENCE_NONE && te1 == te2)
            adjusted.value.type = targetDataType;
    }

    /* No more possible equivalencies */
    return adjusted;
}

/* Test whether the value matches a variable definition given by
 * - datatype
 * - valueranke
 * - array dimensions */
UA_StatusCode
typeCheckValue(UA_Server *server, const UA_NodeId *targetDataTypeId,
               UA_Int32 targetValueRank, size_t targetArrayDimensionsSize,
               const UA_UInt32 *targetArrayDimensions, const UA_Variant *value,
               const UA_NumericRange *range) {
    /* Empty variant is only allowed for BaseDataType */
    if(!value->type) {
        if(UA_NodeId_equal(targetDataTypeId, &UA_TYPES[UA_TYPES_VARIANT].typeId) ||
           UA_NodeId_equal(targetDataTypeId, &UA_NODEID_NULL))
            return UA_STATUSCODE_GOOD;
        UA_LOG_INFO(server->config.logger, UA_LOGCATEGORY_SERVER,
                    "Only Variables with data type BaseDataType may contain "
                    "a null (empty) value");
        return UA_STATUSCODE_BADTYPEMISMATCH;
    }

    /* Has the value a subtype of the required type? BaseDataType (Variant) can
     * be anything... */
    if(!compatibleDataType(server, &value->type->typeId, targetDataTypeId))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    /* Array dimensions are checked later when writing the range */
    if(range)
        return UA_STATUSCODE_GOOD;

    size_t valueArrayDimensionsSize = value->arrayDimensionsSize;
    UA_UInt32 *valueArrayDimensions = value->arrayDimensions;
    UA_UInt32 tempArrayDimensions;
    if(valueArrayDimensions == 0 && !UA_Variant_isScalar(value)) {
        valueArrayDimensionsSize = 1;
        tempArrayDimensions = (UA_UInt32)value->arrayLength;
        valueArrayDimensions = &tempArrayDimensions;
    }

    /* See if the array dimensions match. When arrayDimensions are defined, they
     * already match the valuerank. */
    if(targetArrayDimensionsSize > 0)
        return compatibleArrayDimensions(targetArrayDimensionsSize, targetArrayDimensions,
                                         valueArrayDimensionsSize, valueArrayDimensions);

    /* Check if the valuerank allows for the value dimension */
    return compatibleValueRankValue(targetValueRank, value);
}

/*****************************/
/* ArrayDimensions Attribute */
/*****************************/

static UA_StatusCode
readArrayDimensionsAttribute(const UA_VariableNode *vn, UA_DataValue *v) {
    UA_Variant_setArray(&v->value, vn->arrayDimensions,
                        vn->arrayDimensionsSize, &UA_TYPES[UA_TYPES_UINT32]);
    v->value.storageType = UA_VARIANT_DATA_NODELETE;
    v->hasValue = true;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeArrayDimensionsAttribute(UA_Server *server, UA_VariableNode *node,
                              size_t arrayDimensionsSize,
                              UA_UInt32 *arrayDimensions) {
    /* If this is a variabletype, there must be no instances or subtypes of it
     * when we do the change */
    if(node->nodeClass == UA_NODECLASS_VARIABLETYPE &&
       UA_Node_hasSubTypeOrInstances((const UA_Node*)node))
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Check that the array dimensions match with the valuerank */
    UA_StatusCode retval =
        compatibleValueRankArrayDimensions(node->valueRank, arrayDimensionsSize);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_DEBUG(server->config.logger, UA_LOGCATEGORY_SERVER,
                     "The current value rank does not match the new array dimensions");
        return retval;
    }

    /* Get the VariableType */
    const UA_VariableTypeNode *vt = (const UA_VariableTypeNode*)
        getNodeType(server, (UA_Node*)node);
    if(!vt)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Check if the array dimensions match with the wildcards in the
     * variabletype (dimension length 0) */
    if(vt->arrayDimensions)
        retval = compatibleArrayDimensions(vt->arrayDimensionsSize, vt->arrayDimensions,
                                           arrayDimensionsSize, arrayDimensions);

    /* Release the VariableType */
    server->config.nodestore.releaseNode(server->config.nodestore.context,
                                         (const UA_Node*)vt);

    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_DEBUG(server->config.logger, UA_LOGCATEGORY_SERVER,
                     "Array dimensions in the variable type do not match");
        return retval;
    }

    /* Check if the current value is compatible with the array dimensions */
    UA_DataValue value;
    UA_DataValue_init(&value);
    retval = readValueAttribute(server, node, &value);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    if(value.hasValue) {
        retval = compatibleArrayDimensions(arrayDimensionsSize, arrayDimensions,
                                           value.value.arrayDimensionsSize,
                                           value.value.arrayDimensions);
        UA_DataValue_deleteMembers(&value);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_DEBUG(server->config.logger, UA_LOGCATEGORY_SERVER,
                         "Array dimensions in the current value do not match");
            return retval;
        }
    }

    /* Ok, apply */
    UA_UInt32 *oldArrayDimensions = node->arrayDimensions;
    retval = UA_Array_copy(arrayDimensions, arrayDimensionsSize,
                           (void**)&node->arrayDimensions,
                           &UA_TYPES[UA_TYPES_UINT32]);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    UA_free(oldArrayDimensions);
    node->arrayDimensionsSize = arrayDimensionsSize;
    return UA_STATUSCODE_GOOD;
}

/***********************/
/* ValueRank Attribute */
/***********************/

static UA_StatusCode
writeValueRankAttributeWithVT(UA_Server *server, UA_VariableNode *node,
                              UA_Int32 valueRank) {
    const UA_VariableTypeNode *vt = (const UA_VariableTypeNode*)
        getNodeType(server, (UA_Node*)node);
    if(!vt)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = writeValueRankAttribute(server, node, valueRank,
                                                   vt->valueRank);

    server->config.nodestore.releaseNode(server->config.nodestore.context,
                                         (const UA_Node*)vt);
    return retval;
}

UA_StatusCode
writeValueRankAttribute(UA_Server *server, UA_VariableNode *node,
                        UA_Int32 valueRank, UA_Int32 constraintValueRank) {
    /* If this is a variabletype, there must be no instances or subtypes of it
       when we do the change */
    if(node->nodeClass == UA_NODECLASS_VARIABLETYPE &&
       UA_Node_hasSubTypeOrInstances((const UA_Node*)node))
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Check if the valuerank of the variabletype allows the change. */
    UA_StatusCode retval = compatibleValueRanks(valueRank, constraintValueRank);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Check if the new valuerank is compatible with the array dimensions. Use
     * the read service to handle data sources. */
    size_t arrayDims = node->arrayDimensionsSize;
    if(arrayDims == 0) {
        /* the value could be an array with no arrayDimensions defined.
           dimensions zero indicate a scalar for compatibleValueRankArrayDimensions. */
        UA_DataValue value;
        UA_DataValue_init(&value);
        retval = readValueAttribute(server, node, &value);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        if(!value.hasValue || !value.value.type) {
            /* no value -> apply */
            node->valueRank = valueRank;
            return UA_STATUSCODE_GOOD;
        }
        if(!UA_Variant_isScalar(&value.value))
            arrayDims = 1;
        UA_DataValue_deleteMembers(&value);
    }
    retval = compatibleValueRankArrayDimensions(valueRank, arrayDims);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* All good, apply the change */
    node->valueRank = valueRank;
    return UA_STATUSCODE_GOOD;
}

/**********************/
/* DataType Attribute */
/**********************/

static UA_StatusCode
writeDataTypeAttribute(UA_Server *server, UA_VariableNode *node,
                       const UA_NodeId *dataType,
                       const UA_NodeId *constraintDataType) {
    /* If this is a variabletype, there must be no instances or subtypes of it
       when we do the change */
    if(node->nodeClass == UA_NODECLASS_VARIABLETYPE &&
       UA_Node_hasSubTypeOrInstances((const UA_Node*)node))
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Does the new type match the constraints of the variabletype? */
    if(!compatibleDataType(server, dataType, constraintDataType))
        return UA_STATUSCODE_BADTYPEMISMATCH;

    /* Check if the current value would match the new type */
    UA_DataValue value;
    UA_DataValue_init(&value);
    UA_StatusCode retval = readValueAttribute(server, node, &value);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    if(value.hasValue) {
        retval = typeCheckValue(server, dataType, node->valueRank,
                                node->arrayDimensionsSize, node->arrayDimensions,
                                &value.value, NULL);
        UA_DataValue_deleteMembers(&value);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_DEBUG(server->config.logger, UA_LOGCATEGORY_SERVER,
                         "The current value does not match the new data type");
            return retval;
        }
    }

    /* Replace the datatype nodeid */
    UA_NodeId dtCopy = node->dataType;
    retval = UA_NodeId_copy(dataType, &node->dataType);
    if(retval != UA_STATUSCODE_GOOD) {
        node->dataType = dtCopy;
        return retval;
    }
    UA_NodeId_deleteMembers(&dtCopy);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeDataTypeAttributeWithVT(UA_Server *server, UA_VariableNode *node,
                             const UA_NodeId *dataType) {
    const UA_VariableTypeNode *vt = (const UA_VariableTypeNode*)
        getNodeType(server, (UA_Node*)node);
    if(!vt)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = writeDataTypeAttribute(server, node, dataType,
                                                  &vt->dataType);

    server->config.nodestore.releaseNode(server->config.nodestore.context,
                                         (const UA_Node*)vt);
    return retval;
}

/*******************/
/* Value Attribute */
/*******************/

static UA_StatusCode
readValueAttributeFromNode(UA_Server *server, const UA_VariableNode *vn,
                           UA_DataValue *v, UA_NumericRange *rangeptr) {
    if(vn->value.data.callback.onRead) {
        vn->value.data.callback.onRead(vn->value.data.callback.handle,
                                       vn->nodeId, &vn->value.data.value.value, rangeptr);
#ifdef UA_ENABLE_MULTITHREADING
        /* Reopen the node to see the changes (multithreading only) */
        vn = (const UA_VariableNode*)UA_NodeStore_get(server->nodestore, &vn->nodeId);
#endif
    }
    if(rangeptr)
        return UA_Variant_copyRange(&vn->value.data.value.value, &v->value, *rangeptr);
    *v = vn->value.data.value;
    v->value.storageType = UA_VARIANT_DATA_NODELETE;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
readValueAttributeFromDataSource(const UA_VariableNode *vn, UA_DataValue *v,
                                 UA_TimestampsToReturn timestamps,
                                 UA_NumericRange *rangeptr) {
    if(!vn->value.dataSource.read)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_Boolean sourceTimeStamp = (timestamps == UA_TIMESTAMPSTORETURN_SOURCE ||
                                  timestamps == UA_TIMESTAMPSTORETURN_BOTH);
    UA_StatusCode retval =
        vn->value.dataSource.read(vn->value.dataSource.handle, vn->nodeId,
                                  sourceTimeStamp, rangeptr, v);
    return retval;
}

static UA_StatusCode
readValueAttributeComplete(UA_Server *server, const UA_VariableNode *vn,
                           UA_TimestampsToReturn timestamps,
                           const UA_String *indexRange,
                           UA_DataValue *v) {
    /* Compute the index range */
    UA_NumericRange range;
    UA_NumericRange *rangeptr = NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(indexRange && indexRange->length > 0) {
        retval = UA_NumericRange_parseFromString(&range, indexRange);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        rangeptr = &range;
    }

    /* Read the value */
    if(vn->valueSource == UA_VALUESOURCE_DATA)
        retval = readValueAttributeFromNode(server, vn, v, rangeptr);
    else
        retval = readValueAttributeFromDataSource(vn, v, timestamps, rangeptr);

    /* Clean up */
    if(rangeptr)
        UA_free(range.dimensions);
    return retval;
}

UA_StatusCode
readValueAttribute(UA_Server *server, const UA_VariableNode *vn,
                   UA_DataValue *v) {
    return readValueAttributeComplete(server, vn, UA_TIMESTAMPSTORETURN_NEITHER,
                                      NULL, v);
}

static UA_StatusCode
writeValueAttributeWithoutRange(UA_VariableNode *node, const UA_DataValue *value) {
    UA_DataValue old_value = node->value.data.value; /* keep the pointers for restoring */
    UA_StatusCode retval = UA_DataValue_copy(value, &node->value.data.value);
    if(retval == UA_STATUSCODE_GOOD)
        UA_DataValue_deleteMembers(&old_value);
    else
        node->value.data.value = old_value;
    return retval;
}

static UA_StatusCode
writeValueAttributeWithRange(UA_VariableNode *node, const UA_DataValue *value,
                             const UA_NumericRange *rangeptr) {
    /* Value on both sides? */
    if(value->status != node->value.data.value.status ||
       !value->hasValue || !node->value.data.value.hasValue)
        return UA_STATUSCODE_BADINDEXRANGEINVALID;

    /* Make scalar a one-entry array for range matching */
    UA_Variant editableValue;
    const UA_Variant *v = &value->value;
    if(UA_Variant_isScalar(&value->value)) {
        editableValue = value->value;
        editableValue.arrayLength = 1;
        v = &editableValue;
    }

    /* Write the value */
    UA_StatusCode retval = UA_Variant_setRangeCopy(&node->value.data.value.value,
                                                   v->data, v->arrayLength, *rangeptr);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Write the status and timestamps */
    node->value.data.value.hasStatus = value->hasStatus;
    node->value.data.value.status = value->status;
    node->value.data.value.hasSourceTimestamp = value->hasSourceTimestamp;
    node->value.data.value.sourceTimestamp = value->sourceTimestamp;
    node->value.data.value.hasSourcePicoseconds = value->hasSourcePicoseconds;
    node->value.data.value.sourcePicoseconds = value->sourcePicoseconds;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeValueAttribute(UA_Server *server, UA_VariableNode *node,
                    const UA_DataValue *value, const UA_String *indexRange) {
    /* Parse the range */
    UA_NumericRange range;
    UA_NumericRange *rangeptr = NULL;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(indexRange && indexRange->length > 0) {
        retval = UA_NumericRange_parseFromString(&range, indexRange);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        rangeptr = &range;
    }

    /* Make a shallow copy with adjustments if necessary */
    UA_DataValue adjustedValue = adjustValue(server, value, &node->dataType);

    /* Type checking. May change the type of editableValue */
    if(value->hasValue) {
        retval = typeCheckValue(server, &node->dataType, node->valueRank,
                                node->arrayDimensionsSize, node->arrayDimensions,
                                &value->value, rangeptr);
        if(retval != UA_STATUSCODE_GOOD) {
            if(rangeptr)
                UA_free(range.dimensions);
            return retval;
        }
    }

    /* Set the source timestamp if there is none */
    if(!adjustedValue.hasSourceTimestamp) {
        adjustedValue.sourceTimestamp = UA_DateTime_now();
        adjustedValue.hasSourceTimestamp = true;
    }

    /* Ok, do it */
    if(node->valueSource == UA_VALUESOURCE_DATA) {
        if(!rangeptr)
            retval = writeValueAttributeWithoutRange(node, &adjustedValue);
        else
            retval = writeValueAttributeWithRange(node, &adjustedValue, rangeptr);

        /* Callback after writing */
        if(retval == UA_STATUSCODE_GOOD && node->value.data.callback.onWrite) {
            const UA_VariableNode *writtenNode = (const UA_VariableNode*)
                server->config.nodestore.getNode(server->config.nodestore.context, &node->nodeId);
            if(writtenNode && writtenNode->value.data.callback.onWrite)
                writtenNode->value.data.callback.onWrite(writtenNode->value.data.callback.handle,
                                   writtenNode->nodeId, &writtenNode->value.data.value.value, rangeptr);
            server->config.nodestore.releaseNode(server->config.nodestore.context,
                                                 (const UA_Node*)writtenNode);
        }
    } else {
        if(node->value.dataSource.write) {
            retval = node->value.dataSource.write(node->value.dataSource.handle,
                                      node->nodeId, &adjustedValue.value, rangeptr);
        } else {
            retval = UA_STATUSCODE_BADWRITENOTSUPPORTED;
        }
    }

    /* Clean up */
    if(rangeptr)
        UA_free(range.dimensions);
    return retval;
}

/************************/
/* IsAbstract Attribute */
/************************/

static UA_StatusCode
readIsAbstractAttribute(const UA_Node *node, UA_Variant *v) {
    const UA_Boolean *isAbstract;
    switch(node->nodeClass) {
    case UA_NODECLASS_REFERENCETYPE:
        isAbstract = &((const UA_ReferenceTypeNode*)node)->isAbstract;
        break;
    case UA_NODECLASS_OBJECTTYPE:
        isAbstract = &((const UA_ObjectTypeNode*)node)->isAbstract;
        break;
    case UA_NODECLASS_VARIABLETYPE:
        isAbstract = &((const UA_VariableTypeNode*)node)->isAbstract;
        break;
    case UA_NODECLASS_DATATYPE:
        isAbstract = &((const UA_DataTypeNode*)node)->isAbstract;
        break;
    default:
        return UA_STATUSCODE_BADATTRIBUTEIDINVALID;
    }
    forceVariantSetScalar(v, isAbstract, &UA_TYPES[UA_TYPES_BOOLEAN]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
writeIsAbstractAttribute(UA_Node *node, UA_Boolean value) {
    switch(node->nodeClass) {
    case UA_NODECLASS_OBJECTTYPE:
        ((UA_ObjectTypeNode*)node)->isAbstract = value;
        break;
    case UA_NODECLASS_REFERENCETYPE:
        ((UA_ReferenceTypeNode*)node)->isAbstract = value;
        break;
    case UA_NODECLASS_VARIABLETYPE:
        ((UA_VariableTypeNode*)node)->isAbstract = value;
        break;
    case UA_NODECLASS_DATATYPE:
        ((UA_DataTypeNode*)node)->isAbstract = value;
        break;
    default:
        return UA_STATUSCODE_BADNODECLASSINVALID;
    }
    return UA_STATUSCODE_GOOD;
}

/****************/
/* Read Service */
/****************/

static const UA_String binEncoding = {sizeof("Default Binary")-1, (UA_Byte*)"Default Binary"};
/* static const UA_String xmlEncoding = {sizeof("Default Xml")-1, (UA_Byte*)"Default Xml"}; */

/* Thread-local variables to pass additional arguments into the operation */
static UA_THREAD_LOCAL UA_TimestampsToReturn op_timestampsToReturn;

#define CHECK_NODECLASS(CLASS)                                  \
    if(!(node->nodeClass & (CLASS))) {                          \
        retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;           \
        break;                                                  \
    }

static void
Operation_Read(UA_Server *server, UA_Session *session,
               const UA_ReadValueId *id, UA_DataValue *v) {
    UA_LOG_DEBUG_SESSION(server->config.logger, session,
                         "Read the attribute %i", id->attributeId);

    /* XML encoding is not supported */
    if(id->dataEncoding.name.length > 0 &&
       !UA_String_equal(&binEncoding, &id->dataEncoding.name)) {
           v->hasStatus = true;
           v->status = UA_STATUSCODE_BADDATAENCODINGUNSUPPORTED;
           return;
    }

    /* Index range for an attribute other than value */
    if(id->indexRange.length > 0 && id->attributeId != UA_ATTRIBUTEID_VALUE) {
        v->hasStatus = true;
        v->status = UA_STATUSCODE_BADINDEXRANGENODATA;
        return;
    }

    /* Get the node */
    const UA_Node *node =
        server->config.nodestore.getNode(server->config.nodestore.context, &id->nodeId);
    if(!node) {
        v->hasStatus = true;
        v->status = UA_STATUSCODE_BADNODEIDUNKNOWN;
        return;
    }

    /* Read the attribute */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    switch(id->attributeId) {
    case UA_ATTRIBUTEID_NODEID:
        forceVariantSetScalar(&v->value, &node->nodeId, &UA_TYPES[UA_TYPES_NODEID]);
        break;
    case UA_ATTRIBUTEID_NODECLASS:
        forceVariantSetScalar(&v->value, &node->nodeClass, &UA_TYPES[UA_TYPES_NODECLASS]);
        break;
    case UA_ATTRIBUTEID_BROWSENAME:
        forceVariantSetScalar(&v->value, &node->browseName, &UA_TYPES[UA_TYPES_QUALIFIEDNAME]);
        break;
    case UA_ATTRIBUTEID_DISPLAYNAME:
        forceVariantSetScalar(&v->value, &node->displayName, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        break;
    case UA_ATTRIBUTEID_DESCRIPTION:
        forceVariantSetScalar(&v->value, &node->description, &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        break;
    case UA_ATTRIBUTEID_WRITEMASK:
        forceVariantSetScalar(&v->value, &node->writeMask, &UA_TYPES[UA_TYPES_UINT32]);
        break;
    case UA_ATTRIBUTEID_USERWRITEMASK: {
        UA_UInt32 userWriteMask = getUserWriteMask(server, session, node);
        UA_Variant_setScalarCopy(&v->value, &userWriteMask, &UA_TYPES[UA_TYPES_UINT32]);
        break; }
    case UA_ATTRIBUTEID_ISABSTRACT:
        retval = readIsAbstractAttribute(node, &v->value);
        break;
    case UA_ATTRIBUTEID_SYMMETRIC:
        CHECK_NODECLASS(UA_NODECLASS_REFERENCETYPE);
        forceVariantSetScalar(&v->value, &((const UA_ReferenceTypeNode*)node)->symmetric,
                              &UA_TYPES[UA_TYPES_BOOLEAN]);
        break;
    case UA_ATTRIBUTEID_INVERSENAME:
        CHECK_NODECLASS(UA_NODECLASS_REFERENCETYPE);
        forceVariantSetScalar(&v->value, &((const UA_ReferenceTypeNode*)node)->inverseName,
                              &UA_TYPES[UA_TYPES_LOCALIZEDTEXT]);
        break;
    case UA_ATTRIBUTEID_CONTAINSNOLOOPS:
        CHECK_NODECLASS(UA_NODECLASS_VIEW);
        forceVariantSetScalar(&v->value, &((const UA_ViewNode*)node)->containsNoLoops,
                              &UA_TYPES[UA_TYPES_BOOLEAN]);
        break;
    case UA_ATTRIBUTEID_EVENTNOTIFIER:
        CHECK_NODECLASS(UA_NODECLASS_VIEW | UA_NODECLASS_OBJECT);
        forceVariantSetScalar(&v->value, &((const UA_ViewNode*)node)->eventNotifier,
                              &UA_TYPES[UA_TYPES_BYTE]);
        break;
    case UA_ATTRIBUTEID_VALUE: {
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        UA_Byte userAccessLevel = getUserAccessLevel(server, session,
                                                     (const UA_VariableNode*)node);
        if(!(userAccessLevel & (UA_ACCESSLEVELMASK_READ))) {
            retval = UA_STATUSCODE_BADUSERACCESSDENIED;
            break;
        }
        retval = readValueAttributeComplete(server, (const UA_VariableNode*)node,
                                            op_timestampsToReturn, &id->indexRange, v);
        break;
    }
    case UA_ATTRIBUTEID_DATATYPE:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        forceVariantSetScalar(&v->value, &((const UA_VariableTypeNode*)node)->dataType,
                              &UA_TYPES[UA_TYPES_NODEID]);
        break;
    case UA_ATTRIBUTEID_VALUERANK:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        forceVariantSetScalar(&v->value, &((const UA_VariableTypeNode*)node)->valueRank,
                              &UA_TYPES[UA_TYPES_INT32]);
        break;
    case UA_ATTRIBUTEID_ARRAYDIMENSIONS:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        retval = readArrayDimensionsAttribute((const UA_VariableNode*)node, v);
        break;
    case UA_ATTRIBUTEID_ACCESSLEVEL:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        forceVariantSetScalar(&v->value, &((const UA_VariableNode*)node)->accessLevel,
                              &UA_TYPES[UA_TYPES_BYTE]);
        break;
    case UA_ATTRIBUTEID_USERACCESSLEVEL: {
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        UA_Byte userAccessLevel = getUserAccessLevel(server, session,
                                                     (const UA_VariableNode*)node);
        UA_Variant_setScalarCopy(&v->value, &userAccessLevel, &UA_TYPES[UA_TYPES_BYTE]);
        break; }
    case UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        forceVariantSetScalar(&v->value, &((const UA_VariableNode*)node)->minimumSamplingInterval,
                              &UA_TYPES[UA_TYPES_DOUBLE]);
        break;
    case UA_ATTRIBUTEID_HISTORIZING:
        CHECK_NODECLASS(UA_NODECLASS_VARIABLE);
        forceVariantSetScalar(&v->value, &((const UA_VariableNode*)node)->historizing,
                              &UA_TYPES[UA_TYPES_BOOLEAN]);
        break;
    case UA_ATTRIBUTEID_EXECUTABLE:
        CHECK_NODECLASS(UA_NODECLASS_METHOD);
        forceVariantSetScalar(&v->value, &((const UA_MethodNode*)node)->executable,
                              &UA_TYPES[UA_TYPES_BOOLEAN]);
        break;
    case UA_ATTRIBUTEID_USEREXECUTABLE: {
        CHECK_NODECLASS(UA_NODECLASS_METHOD);
        UA_Boolean userExecutable = getUserExecutable(server, session,
                                                      (const UA_MethodNode*)node);
        UA_Variant_setScalarCopy(&v->value, &userExecutable, &UA_TYPES[UA_TYPES_BOOLEAN]);
        break; }
    default:
        retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;
    }

    /* Release the node */
    server->config.nodestore.releaseNode(server->config.nodestore.context, node);

    /* Return error code when reading has failed */
    if(retval != UA_STATUSCODE_GOOD) {
        v->hasStatus = true;
        v->status = retval;
        return;
    }

    v->hasValue = true;

    /* Create server timestamp */
    if(op_timestampsToReturn == UA_TIMESTAMPSTORETURN_SERVER ||
       op_timestampsToReturn == UA_TIMESTAMPSTORETURN_BOTH) {
        v->serverTimestamp = UA_DateTime_now();
        v->hasServerTimestamp = true;
    }

    /* Handle source time stamp */
    if(id->attributeId == UA_ATTRIBUTEID_VALUE) {
        if(op_timestampsToReturn == UA_TIMESTAMPSTORETURN_SERVER ||
           op_timestampsToReturn == UA_TIMESTAMPSTORETURN_NEITHER) {
            v->hasSourceTimestamp = false;
            v->hasSourcePicoseconds = false;
        } else if(!v->hasSourceTimestamp) {
            v->sourceTimestamp = UA_DateTime_now();
            v->hasSourceTimestamp = true;
        }
    }
}

void Service_Read(UA_Server *server, UA_Session *session,
                  const UA_ReadRequest *request, UA_ReadResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logger, session,
                         "Processing ReadRequest");

    /* Check if the timestampstoreturn is valid */
    op_timestampsToReturn = request->timestampsToReturn;
    if(op_timestampsToReturn > UA_TIMESTAMPSTORETURN_NEITHER) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADTIMESTAMPSTORETURNINVALID;
        return;
    }

    /* Check if maxAge is valid */
    if(request->maxAge < 0) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADMAXAGEINVALID;
        return;
    }

    response->responseHeader.serviceResult = 
        UA_Server_processServiceOperations(server, session,
                  (UA_ServiceOperation)Operation_Read,
                  &request->nodesToReadSize, &UA_TYPES[UA_TYPES_READVALUEID],
                  &response->resultsSize, &UA_TYPES[UA_TYPES_DATAVALUE]);

#ifdef UA_ENABLE_NONSTANDARD_STATELESS
    /* Add an expiry header for caching */
    if(session->sessionId.namespaceIndex == 0 &&
       session->sessionId.identifierType == UA_NODEIDTYPE_NUMERIC &&
       session->sessionId.identifier.numeric == 0) {
        UA_ExtensionObject additionalHeader;
        UA_ExtensionObject_init(&additionalHeader);
        additionalHeader.encoding = UA_EXTENSIONOBJECT_ENCODED_BYTESTRING;
        additionalHeader.content.encoded.typeId =UA_TYPES[UA_TYPES_VARIANT].typeId;

        UA_Variant variant;
        UA_Variant_init(&variant);

        UA_DateTime* expireArray = NULL;
        expireArray = UA_Array_new(request->nodesToReadSize,
                                   &UA_TYPES[UA_TYPES_DATETIME]);
        variant.data = expireArray;

        /* expires in 20 seconds */
        for(UA_UInt32 i = 0;i < response->resultsSize;++i) {
            expireArray[i] = UA_DateTime_now() + 20 * 100 * 1000 * 1000;
        }
        UA_Variant_setArray(&variant, expireArray, request->nodesToReadSize,
                            &UA_TYPES[UA_TYPES_DATETIME]);

        size_t offset = 0;
        UA_ByteString str;
        size_t strlength = UA_calcSizeBinary(&variant, &UA_TYPES[UA_TYPES_VARIANT]);
        UA_ByteString_allocBuffer(&str, strlength);
        /* No chunking callback for the encoding */
        UA_StatusCode retval = UA_encodeBinary(&variant, &UA_TYPES[UA_TYPES_VARIANT],
                                               NULL, NULL, &str, &offset);
        UA_Array_delete(expireArray, request->nodesToReadSize, &UA_TYPES[UA_TYPES_DATETIME]);
        if(retval == UA_STATUSCODE_GOOD){
            additionalHeader.content.encoded.body.data = str.data;
            additionalHeader.content.encoded.body.length = offset;
            response->responseHeader.additionalHeader = additionalHeader;
        }
    }
#endif
}

UA_DataValue
UA_Server_readWithSession(UA_Server *server, UA_Session *session,
                          const UA_ReadValueId *item,
                          UA_TimestampsToReturn timestamps) {
    UA_DataValue dv;
    UA_DataValue_init(&dv);
    op_timestampsToReturn = timestamps;
    Operation_Read(server, session, item, &dv);
    return dv;
}

/* Exposes the Read service to local users */
UA_DataValue
UA_Server_read(UA_Server *server, const UA_ReadValueId *item,
               UA_TimestampsToReturn timestamps) {
    return UA_Server_readWithSession(server, &adminSession, item, timestamps);
}

/* Used in inline functions exposing the Read service with more syntactic sugar
 * for individual attributes */
UA_StatusCode
__UA_Server_read(UA_Server *server, const UA_NodeId *nodeId,
                 const UA_AttributeId attributeId, void *v) {
    /* Call the read service */
    UA_ReadValueId item;
    UA_ReadValueId_init(&item);
    item.nodeId = *nodeId;
    item.attributeId = attributeId;
    UA_DataValue dv = UA_Server_read(server, &item, UA_TIMESTAMPSTORETURN_NEITHER);

    /* Check the return value */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(dv.hasStatus)
        retval = dv.hasStatus;
    else if(!dv.hasValue)
        retval = UA_STATUSCODE_BADUNEXPECTEDERROR;
    if(retval != UA_STATUSCODE_GOOD) {
        UA_DataValue_deleteMembers(&dv);
        return retval;
    }

    /* Prepare the result */
    if(attributeId == UA_ATTRIBUTEID_VALUE ||
       attributeId == UA_ATTRIBUTEID_ARRAYDIMENSIONS) {
        /* Return the entire variant */
        if(dv.value.storageType == UA_VARIANT_DATA_NODELETE) {
            retval = UA_Variant_copy(&dv.value, (UA_Variant*)v);
        } else {
            /* storageType is UA_VARIANT_DATA. Copy the entire variant
             * (including pointers and all) */
            memcpy(v, &dv.value, sizeof(UA_Variant));
        }
    } else {
        /* Return the variant content only */
        if(dv.value.storageType == UA_VARIANT_DATA_NODELETE) {
            retval = UA_copy(dv.value.data, v, dv.value.type);
        } else {
            /* storageType is UA_VARIANT_DATA. Copy the content of the type
             * (including pointers and all) */
            memcpy(v, dv.value.data, dv.value.type->memSize);
            /* Delete the "carrier" in the variant */
            UA_free(dv.value.data);
        }
    }
    return retval;
}

/*****************/
/* Write Service */
/*****************/

#define CHECK_DATATYPE_SCALAR(EXP_DT)                                   \
    if(!wvalue->value.hasValue ||                                       \
       &UA_TYPES[UA_TYPES_##EXP_DT] != wvalue->value.value.type ||      \
       !UA_Variant_isScalar(&wvalue->value.value)) {                    \
        retval = UA_STATUSCODE_BADTYPEMISMATCH;                         \
        break;                                                          \
    }

#define CHECK_DATATYPE_ARRAY(EXP_DT)                                    \
    if(!wvalue->value.hasValue ||                                       \
       &UA_TYPES[UA_TYPES_##EXP_DT] != wvalue->value.value.type ||      \
       UA_Variant_isScalar(&wvalue->value.value)) {                     \
        retval = UA_STATUSCODE_BADTYPEMISMATCH;                         \
        break;                                                          \
    }

#define CHECK_NODECLASS_WRITE(CLASS)                                    \
    if((node->nodeClass & (CLASS)) == 0) {                              \
        retval = UA_STATUSCODE_BADNODECLASSINVALID;                     \
        break;                                                          \
    }

#define CHECK_USERWRITEMASK(mask)                           \
    if(!(userWriteMask & (mask))) {                         \
        retval = UA_STATUSCODE_BADUSERACCESSDENIED;         \
        break;                                              \
    }

/* This function implements the main part of the write service and operates on a
   copy of the node (not in single-threaded mode). */
static UA_StatusCode
copyAttributeIntoNode(UA_Server *server, UA_Session *session,
                      UA_Node *node, const UA_WriteValue *wvalue) {
    const void *value = wvalue->value.value.data;
    UA_UInt32 userWriteMask = getUserWriteMask(server, session, node);
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    switch(wvalue->attributeId) {
    case UA_ATTRIBUTEID_NODEID:
    case UA_ATTRIBUTEID_NODECLASS:
    case UA_ATTRIBUTEID_USERWRITEMASK:
    case UA_ATTRIBUTEID_USERACCESSLEVEL:
    case UA_ATTRIBUTEID_USEREXECUTABLE:
        retval = UA_STATUSCODE_BADWRITENOTSUPPORTED;
        break;
    case UA_ATTRIBUTEID_BROWSENAME:
        CHECK_USERWRITEMASK(UA_WRITEMASK_BROWSENAME);
        CHECK_DATATYPE_SCALAR(QUALIFIEDNAME);
        UA_QualifiedName_deleteMembers(&node->browseName);
        UA_QualifiedName_copy((const UA_QualifiedName *)value, &node->browseName);
        break;
    case UA_ATTRIBUTEID_DISPLAYNAME:
        CHECK_USERWRITEMASK(UA_WRITEMASK_DISPLAYNAME);
        CHECK_DATATYPE_SCALAR(LOCALIZEDTEXT);
        UA_LocalizedText_deleteMembers(&node->displayName);
        UA_LocalizedText_copy((const UA_LocalizedText *)value, &node->displayName);
        break;
    case UA_ATTRIBUTEID_DESCRIPTION:
        CHECK_USERWRITEMASK(UA_WRITEMASK_DESCRIPTION);
        CHECK_DATATYPE_SCALAR(LOCALIZEDTEXT);
        UA_LocalizedText_deleteMembers(&node->description);
        UA_LocalizedText_copy((const UA_LocalizedText *)value, &node->description);
        break;
    case UA_ATTRIBUTEID_WRITEMASK:
        CHECK_USERWRITEMASK(UA_WRITEMASK_WRITEMASK);
        CHECK_DATATYPE_SCALAR(UINT32);
        node->writeMask = *(const UA_UInt32*)value;
        break;
    case UA_ATTRIBUTEID_ISABSTRACT:
        CHECK_USERWRITEMASK(UA_WRITEMASK_ISABSTRACT);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        retval = writeIsAbstractAttribute(node, *(const UA_Boolean*)value);
        break;
    case UA_ATTRIBUTEID_SYMMETRIC:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_REFERENCETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_SYMMETRIC);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        ((UA_ReferenceTypeNode*)node)->symmetric = *(const UA_Boolean*)value;
        break;
    case UA_ATTRIBUTEID_INVERSENAME:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_REFERENCETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_INVERSENAME);
        CHECK_DATATYPE_SCALAR(LOCALIZEDTEXT);
        UA_LocalizedText_deleteMembers(&((UA_ReferenceTypeNode*)node)->inverseName);
        UA_LocalizedText_copy((const UA_LocalizedText *)value,
                              &((UA_ReferenceTypeNode*)node)->inverseName);
        break;
    case UA_ATTRIBUTEID_CONTAINSNOLOOPS:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VIEW);
        CHECK_USERWRITEMASK(UA_WRITEMASK_CONTAINSNOLOOPS);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        ((UA_ViewNode*)node)->containsNoLoops = *(const UA_Boolean*)value;
        break;
    case UA_ATTRIBUTEID_EVENTNOTIFIER:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VIEW | UA_NODECLASS_OBJECT);
        CHECK_USERWRITEMASK(UA_WRITEMASK_EVENTNOTIFIER);
        CHECK_DATATYPE_SCALAR(BYTE);
        ((UA_ViewNode*)node)->eventNotifier = *(const UA_Byte*)value;
        break;
    case UA_ATTRIBUTEID_VALUE:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        if(node->nodeClass == UA_NODECLASS_VARIABLE) {
            /* The access to a value variable is granted via the AccessLevel Byte */
            UA_Byte userAccessLevel = getUserAccessLevel(server, session,
                                                         (const UA_VariableNode*)node);
            if(!(userAccessLevel & (UA_ACCESSLEVELMASK_WRITE))) {
                retval = UA_STATUSCODE_BADUSERACCESSDENIED;
                break;
            }
        } else { /* UA_NODECLASS_VARIABLETYPE */
            CHECK_USERWRITEMASK(UA_WRITEMASK_VALUEFORVARIABLETYPE);
        }
        retval = writeValueAttribute(server, (UA_VariableNode*)node,
                                     &wvalue->value, &wvalue->indexRange);
        break;
    case UA_ATTRIBUTEID_DATATYPE:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_DATATYPE);
        CHECK_DATATYPE_SCALAR(NODEID);
        retval = writeDataTypeAttributeWithVT(server, (UA_VariableNode*)node,
                                              (const UA_NodeId*)value);
        break;
    case UA_ATTRIBUTEID_VALUERANK:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_VALUERANK);
        CHECK_DATATYPE_SCALAR(INT32);
        retval = writeValueRankAttributeWithVT(server, (UA_VariableNode*)node,
                                               *(const UA_Int32*)value);
        break;
    case UA_ATTRIBUTEID_ARRAYDIMENSIONS:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE | UA_NODECLASS_VARIABLETYPE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_ARRRAYDIMENSIONS);
        CHECK_DATATYPE_ARRAY(UINT32);
        retval = writeArrayDimensionsAttribute(server, (UA_VariableNode*)node,
                                               wvalue->value.value.arrayLength,
                                               (UA_UInt32 *)wvalue->value.value.data);
        break;
    case UA_ATTRIBUTEID_ACCESSLEVEL:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_ACCESSLEVEL);
        CHECK_DATATYPE_SCALAR(BYTE);
        ((UA_VariableNode*)node)->accessLevel = *(const UA_Byte*)value;
        break;
    case UA_ATTRIBUTEID_MINIMUMSAMPLINGINTERVAL:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_MINIMUMSAMPLINGINTERVAL);
        CHECK_DATATYPE_SCALAR(DOUBLE);
        ((UA_VariableNode*)node)->minimumSamplingInterval = *(const UA_Double*)value;
        break;
    case UA_ATTRIBUTEID_HISTORIZING:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_VARIABLE);
        CHECK_USERWRITEMASK(UA_WRITEMASK_HISTORIZING);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        ((UA_VariableNode*)node)->historizing = *(const UA_Boolean*)value;
        break;
    case UA_ATTRIBUTEID_EXECUTABLE:
        CHECK_NODECLASS_WRITE(UA_NODECLASS_METHOD);
        CHECK_USERWRITEMASK(UA_WRITEMASK_EXECUTABLE);
        CHECK_DATATYPE_SCALAR(BOOLEAN);
        ((UA_MethodNode*)node)->executable = *(const UA_Boolean*)value;
        break;
    default:
        retval = UA_STATUSCODE_BADATTRIBUTEIDINVALID;
        break;
    }
    if(retval != UA_STATUSCODE_GOOD)
        UA_LOG_INFO_SESSION(server->config.logger, session,
                            "WriteRequest returned status code %s",
                            UA_StatusCode_name(retval));
    return retval;
}

static void
Operation_Write(UA_Server *server, UA_Session *session,
                UA_WriteValue *wv, UA_StatusCode *result) {
    *result = UA_Server_editNode(server, session, &wv->nodeId,
                        (UA_EditNodeCallback)copyAttributeIntoNode, wv);
}

void
Service_Write(UA_Server *server, UA_Session *session,
              const UA_WriteRequest *request,
              UA_WriteResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logger, session,
                         "Processing WriteRequest");

    response->responseHeader.serviceResult = 
        UA_Server_processServiceOperations(server, session,
                  (UA_ServiceOperation)Operation_Write,
                  &request->nodesToWriteSize, &UA_TYPES[UA_TYPES_WRITEVALUE],
                  &response->resultsSize, &UA_TYPES[UA_TYPES_STATUSCODE]);
}

UA_StatusCode
UA_Server_write(UA_Server *server, const UA_WriteValue *value) {
    UA_StatusCode retval =
        UA_Server_editNode(server, &adminSession, &value->nodeId,
                  (UA_EditNodeCallback)copyAttributeIntoNode, value);
    return retval;
}

/* Convenience function to be wrapped into inline functions */
UA_StatusCode
__UA_Server_write(UA_Server *server, const UA_NodeId *nodeId,
                  const UA_AttributeId attributeId,
                  const UA_DataType *attr_type,
                  const void *attr) {
    UA_WriteValue wvalue;
    UA_WriteValue_init(&wvalue);
    wvalue.nodeId = *nodeId;
    wvalue.attributeId = attributeId;
    wvalue.value.hasValue = true;
    if(attr_type != &UA_TYPES[UA_TYPES_VARIANT]) {
        /* hacked cast. the target WriteValue is used as const anyway */
        UA_Variant_setScalar(&wvalue.value.value,
                             (void*)(uintptr_t)attr, attr_type);
    } else {
        wvalue.value.value = *(const UA_Variant*)attr;
    }
    return UA_Server_write(server, &wvalue);
}
