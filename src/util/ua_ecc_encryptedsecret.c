/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2025 (c) Siemens AG (Author: Tin Raic)
 */

#include "ua_ecc_encryptedsecret.h"
#include "ua_util_internal.h"

/* ECC Policy URIs */
static const UA_String eccPolicies[] = {
    UA_STRING_STATIC("http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256"),
    UA_STRING_STATIC("http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384"),
};

UA_Boolean UA_SecurityPolicy_isEccPolicy(UA_String policyURI) {
    for(size_t i=0; i<sizeof(eccPolicies); i++) {
        if(UA_String_equal(&eccPolicies[i], &policyURI)) {
            return true;
        }
    }
    return false;
}

void UA_EccEncryptedSecretStruct_init(UA_EccEncryptedSecretStruct* es) {
    UA_NodeId_init(&es->typeId);

    UA_ByteString_init(&es->certificate);
    UA_ByteString_init(&es->nonce);
    UA_ByteString_init(&es->receiverPublicKey);
    UA_ByteString_init(&es->senderPublicKey);
    UA_ByteString_init(&es->secret);

    UA_DateTime_init(&es->signingTime);

    UA_String_init(&es->securityPolicyUri);

    es->encodingMask = 0x00;
    
    es->keyDataLen = 0;
    es->length = 0;
    es->payloadPaddingSize = 0;

    es->payloadPadding = NULL;
    es->signature = NULL;
}

void UA_EccEncryptedSecretStruct_clear(UA_EccEncryptedSecretStruct* es) {
        if(!UA_String_isEmpty(&es->securityPolicyUri)) {
            UA_String_clear(&es->securityPolicyUri);
        }
        if(es->certificate.data != NULL) {
            UA_ByteString_clear(&es->certificate);
        }
        if(es->senderPublicKey.data != NULL) {
            UA_ByteString_clear(&es->senderPublicKey);
        }
        if(es->receiverPublicKey.data != NULL) {
            UA_ByteString_clear(&es->receiverPublicKey);
        }
        if(es->nonce.data != NULL) {
            UA_ByteString_clear(&es->nonce);
        }
        if(es->secret.data != NULL) {
            UA_ByteString_clear(&es->secret);
        }
        if(es->payloadPadding != NULL) {
            UA_Array_delete(es->payloadPadding, es->payloadPaddingSize, &UA_TYPES[UA_DATATYPEKIND_BYTE]);
        }
}

size_t UA_EccEncryptedSecret_getCommonHeaderSize(const UA_EccEncryptedSecretStruct* src) {
    size_t len = 0;

    len += UA_calcSizeBinary(&src->typeId, &UA_TYPES[UA_TYPES_NODEID], NULL);
    len += UA_calcSizeBinary(&src->encodingMask, &UA_TYPES[UA_TYPES_BYTE], NULL);
    len += UA_calcSizeBinary(&src->length, &UA_TYPES[UA_TYPES_UINT32], NULL);
    len += UA_calcSizeBinary(&src->securityPolicyUri, &UA_TYPES[UA_TYPES_STRING], NULL);
    len += UA_calcSizeBinary(&src->certificate, &UA_TYPES[UA_TYPES_BYTESTRING], NULL);
    len += UA_calcSizeBinary(&src->signingTime, &UA_TYPES[UA_TYPES_DATETIME], NULL);
    len += UA_calcSizeBinary(&src->keyDataLen, &UA_TYPES[UA_TYPES_UINT16], NULL);

    return len;
}

size_t UA_EccEncryptedSecret_getPolicyHeaderSize(const UA_EccEncryptedSecretStruct* src) {
    size_t len = 0;

    len += UA_calcSizeBinary(&src->senderPublicKey, &UA_TYPES[UA_TYPES_BYTESTRING], NULL);
    len += UA_calcSizeBinary(&src->receiverPublicKey, &UA_TYPES[UA_TYPES_BYTESTRING], NULL);

    return len;
}

UA_StatusCode UA_EccEncryptedSecret_serializeCommonHeader(const UA_EccEncryptedSecretStruct* src, UA_Byte** bufPos, const UA_Byte* bufEnd) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    ret |= UA_NodeId_encodeBinary(&src->typeId, bufPos, bufEnd);
    ret |= UA_Byte_encodeBinary(&src->encodingMask, bufPos, bufEnd);
    ret |= UA_UInt32_encodeBinary(&src->length, bufPos, bufEnd);
    ret |= UA_String_encodeBinary(&src->securityPolicyUri, bufPos, bufEnd);
    ret |= UA_ByteString_encodeBinary(&src->certificate, bufPos, bufEnd);
    ret |= UA_DateTime_encodeBinary(&src->signingTime, bufPos, bufEnd);
    ret |= UA_UInt16_encodeBinary(&src->keyDataLen, bufPos, bufEnd);

    return ret;
}

UA_StatusCode UA_EccEncryptedSecret_serializePolicyHeader(const UA_EccEncryptedSecretStruct* src, UA_Byte** bufPos, const UA_Byte* bufEnd) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    ret |= UA_ByteString_encodeBinary(&src->senderPublicKey, bufPos, bufEnd);
    ret |= UA_ByteString_encodeBinary(&src->receiverPublicKey, bufPos, bufEnd);

    return ret;
}

UA_StatusCode UA_EccEncryptedSecret_deserializeCommonHeader(UA_EccEncryptedSecret* src, UA_EccEncryptedSecretStruct* dest, size_t* offset) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;
    *offset = 0;

    ret |= UA_NodeId_decodeBinary(src, offset, &dest->typeId);
    ret |= UA_Byte_decodeBinary(src, offset, &dest->encodingMask);
    ret |= UA_UInt32_decodeBinary(src, offset, &dest->length);
    ret |= UA_String_decodeBinary(src, offset, &dest->securityPolicyUri);
    ret |= UA_ByteString_decodeBinary(src, offset, &dest->certificate);
    ret |= UA_DateTime_decodeBinary(src, offset, &dest->signingTime);
    ret |= UA_UInt16_decodeBinary(src, offset, &dest->keyDataLen);

    return ret;
}

UA_StatusCode UA_EccEncryptedSecret_deserializePolicyHeader(UA_EccEncryptedSecret* src, UA_EccEncryptedSecretStruct* dest, size_t* offset) {
    UA_StatusCode ret = UA_STATUSCODE_GOOD;

    if(*offset == 0) {
        return UA_STATUSCODE_BAD;
    }

    ret |= UA_ByteString_decodeBinary(src, offset, &dest->senderPublicKey);
    ret |= UA_ByteString_decodeBinary(src, offset, &dest->receiverPublicKey);

    return ret;
}

static inline UA_Boolean EccEncryptedSecret_checkNodeId(UA_NodeId* nid) {
    if(nid->identifierType != UA_NODEIDTYPE_NUMERIC || nid->identifier.numeric != 335) {
        return false;
    }
    return true;
}

static inline UA_Boolean EccEncryptedSecret_checkEncodingMask(UA_Byte em) {
    if(em != 0x01) {
        return false;
    }
    return true;
}

UA_Boolean UA_EccEncryptedSecret_checkCommonHeader(UA_EccEncryptedSecretStruct* es) {
    if(!EccEncryptedSecret_checkNodeId(&es->typeId)) {
        return false;
    }
    if(!EccEncryptedSecret_checkEncodingMask(es->encodingMask)) {
        return false;
    }
    if(!UA_SecurityPolicy_isEccPolicy(es->securityPolicyUri)) {
        return false;
    }

    return true;
}

UA_Boolean UA_EccEncryptedSecret_checkAndExtractPayload(const UA_ByteString* payload, const UA_ByteString* serverNonce, UA_ByteString* outPass) {
    size_t paddingSizeBytes = 2;
    
    if(memcmp(payload->data, serverNonce->data, serverNonce->length) != 0) {
        return false;
    }

    UA_UInt16 paddingSize = 0;
    size_t offset = payload->length - paddingSizeBytes;
    UA_UInt16_decodeBinary(payload, &offset, &paddingSize);
    if(paddingSize <= 0) {
        return false;
    }

    UA_Byte padd = paddingSize & 0xFF;

    for(size_t i=payload->length-3, j=paddingSize; j>0; i--, j--) {
        if(payload->data[i] != padd) {
            return false;
        }
    }

    // Compute the length and extract the password
    size_t passLen = payload->length - paddingSizeBytes - paddingSize -serverNonce->length;
    UA_ByteString_allocBuffer(outPass, passLen);
    
    if(outPass->data == NULL) {
        return false;
    }
    
    memcpy(outPass->data, &payload->data[serverNonce->length], passLen);
    outPass->length = passLen;

    return true;
}
