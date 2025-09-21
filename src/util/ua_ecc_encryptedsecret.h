/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2025 (c) Siemens AG (Author: Tin Raic)
 */

#include <open62541/types.h>

/* Ephemeral key node ID identifier, arbitrarily chosen */
#define NODE_IDENTIFIER_NUMERIC_EPHKEY 334
/* ECC Encrypted Secret node ID identifier, arbitrarily chosen*/
#define NODE_IDENTIFIER_NUMERIC_ECCENCRYPTEDSEC 335

typedef struct {
    /* Common Header */
    UA_NodeId typeId;
    UA_Byte encodingMask;
    UA_UInt32 length;
    UA_String securityPolicyUri;
    UA_ByteString certificate;
    UA_DateTime signingTime;
    UA_UInt16 keyDataLen;

    /* Policy Header*/
    UA_ByteString senderPublicKey;
    UA_ByteString receiverPublicKey;

    /* Payload */
    UA_ByteString nonce;
    UA_ByteString secret;
    UA_Byte* payloadPadding;
    UA_UInt16 payloadPaddingSize;

    /* Signature */
    UA_Byte* signature;
} UA_EccEncryptedSecretStruct;

UA_Boolean UA_SecurityPolicy_isEccPolicy(UA_String policyURI);

void UA_EccEncryptedSecretStruct_init(UA_EccEncryptedSecretStruct* es);

void UA_EccEncryptedSecretStruct_clear(UA_EccEncryptedSecretStruct* es);

size_t UA_EccEncryptedSecret_getCommonHeaderSize(const UA_EccEncryptedSecretStruct* src);

size_t UA_EccEncryptedSecret_getPolicyHeaderSize(const UA_EccEncryptedSecretStruct* src);

UA_StatusCode UA_EccEncryptedSecret_serializeCommonHeader(const UA_EccEncryptedSecretStruct* src, UA_Byte** bufPos, const UA_Byte* bufEnd);

UA_StatusCode UA_EccEncryptedSecret_serializePolicyHeader(const UA_EccEncryptedSecretStruct* src, UA_Byte** bufPos, const UA_Byte* bufEnd);

UA_StatusCode UA_EccEncryptedSecret_deserializeCommonHeader(UA_EccEncryptedSecret* src, UA_EccEncryptedSecretStruct* dest, size_t* offset);

UA_StatusCode UA_EccEncryptedSecret_deserializePolicyHeader(UA_EccEncryptedSecret* src, UA_EccEncryptedSecretStruct* dest, size_t* offset);

UA_Boolean UA_EccEncryptedSecret_checkCommonHeader(UA_EccEncryptedSecretStruct* es);

UA_Boolean UA_EccEncryptedSecret_checkAndExtractPayload(const UA_ByteString* payload, const UA_ByteString* serverNonce, UA_ByteString* outPass);
