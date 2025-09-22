/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2025 (c) Siemens AG (Author: Tin Raic)
 */

#include <open62541/types.h>
#include <open62541/plugin/log.h>
#include <open62541/plugin/securitypolicy.h>

/* Ephemeral key node ID identifier, arbitrarily chosen */
#define NODE_IDENTIFIER_NUMERIC_EPHKEY 334
/* ECC Encrypted Secret node ID identifier, arbitrarily chosen*/
#define NODE_IDENTIFIER_NUMERIC_ECCENCRYPTEDSEC 335

UA_Boolean UA_SecurityPolicy_isEccPolicy(UA_String policyURI);

UA_StatusCode
encryptUserIdentityTokenEcc(UA_Logger *logger, UA_ByteString *tokenData,
                            const UA_ByteString serverSessionNonce,
                            const UA_ByteString serverEphemeralPubKey,
                            UA_SecurityPolicy *sp, void *tempChannelContext);

UA_StatusCode
decryptUserTokenEcc(UA_Logger *logger, UA_ByteString sessionServerNonce,
                    const UA_SecurityPolicy *sp, const UA_String encryptionAlgorithm,
                    UA_EccEncryptedSecret *es);
