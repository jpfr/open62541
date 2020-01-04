/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2017 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2017-2018 (c) Thomas Stalder, Blue Time Concept SA
 *    Copyright 2017-2019 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2018 (c) Kalycito Infotech Private Limited
 */

#include <open62541/transport_generated.h>
#include <open62541/transport_generated_encoding_binary.h>
#include <open62541/transport_generated_handling.h>
#include <open62541/types_generated_encoding_binary.h>

#include "ua_client_internal.h"

/* Size are refered in bytes */
#define UA_MINMESSAGESIZE                8192
#define UA_SESSION_LOCALNONCELENGTH      32
#define UA_MAX_SIGN_SIZE                 4096

/*****************/
/* SecureChannel */
/*****************/

static void
UA_Client_setChannelState(UA_Client *client, UA_SecureChannelState state) {
    if(state == client->channel.state)
        return;
    client->lastChannelState = client->channel.state;
    client->channel.state = state;

    /* The session is no longer activated on a closed channel.
     * Reset to status "created" so it can be recovered. */
    if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
        client->sessionState = UA_SESSIONSTATE_CREATED;

    if(client->config.stateCallback)
        client->config.stateCallback(client, client->channel.state, client->sessionState);
}

void
closeSecureChannel(UA_Client *client) {
    UA_SecureChannel *channel = &client->channel;
    if(channel->state == UA_SECURECHANNELSTATE_CLOSED)
        return;

    /* Send CLO message only if the channel is opened */
    if(channel->state == UA_SECURECHANNELSTATE_OPEN) {
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Sending the CLO message");
        UA_CloseSecureChannelRequest request;
        UA_CloseSecureChannelRequest_init(&request);
        request.requestHeader.requestHandle = ++client->requestHandle;
        request.requestHeader.timestamp = UA_DateTime_now();
        request.requestHeader.timeoutHint = 10000;
        request.requestHeader.authenticationToken = client->authenticationToken;
        UA_SecureChannel_sendSymmetricMessage(channel, ++client->requestId,
                                              UA_MESSAGETYPE_CLO, &request,
                                              &UA_TYPES[UA_TYPES_CLOSESECURECHANNELREQUEST]);
        UA_CloseSecureChannelRequest_deleteMembers(&request);
    }

    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Closing the channel internally");

    /* Remove open service calls */
    UA_Client_AsyncService_removeAll(client, UA_STATUSCODE_BADCONNECTIONCLOSED);

    UA_SecureChannel_close(&client->channel); /* Closes the TCP connection */
    UA_Client_setChannelState(client, UA_SECURECHANNELSTATE_CLOSED); /* Notify the user */
    UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel, "SecureChannel closed");
    UA_SecureChannel_clear(&client->channel); /* Reset */
}

void
UA_Client_processERR(UA_Client *client, const UA_ByteString *message) {
    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Received ERR message");
    closeSecureChannel(client);
}

static UA_StatusCode
sendHEL(UA_Client *client) {
    /* Get the buffer */
    UA_ByteString message;
    UA_Connection *conn = &client->connection;
    UA_StatusCode res = conn->getSendBuffer(conn, UA_MINMESSAGESIZE, &message);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    /* Prepare the HEL message and encode at offset 8 */
    UA_TcpHelloMessage hello;
    memcpy(&hello, &client->config.localConnectionConfig,
           sizeof(UA_ConnectionConfig)); /* same struct layout */
    hello.endpointUrl = client->endpointUrl;

    /* Encode the payload */
    UA_Byte *bufPos = &message.data[8]; /* skip the header */
    const UA_Byte *bufEnd = &message.data[message.length];
    res = UA_TcpHelloMessage_encodeBinary(&hello, &bufPos, bufEnd);
    if(res != UA_STATUSCODE_GOOD) {
        conn->releaseSendBuffer(conn, &message);
        goto cleanup;
    }

    /* Encode the message header at offset 0 */
    UA_TcpMessageHeader messageHeader;
    messageHeader.messageTypeAndChunkType = UA_CHUNKTYPE_FINAL + UA_MESSAGETYPE_HEL;
    messageHeader.messageSize = (UA_UInt32) ((uintptr_t)bufPos - (uintptr_t)message.data);
    bufPos = message.data;
    res = UA_TcpMessageHeader_encodeBinary(&messageHeader, &bufPos, bufEnd);
    if(res != UA_STATUSCODE_GOOD) {
        conn->releaseSendBuffer(conn, &message);
        goto cleanup;
    }

    /* Send the HEL message */
    message.length = messageHeader.messageSize;
    res = conn->send(conn, &message);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel, "Sent HEL message");
    UA_Client_setChannelState(client, UA_SECURECHANNELSTATE_HEL_SENT);
    return res;

 cleanup:
    UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel, "Sending HEL failed");
    closeSecureChannel(client);
    return res;
}

UA_StatusCode
UA_Client_sendOPN(UA_Client *client, UA_Boolean renew) {
    /* Prepare the OpenSecureChannelRequest */
    UA_OpenSecureChannelRequest opnSecRq;
    UA_OpenSecureChannelRequest_init(&opnSecRq);
    opnSecRq.requestHeader.timestamp = UA_DateTime_now();
    if(renew) {
        opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_RENEW;
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Renewing the SecureChannel");
    } else {
        opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_ISSUE;
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Opening a SecureChannel");
    }

    /* Generate clientNonce. */
    UA_StatusCode res = UA_SecureChannel_generateLocalNonce(&client->channel);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "Generating a local nonce failed");
        return res;
    }

    /* Set the securityMode to input securityMode from client data */
    opnSecRq.securityMode = client->channel.securityMode;
    opnSecRq.clientNonce = client->channel.localNonce;
    opnSecRq.requestedLifetime = client->config.secureChannelLifeTime;

    /* Send the OPN message */
    UA_UInt32 requestId = ++client->requestId;
    res = UA_SecureChannel_sendAsymmetricOPNMessage(&client->channel, requestId, &opnSecRq,
                                                    &UA_TYPES[UA_TYPES_OPENSECURECHANNELREQUEST]);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel, 
                     "Sending OPN message failed with StatusCode %s", UA_StatusCode_name(res));
        return res;
    }

    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel, "OPN message sent");
    if(!renew)
        UA_Client_setChannelState(client, UA_SECURECHANNELSTATE_OPN_SENT);

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Client_processACK(UA_Client *client, const UA_ByteString *payload) {
    /* Decode the message */
    size_t offset = 0;
    UA_TcpAcknowledgeMessage ackMessage;
    UA_StatusCode res = UA_TcpAcknowledgeMessage_decodeBinary(payload, &offset, &ackMessage);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel, 
                             "Decoding ACK message failed");
        return res;
    }

    res = UA_SecureChannel_processHELACK(&client->channel,
                                         &client->config.localConnectionConfig,
                                         (const UA_ConnectionConfig*)&ackMessage);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel, 
                             "Applying the ACK message failed");
        return res;
    }

    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel, "Applied ACK message");
    UA_Client_setChannelState(client, UA_SECURECHANNELSTATE_ACK_RECEIVED);

    /* Send OPN message */
    return UA_Client_sendOPN(client, false);
}

static UA_SecurityPolicy *
getSecurityPolicy(UA_Client *client, UA_String policyUri) {
    for(size_t i = 0; i < client->config.securityPoliciesSize; i++) {
        if(UA_String_equal(&policyUri, &client->config.securityPolicies[i].policyUri))
            return &client->config.securityPolicies[i];
    }
    return NULL;
}

UA_StatusCode
UA_Client_processOPN(UA_Client *client, UA_ByteString *message, UA_Boolean renew) {
    UA_SecureChannel *channel = &client->channel;
    UA_LOG_DEBUG_CHANNEL(&client->config.logger, channel, "Verify asymmetric OPN header");

    /* Decode and check the asymmetric algorithm security header */
    size_t offset = 0;
    UA_AsymmetricAlgorithmSecurityHeader asymHeader;
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    res |= UA_AsymmetricAlgorithmSecurityHeader_decodeBinary(message, &offset, &asymHeader);
    res |= checkAsymHeader(channel, &asymHeader);
    UA_AsymmetricAlgorithmSecurityHeader_deleteMembers(&asymHeader);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, channel,
                             "Could not verify the AsymmetricAlgorithmSecurityHeader");
        return res;
    }

    /* Decrypt */
    UA_LOG_DEBUG_CHANNEL(&client->config.logger, channel, "Decrypt the OPN response");
    UA_UInt32 requestId = 0;
    UA_UInt32 sequenceNumber = 0;
    res = decryptAndVerifyChunk(channel, &channel->securityPolicy->asymmetricModule.cryptoModule,
                                UA_MESSAGETYPE_OPN, message, offset, &requestId,
                                &sequenceNumber, message);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    res = processSequenceNumberAsym(channel, sequenceNumber);
    if(res != UA_STATUSCODE_GOOD)
        return res;

    offset = 0; /* Reset the offset for the decrypted content */

    UA_LOG_DEBUG_CHANNEL(&client->config.logger, channel, "Decode the OPN content");
    UA_NodeId requestType;
    UA_OpenSecureChannelResponse response;
    res |= UA_NodeId_decodeBinary(message, &offset, &requestType);
    res |= UA_OpenSecureChannelResponse_decodeBinary(message, &offset, &response);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    res = response.responseHeader.serviceResult;
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Replace the nonce */
    UA_ByteString_deleteMembers(&channel->remoteNonce);
    channel->remoteNonce = response.serverNonce;
    UA_ByteString_init(&response.serverNonce);

    /* TODO: Verify if the created-timestamps and the revised token lifetime are
       conformant */

    /* Replace the token and generate keys. For the client, the new token is
     * immediately active. The server continues to accept the old token until a
     * message with the new token arrives.*/
    channel->securityToken = response.securityToken;
    res = UA_SecureChannel_generateNewKeys(channel);
    if(res != UA_STATUSCODE_GOOD)
        goto cleanup;

    if(channel->state == UA_SECURECHANNELSTATE_OPEN)
        UA_LOG_INFO_CHANNEL(&client->config.logger, channel, "SecureChannel renewed");
    else
        UA_LOG_INFO_CHANNEL(&client->config.logger, channel,
                            "Opened SecureChannel with SecurityPolicy %.*s",
                            (int)channel->securityPolicy->policyUri.length,
                            channel->securityPolicy->policyUri.data);

    /* Response.securityToken.revisedLifetime is UInt32 we need to cast it to
     * DateTime=Int64 we take 75% of lifetime to start renewing as described in
     * standard */
    UA_Client_setChannelState(client, UA_SECURECHANNELSTATE_OPEN);
    client->nextChannelRenewal = UA_DateTime_nowMonotonic() + (UA_DateTime)
        (channel->securityToken.revisedLifetime * (UA_Double)UA_DATETIME_MSEC * 0.75);

 cleanup:
    UA_NodeId_clear(&requestType);
    UA_OpenSecureChannelResponse_clear(&response);
    return res;
}

/* Opens the initial connection. Use UA_Client_iterate_run afterwards to
 * complete the handshakes. */
static UA_StatusCode
UA_Client_startConnect(UA_Client *client, const UA_String endpointUrl) {
    UA_SecureChannel *channel = &client->channel;
    if(channel->state == UA_SECURECHANNELSTATE_OPEN)
        return UA_STATUSCODE_GOOD;

    /* Reset if required */
    if(channel->state > UA_SECURECHANNELSTATE_FRESH)
        closeSecureChannel(client);

    /* Set the channel connection settings */
    channel->config = client->config.localConnectionConfig;

    /* Set the channel SecurityMode */
    channel->securityMode = client->config.endpoint.securityMode;
    if(channel->securityMode == UA_MESSAGESECURITYMODE_INVALID)
        channel->securityMode = UA_MESSAGESECURITYMODE_NONE;

    /* Set the channel SecurityPolicy to #None if no endpoint is selected */
    UA_String sps = client->config.endpoint.securityPolicyUri;
    if(sps.length == 0) {
        UA_LOG_INFO_CHANNEL(&client->config.logger, channel,
                            "SecurityPolicy not specified -> use default #None");
        sps = UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None");
    }

    UA_SecurityPolicy *sp = getSecurityPolicy(client, sps);
    if(!sp) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, channel,
                             "Failed to find the required security policy");
        closeSecureChannel(client);
        return UA_STATUSCODE_BADINTERNALERROR;
    }
        
    UA_StatusCode res =
        UA_SecureChannel_setSecurityPolicy(channel, sp,
                                           &client->config.endpoint.serverCertificate);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, channel,
                             "Failed to set the security policy with StatusCode %s",
                             UA_StatusCode_name(res));
        closeSecureChannel(client);
        return res;
    }

    /* Open a TCP connection */
    client->connection =
        client->config.connectionFunc(client->config.localConnectionConfig, endpointUrl,
                                      client->config.timeout, &client->config.logger);
    if(client->connection.state != UA_CONNECTION_OPENING) {
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "Opening the TCP socket failed");
        closeSecureChannel(client);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    /* Set the connection in the channel */
    channel->connection = &client->connection;
    UA_LOG_INFO_CHANNEL(&client->config.logger, channel, "TCP connection established");

    /* Send HEL */
    return sendHEL(client);
}

/*****************/
/* Close Session */
/*****************/

void
UA_Client_setSessionState(UA_Client *client, UA_SessionState state) {
    if(client->sessionState == state)
        return;
    client->sessionState = state;
    if(client->config.stateCallback)
        client->config.stateCallback(client, client->channel.state,
                                     client->sessionState);
}

static void
closeSessionResponseCallback(UA_Client *client, void *userdata,
                             UA_UInt32 requestId, void *r) {
    UA_CloseSessionResponse *response = (UA_CloseSessionResponse*)r;
    UA_StatusCode res = response->responseHeader.serviceResult;
    if(res == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel, "Session closed");
    } else {
        UA_LOG_WARNING_CHANNEL(&client->config.logger, &client->channel,
                               "The CloseSessionRequest returned StatusCode %s",
                               UA_StatusCode_name(res));
    }
    closeSecureChannel(client);
}

static void
closeSessionAsync(UA_Client *client) {
    if(client->sessionState == UA_SESSIONSTATE_FRESH ||
       client->sessionState == UA_SESSIONSTATE_CLOSED)
        return;
    
    /* Set the session closed to avoid recursion */
    client->sessionState = UA_SESSIONSTATE_CLOSED;

    UA_CloseSessionRequest request;
    UA_CloseSessionRequest_init(&request);
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.deleteSubscriptions = true;

    UA_StatusCode retval =
        UA_Client_AsyncService(client, &request, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST],
                               closeSessionResponseCallback,
                               &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE], NULL, NULL);

    /* Don't send any more publish requests during CloseSession */
#ifdef UA_ENABLE_SUBSCRIPTIONS
    UA_Client_Subscriptions_clean(client);
#endif

    /* Clean up the session */
    UA_NodeId_deleteMembers(&client->authenticationToken);
    client->requestHandle = 0;

    if(retval == UA_STATUSCODE_GOOD) {
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Sent the CloseSessionRequest");
    } else {
        UA_LOG_WARNING_CHANNEL(&client->config.logger, &client->channel,
                               "Could not send the CloseSessionRequest with StatusCode %s",
                               UA_StatusCode_name(retval));
        closeSecureChannel(client);
    }
}

/****************/
/* Open Session */
/****************/

/* Function to create a signature using remote certificate and nonce */
#ifdef UA_ENABLE_ENCRYPTION
static UA_StatusCode
signActivateSessionRequest(UA_SecureChannel *channel,
                           UA_ActivateSessionRequest *request) {
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    const UA_SecurityPolicy *sp = channel->securityPolicy;
    UA_SignatureData *sd = &request->clientSignature;

    /* Prepare the signature */
    size_t signatureSize = sp->certificateSigningAlgorithm.
        getLocalSignatureSize(sp, channel->channelContext);
    UA_StatusCode retval = UA_String_copy(&sp->certificateSigningAlgorithm.uri,
                                          &sd->algorithm);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_ByteString_allocBuffer(&sd->signature, signatureSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Allocate a temporary buffer */
    size_t dataToSignSize = channel->remoteCertificate.length + channel->remoteNonce.length;
    if(dataToSignSize > UA_MAX_SIGN_SIZE)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_ByteString dataToSign;
    retval = UA_ByteString_allocBuffer(&dataToSign, dataToSignSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval; /* sd->signature is cleaned up with the response */

    /* Sign the signature */
    memcpy(dataToSign.data, channel->remoteCertificate.data,
           channel->remoteCertificate.length);
    memcpy(dataToSign.data + channel->remoteCertificate.length,
           channel->remoteNonce.data, channel->remoteNonce.length);
    retval = sp->certificateSigningAlgorithm.sign(sp, channel->channelContext,
                                                  &dataToSign, &sd->signature);

    /* Clean up */
    UA_ByteString_deleteMembers(&dataToSign);
    return retval;
}

static UA_StatusCode
encryptUserIdentityToken(UA_Client *client, const UA_String *userTokenSecurityPolicy,
                         UA_ExtensionObject *userIdentityToken) {
    UA_IssuedIdentityToken *iit = NULL;
    UA_UserNameIdentityToken *unit = NULL;
    UA_ByteString *tokenData;
    if(userIdentityToken->content.decoded.type == &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN]) {
        iit = (UA_IssuedIdentityToken*)userIdentityToken->content.decoded.data;
        tokenData = &iit->tokenData;
    } else if(userIdentityToken->content.decoded.type == &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
        unit = (UA_UserNameIdentityToken*)userIdentityToken->content.decoded.data;
        tokenData = &unit->password;
    } else {
        return UA_STATUSCODE_GOOD;
    }

    /* No encryption */
    const UA_String none = UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None");
    if(userTokenSecurityPolicy->length == 0 ||
       UA_String_equal(userTokenSecurityPolicy, &none)) {
        return UA_STATUSCODE_GOOD;
    }

    UA_SecurityPolicy *sp = getSecurityPolicy(client, *userTokenSecurityPolicy);
    if(!sp) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "Could not find the required SecurityPolicy for the UserToken");
        return UA_STATUSCODE_BADSECURITYPOLICYREJECTED;
    }

    /* Create a temp channel context */

    void *channelContext;
    UA_StatusCode retval = sp->channelModule.
        newContext(sp, &client->config.endpoint.serverCertificate, &channelContext);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "Could not instantiate the SecurityPolicy for the UserToken");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    
    /* Compute the encrypted length (at least one byte padding) */
    size_t plainTextBlockSize = sp->asymmetricModule.cryptoModule.
        encryptionAlgorithm.getRemotePlainTextBlockSize(sp, channelContext);
    UA_UInt32 length = (UA_UInt32)(tokenData->length + client->channel.remoteNonce.length);
    UA_UInt32 totalLength = length + 4; /* Including the length field */
    size_t blocks = totalLength / plainTextBlockSize;
    if(totalLength  % plainTextBlockSize != 0)
        blocks++;
    size_t overHead =
        UA_SecurityPolicy_getRemoteAsymEncryptionBufferLengthOverhead(sp, channelContext,
                                                                      blocks * plainTextBlockSize);

    /* Allocate memory for encryption overhead */
    UA_ByteString encrypted;
    retval = UA_ByteString_allocBuffer(&encrypted, (blocks * plainTextBlockSize) + overHead);
    if(retval != UA_STATUSCODE_GOOD) {
        sp->channelModule.deleteContext(channelContext);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    UA_Byte *pos = encrypted.data;
    const UA_Byte *end = &encrypted.data[encrypted.length];
    UA_UInt32_encodeBinary(&length, &pos, end);
    memcpy(pos, tokenData->data, tokenData->length);
    memcpy(&pos[tokenData->length], client->channel.remoteNonce.data,
           client->channel.remoteNonce.length);

    /* Add padding
     *
     * 7.36.2.2 Legacy Encrypted Token Secret Format: A Client should not add any
     * padding after the secret. If a Client adds padding then all bytes shall
     * be zero. A Server shall check for padding added by Clients and ensure
     * that all padding bytes are zeros. */
    size_t paddedLength = plainTextBlockSize * blocks;
    for(size_t i = totalLength; i < paddedLength; i++)
        encrypted.data[i] = 0;
    encrypted.length = paddedLength;

    UA_SecurityPolicyEncryptionAlgorithm *ea =
        &sp->asymmetricModule.cryptoModule.encryptionAlgorithm;

    retval = ea->encrypt(sp, channelContext, &encrypted);
    encrypted.length = (blocks * plainTextBlockSize) + overHead;

    if(iit) {
        retval |= UA_String_copy(&ea->uri, &iit->encryptionAlgorithm);
    } else {
        retval |= UA_String_copy(&ea->uri, &unit->encryptionAlgorithm);
    }

    UA_ByteString_deleteMembers(tokenData);
    *tokenData = encrypted;

    /* Delete the temp channel context */
    sp->channelModule.deleteContext(channelContext);
    return retval;
}
#endif

static void
activateSessionResponseCallback(UA_Client *client, void *userdata,
                                UA_UInt32 requestId, void *response) {
    UA_ActivateSessionResponse *asr = (UA_ActivateSessionResponse *)response;
    client->connectionResult = asr->responseHeader.serviceResult;
    if(client->connectionResult != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "ActivateSession failed with StatusCode %s",
                             UA_StatusCode_name(client->connectionResult));
        closeSessionAsync(client);
        return;
    }

    UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel, "Session activated");
    UA_Client_setSessionState(client, UA_SESSIONSTATE_ACTIVATED);
}

static UA_StatusCode
sendActivateSession(UA_Client *client) {
    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Prepare to send ActivateSession");
    UA_ActivateSessionRequest request;
    UA_ActivateSessionRequest_init(&request);
    request.requestHeader.requestHandle = ++client->requestHandle;
    request.requestHeader.timestamp = UA_DateTime_now ();
    request.requestHeader.timeoutHint = 600000;
    UA_StatusCode retval =
        UA_ExtensionObject_copy(&client->config.userIdentityToken, &request.userIdentityToken);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* If not token is set, use anonymous */
    if(request.userIdentityToken.encoding == UA_EXTENSIONOBJECT_ENCODED_NOBODY) {
        UA_AnonymousIdentityToken *t = UA_AnonymousIdentityToken_new();
        if(!t) {
            UA_ActivateSessionRequest_deleteMembers(&request);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        request.userIdentityToken.content.decoded.data = t;
        request.userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN];
        request.userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
    }

    /* Set the PolicyId from the endpoint. Every IdentityToken starts with a
     * string. */
    retval = UA_String_copy(&client->config.userTokenPolicy.policyId,
                            (UA_String*)request.userIdentityToken.content.decoded.data);

#ifdef UA_ENABLE_ENCRYPTION
    /* Encrypt the UserIdentityToken and sign the request */
    const UA_String *userTokenPolicy = &client->channel.securityPolicy->policyUri;
    if(client->config.userTokenPolicy.securityPolicyUri.length > 0)
        userTokenPolicy = &client->config.userTokenPolicy.securityPolicyUri;
    retval |= encryptUserIdentityToken(client, userTokenPolicy, &request.userIdentityToken);
    retval |= signActivateSessionRequest(&client->channel, &request);
#endif

    if(retval != UA_STATUSCODE_GOOD) {
        UA_ActivateSessionRequest_deleteMembers(&request);
        return retval;
    }

    retval = UA_Client_AsyncService(client, &request, &UA_TYPES[UA_TYPES_ACTIVATESESSIONREQUEST],
                                    activateSessionResponseCallback,
                                    &UA_TYPES[UA_TYPES_ACTIVATESESSIONRESPONSE], NULL, NULL);

    UA_ActivateSessionRequest_deleteMembers(&request);
    if(retval == UA_STATUSCODE_GOOD)
        UA_Client_setSessionState(client, UA_SESSIONSTATE_ACTIVATE_REQUESTED);
    return retval;
}

/* Function to verify the signature corresponds to ClientNonce
 * using the local certificate */
static UA_StatusCode
checkClientSignature(const UA_SecureChannel *channel,
                     const UA_CreateSessionResponse *response) {
    if(channel->securityMode != UA_MESSAGESECURITYMODE_SIGN &&
       channel->securityMode != UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        return UA_STATUSCODE_GOOD;

    const UA_SecurityPolicy *sp = channel->securityPolicy;
    if(!sp)
        return UA_STATUSCODE_BADINTERNALERROR;

    const UA_ByteString *lc = &sp->localCertificate;
    size_t dataToVerifySize = lc->length + channel->localNonce.length;
    UA_ByteString dataToVerify = UA_BYTESTRING_NULL;
    UA_StatusCode retval = UA_ByteString_allocBuffer(&dataToVerify, dataToVerifySize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    memcpy(dataToVerify.data, lc->data, lc->length);
    memcpy(dataToVerify.data + lc->length, channel->localNonce.data,
           channel->localNonce.length);

    retval = sp->certificateSigningAlgorithm.
        verify(sp, channel->channelContext, &dataToVerify,
               &response->serverSignature.signature);
    UA_ByteString_deleteMembers(&dataToVerify);
    return retval;
}

static void
createSessionResponseCallback(UA_Client *client, void *userdata,
                              UA_UInt32 requestId, void *response) {
    UA_CreateSessionResponse *sessionResponse = (UA_CreateSessionResponse *)response;
    UA_StatusCode res = sessionResponse->responseHeader.serviceResult;
    if(res == UA_STATUSCODE_GOOD)
        res = checkClientSignature(&client->channel, sessionResponse);

    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "CreateSession failed with StatusCode %s",
                             UA_StatusCode_name(res));
        UA_Client_setSessionState(client, UA_SESSIONSTATE_CLOSED);
        client->connectionResult = res;
        return;
    }

    UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel, "Session created");
    UA_NodeId_copy(&sessionResponse->authenticationToken, &client->authenticationToken);
    UA_Client_setSessionState(client, UA_SESSIONSTATE_CREATED);
    client->connectionResult = sendActivateSession(client);
}

static UA_StatusCode
sendCreateSession(UA_Client *client) {
    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Prepare to send CreateSession");

    UA_CreateSessionRequest request;
    UA_CreateSessionRequest_init(&request);

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       client->channel.securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT) {
        if(client->channel.localNonce.length != UA_SESSION_LOCALNONCELENGTH) {
           UA_ByteString_deleteMembers(&client->channel.localNonce);
            res = UA_ByteString_allocBuffer(&client->channel.localNonce,
                                            UA_SESSION_LOCALNONCELENGTH);
            if(res != UA_STATUSCODE_GOOD)
                return res;
        }

        res = client->channel.securityPolicy->symmetricModule.
                 generateNonce(client->channel.securityPolicy, &client->channel.localNonce);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    request.requestHeader.requestHandle = ++client->requestHandle;
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.requestedSessionTimeout = client->config.requestedSessionTimeout;
    request.maxResponseMessageSize = UA_INT32_MAX;
    res |= UA_ByteString_copy(&client->channel.localNonce, &request.clientNonce);
    res |= UA_String_copy(&client->config.endpoint.endpointUrl, &request.endpointUrl);
    res |= UA_ApplicationDescription_copy(&client->config.clientDescription,
                                          &request.clientDescription);
    if(res != UA_STATUSCODE_GOOD) {
        UA_CreateSessionRequest_deleteMembers(&request);
        return res;
    }

    res = UA_Client_AsyncService(client, &request, &UA_TYPES[UA_TYPES_CREATESESSIONREQUEST],
                                 (UA_ClientAsyncServiceCallback)createSessionResponseCallback,
                                 &UA_TYPES[UA_TYPES_CREATESESSIONRESPONSE], NULL, NULL);
    UA_CreateSessionRequest_deleteMembers(&request);

    if(res == UA_STATUSCODE_GOOD)
        UA_Client_setSessionState(client, UA_SESSIONSTATE_CREATE_REQUESTED);
    return res;
}

static void
selectEndpoint(UA_Client *client, void *userdata, UA_UInt32 requestId,
               const UA_GetEndpointsResponse *response) {
    client->endpointsRequested = false;
    UA_Boolean endpointFound = false;
    UA_Boolean tokenFound = false;
    UA_String binaryTransport =
        UA_STRING("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");
    UA_StatusCode res = UA_STATUSCODE_GOOD;

    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Selecting endpoints from GetEndpointsResponse");
    
    for(size_t i = 0; i < response->endpointsSize; ++i) {
        UA_EndpointDescription* endpoint = &response->endpoints[i];
        /* Match Binary TransportProfile?
         * Note: Siemens returns empty ProfileUrl, we will accept it as binary */
        if(endpoint->transportProfileUri.length != 0 &&
           !UA_String_equal(&endpoint->transportProfileUri, &binaryTransport))
            continue;

        /* Valid SecurityMode? */
        if(endpoint->securityMode < 1 || endpoint->securityMode > 3) {
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: invalid security mode", (long unsigned)i);
            continue;
        }

        /* Selected SecurityMode? */
        if(client->config.securityMode > 0 &&
           client->config.securityMode != endpoint->securityMode) {
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security mode doesn't match", (long unsigned)i);
            continue;
        }

        /* Matching SecurityPolicy? */
        if(client->config.securityPolicyUri.length > 0 &&
           !UA_String_equal(&client->config.securityPolicyUri,
                            &endpoint->securityPolicyUri)) {
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security policy doesn't match", (long unsigned)i);
            continue;
        }

        /* SecurityPolicy available? */
        if(!getSecurityPolicy(client, endpoint->securityPolicyUri)) {
            UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                        "Rejecting endpoint %lu: security policy not available", (long unsigned)i);
            continue;
        }

        endpointFound = true;

        /* Select a matching UserTokenPolicy inside the endpoint */
        UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "Endpoint %lu has %lu user token policies",
                     (long unsigned)i, (long unsigned)endpoint->userIdentityTokensSize);
        for(size_t j = 0; j < endpoint->userIdentityTokensSize; ++j) {
            UA_UserTokenPolicy* userToken = &endpoint->userIdentityTokens[j];

            /* Usertokens also have a security policy... */
            if(userToken->securityPolicyUri.length > 0 &&
                !getSecurityPolicy(client, userToken->securityPolicyUri)) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu in endpoint %lu: "
                            "security policy '%.*s' not available",
                (long unsigned)j, (long unsigned)i,
                (int)userToken->securityPolicyUri.length, userToken->securityPolicyUri.data);
                continue;
            }

            if(userToken->tokenType > 3) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu in endpoint %lu: "
                            "invalid token type", (long unsigned)j, (long unsigned)i);
                continue;
            }

            const UA_DataType *tokenType = client->config.userIdentityToken.content.decoded.type;

            /* Does the token type match the client configuration? */
            if(userToken->tokenType == UA_USERTOKENTYPE_ANONYMOUS &&
               tokenType != &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN] &&
               client->config.userIdentityToken.content.decoded.type != NULL) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (anonymous) in endpoint %lu: "
                            "configuration doesn't match", (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(userToken->tokenType == UA_USERTOKENTYPE_USERNAME &&
               tokenType != &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (username) in endpoint %lu: "
                            "configuration doesn't match", (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(userToken->tokenType == UA_USERTOKENTYPE_CERTIFICATE &&
               tokenType != &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN]) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (certificate) in endpoint %lu: "
                            "configuration doesn't match", (long unsigned)j, (long unsigned)i);
                continue;
            }
            if(userToken->tokenType == UA_USERTOKENTYPE_ISSUEDTOKEN &&
               tokenType != &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN]) {
                UA_LOG_INFO(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                            "Rejecting UserTokenPolicy %lu (token) in endpoint %lu: "
                            "configuration doesn't match", (long unsigned)j, (long unsigned)i);
                continue;
            }

            /* Endpoint with matching UserTokenPolicy found. Copy to the configuration. */
            tokenFound = true;
            UA_EndpointDescription_deleteMembers(&client->config.endpoint);
            UA_EndpointDescription temp = *endpoint;
            temp.userIdentityTokensSize = 0;
            temp.userIdentityTokens = NULL;
            UA_UserTokenPolicy_deleteMembers(&client->config.userTokenPolicy);

            res = UA_EndpointDescription_copy(&temp, &client->config.endpoint);
            if(res != UA_STATUSCODE_GOOD) {
                UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                    "Copying endpoint description failed with StatusCode %s",
                    UA_StatusCode_name(res));
                break;
            }

            res = UA_UserTokenPolicy_copy(userToken, &client->config.userTokenPolicy);
            if(res != UA_STATUSCODE_GOOD) {
                UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                             "Copying user token policy failed with StatusCode %s",
                             UA_StatusCode_name(res));
                break;
            }

#if UA_LOGLEVEL <= 300
            const char *securityModeNames[3] = {"None", "Sign", "SignAndEncrypt"};
            const char *userTokenTypeNames[4] =
                {"Anonymous", "UserName", "Certificate", "IssuedToken"};

            /* Log the selected endpoint */
            UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel,
                                "Selected Endpoint %.*s with SecurityMode %s and SecurityPolicy %.*s",
                                (int)endpoint->endpointUrl.length, endpoint->endpointUrl.data,
                                securityModeNames[endpoint->securityMode - 1],
                                (int)endpoint->securityPolicyUri.length,
                                endpoint->securityPolicyUri.data);

            /* Log the selected UserTokenPolicy */
            UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel,
                                "Selected UserTokenPolicy %.*s with UserTokenType %s",
                                (int)userToken->policyId.length, userToken->policyId.data,
                                userTokenTypeNames[userToken->tokenType]);
#endif
            break;
        }

        if(tokenFound)
            break;
    }

    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "Endpoint selection failed with StatusCode %s",
                             UA_StatusCode_name(res));
        goto close_channel;
    }

    if(!endpointFound) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "No suitable endpoint found");
        goto close_channel;
    }

    if(!tokenFound) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "No suitable UserTokenPolicy found for the possible endpoints");
        goto close_channel;
    }

    res = sendCreateSession(client);
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "CreateSession failed with StatusCode %s",
                             UA_StatusCode_name(res));
    }
    return;

 close_channel:
    client->connectionResult = res;
    closeSecureChannel(client);
}

UA_StatusCode
connectSessionAsync(UA_Client *client) {
    if(client->channel.state != UA_SECURECHANNELSTATE_OPEN)
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;

    if(client->sessionState == UA_SESSIONSTATE_ACTIVATED)
        return UA_STATUSCODE_GOOD;

    /* GetEndpoints in transit */
    if(client->endpointsRequested)
        return UA_STATUSCODE_GOOD;

    /* Get endpoints only if the description has not been touched (memset to zero) */
    UA_Byte test = 0;
    UA_Byte *pos = (UA_Byte*)&client->config.endpoint;
    for(size_t i = 0; i < sizeof(UA_EndpointDescription); i++)
        test = test | pos[i];
    pos = (UA_Byte*)&client->config.userTokenPolicy;
    for(size_t i = 0; i < sizeof(UA_UserTokenPolicy); i++)
        test = test | pos[i];
    UA_Boolean getEndpoints = (test == 0);

    /* Get endpoints and select matching one */
    if(getEndpoints) {
        UA_LOG_INFO_CHANNEL(&client->config.logger, &client->channel,
                            "Endpoint and UserTokenPolicy unconfigured, perform GetEndpoints");
        UA_GetEndpointsRequest request;
        UA_GetEndpointsRequest_init(&request);
        request.requestHeader.timestamp = UA_DateTime_now();
        request.requestHeader.timeoutHint = 10000;
        request.endpointUrl = client->endpointUrl;
        UA_StatusCode res =
            UA_Client_AsyncService(client, &request, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST],
                                   (UA_ClientAsyncServiceCallback)selectEndpoint,
                                   &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE], NULL, NULL);
        if(res == UA_STATUSCODE_GOOD)
            client->endpointsRequested = true;
        return res;
    }

    /* Recover (activate) an existing Session */
    if(!UA_NodeId_isNull(&client->authenticationToken))
        return sendActivateSession(client);

    /* Create a new Session. */
    return sendCreateSession(client);
}

#ifdef UA_ENABLE_ENCRYPTION
/* The local ApplicationURI has to match the certificates of the
 * SecurityPolicies */
static void
verifyClientApplicationURI(const UA_Client *client) {
#if UA_LOGLEVEL <= 400
    for(size_t i = 0; i < client->config.securityPoliciesSize; i++) {
        UA_SecurityPolicy *sp = &client->config.securityPolicies[i];
        if(!sp->certificateVerification)
            continue;
        UA_StatusCode retval =
            sp->certificateVerification->
            verifyApplicationURI(sp->certificateVerification->context,
                                 &sp->localCertificate,
                                 &client->config.clientDescription.applicationUri);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_LOG_WARNING(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                           "The configured ApplicationURI does not match the URI "
                           "specified in the certificate for the SecurityPolicy %.*s",
                           (int)sp->policyUri.length, sp->policyUri.data);
        }
    }
#endif
}
#endif

UA_StatusCode
UA_Client_connect_async_noSession(UA_Client *client, const char *endpointUrl) {
    client->connectionResult = UA_STATUSCODE_GOOD;

    if(client->channel.state != UA_SECURECHANNELSTATE_FRESH &&
       client->channel.state != UA_SECURECHANNELSTATE_CLOSED)
        return UA_STATUSCODE_GOOD;

#ifdef UA_ENABLE_ENCRYPTION
    verifyClientApplicationURI(client);
#endif

    client->autoConnectSession = false;

    UA_StatusCode res =
        UA_Client_startConnect(client, UA_STRING((char *)(uintptr_t)endpointUrl));
    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "Couldn't connect the client to a TCP secure channel");
    }
    return res;
}

UA_StatusCode
UA_Client_connect_async(UA_Client *client, const char *endpointUrl) {
    UA_StatusCode res = UA_Client_connect_async_noSession(client, endpointUrl);
    client->autoConnectSession = true;
    return res;
}

/* Don't try to connect a session. For this, set the session to closed. */
UA_StatusCode
UA_Client_connect_noSession(UA_Client *client, const char *endpointUrl) {
    /* Start connecting the SecureChannel */
    UA_StatusCode res = UA_Client_connect_async_noSession(client, endpointUrl);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Client_disconnect(client);
        return res;
    }

    /* Loop until timeout or the channel is connected */
    UA_DateTime timeout = UA_DateTime_nowMonotonic() + (UA_DateTime)
        (client->config.timeout * (UA_Double)UA_DATETIME_MSEC);
    while(client->channel.state != UA_SECURECHANNELSTATE_OPEN) {
        UA_DateTime remaining = UA_DateTime_nowMonotonic();
        if(remaining > timeout) {
            res = UA_STATUSCODE_BADTIMEOUT;
            break;
        }
        remaining = timeout - remaining;
        res = UA_Client_run_iterate(client, (UA_UInt16)(remaining / UA_DATETIME_MSEC));
        if(res != UA_STATUSCODE_GOOD)
            break;
    }

    if(res != UA_STATUSCODE_GOOD)
        UA_Client_disconnect(client);
    return res;
}

UA_StatusCode
UA_Client_connect(UA_Client *client, const char *endpointUrl) {
    /* Start connecting the SecureChannel */
    UA_StatusCode res = UA_Client_connect_async(client, endpointUrl);
    if(res != UA_STATUSCODE_GOOD) {
        UA_Client_disconnect(client);
        return res;
    }

    /* Loop until timeout or the channel and session are connected */
    UA_DateTime timeout = UA_DateTime_nowMonotonic() + (UA_DateTime)
        (client->config.timeout * (UA_Double)UA_DATETIME_MSEC);
    while(client->channel.state != UA_SECURECHANNELSTATE_OPEN ||
          client->sessionState != UA_SESSIONSTATE_ACTIVATED) {
        UA_DateTime remaining = UA_DateTime_nowMonotonic();
        if(remaining > timeout) {
            res = UA_STATUSCODE_BADTIMEOUT;
            break;
        }
        remaining = timeout - remaining;
        res = UA_Client_run_iterate(client, (UA_UInt16)(remaining / UA_DATETIME_MSEC));
        if(res != UA_STATUSCODE_GOOD)
            break;
    }

    if(res != UA_STATUSCODE_GOOD)
        UA_Client_disconnect(client);
    return res;
}

void
UA_Client_disconnect_async(UA_Client *client) {
    /* Is a session established? */
    if(client->sessionState == UA_SESSIONSTATE_ACTIVATED) {
        closeSessionAsync(client);
        return;
    }

    /* Is a secure channel established? */
    if(client->channel.state != UA_SECURECHANNELSTATE_FRESH &&
       client->channel.state != UA_SECURECHANNELSTATE_CLOSED)
        closeSecureChannel(client);
}

void
UA_Client_disconnect(UA_Client *client) {
    UA_Client_disconnect_async(client);
    while(client->channel.state != UA_SECURECHANNELSTATE_FRESH &&
          client->channel.state != UA_SECURECHANNELSTATE_CLOSED) {
        UA_StatusCode res = UA_Client_run_iterate(client, (UA_UInt16)client->config.timeout);
        if(res != UA_STATUSCODE_GOOD)
            closeSecureChannel(client); /* In case of timeouts */
    }
}
