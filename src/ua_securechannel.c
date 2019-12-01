/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2014-2018 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2014, 2016-2017 (c) Florian Palm
 *    Copyright 2015-2016 (c) Sten Grüner
 *    Copyright 2015 (c) Oleksiy Vasylyev
 *    Copyright 2016 (c) TorbenD
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017-2018 (c) Mark Giraud, Fraunhofer IOSB
 */

#include <open62541/transport_generated_encoding_binary.h>
#include <open62541/transport_generated_handling.h>
#include <open62541/types_generated_encoding_binary.h>
#include <open62541/types_generated_handling.h>

#include "ua_securechannel.h"
#include "ua_types_encoding_binary.h"
#include "ua_util_internal.h"

#define UA_BITMASK_MESSAGETYPE 0x00ffffffu
#define UA_BITMASK_CHUNKTYPE 0xff000000u

const UA_ByteString UA_SECURITY_POLICY_NONE_URI =
    {47, (UA_Byte *)"http://opcfoundation.org/UA/SecurityPolicy#None"};

#ifdef UA_ENABLE_UNIT_TEST_FAILURE_HOOKS
UA_StatusCode decrypt_verifySignatureFailure;
UA_StatusCode sendAsym_sendFailure;
UA_StatusCode processSym_seqNumberFailure;
#endif

static void
UA_MessageQueue_deleteMessage(UA_Message *me);

void
UA_SecureChannel_init(UA_SecureChannel *channel) {
    /* Linked lists are also initialized by zeroing out */
    memset(channel, 0, sizeof(UA_SecureChannel));
    channel->state = UA_SECURECHANNELSTATE_FRESH;
    TAILQ_INIT(&channel->messages);
}

void
UA_SecureChannel_clear(UA_SecureChannel *channel) {
    /* Delete members */
    UA_ByteString_deleteMembers(&channel->remoteCertificate);
    UA_ByteString_deleteMembers(&channel->localNonce);
    UA_ByteString_deleteMembers(&channel->remoteNonce);
    UA_ChannelSecurityToken_deleteMembers(&channel->securityToken);
    UA_ChannelSecurityToken_deleteMembers(&channel->nextSecurityToken);

    /* Delete the channel context for the security policy */
    if(channel->securityPolicy) {
        channel->securityPolicy->channelModule.deleteContext(channel->channelContext);
        channel->securityPolicy = NULL;
    }

    /* Remove the buffered messages */
    UA_ByteString_deleteMembers(&channel->incompleteChunk);
    UA_Message *me, *me_tmp;
    TAILQ_FOREACH_SAFE(me, &channel->messages, pointers, me_tmp) {
        TAILQ_REMOVE(&channel->messages, me, pointers);
        UA_MessageQueue_deleteMessage(me);
    }

    UA_SecureChannel_init(channel);
}

void
UA_SecureChannel_close(UA_SecureChannel *channel) {
    /* Set the status to closed */
    channel->state = UA_SECURECHANNELSTATE_CLOSED;

    /* Detach from the connection and close the connection */
    if(channel->connection) {
        if(channel->connection->state != UA_CONNECTION_CLOSED)
            channel->connection->close(channel->connection);
        UA_Connection_detachSecureChannel(channel->connection);
    }

    /* Remove session pointer and NULL the pointers back to the SecureChannel
     * from the Session */
    UA_SessionHeader *sh = channel->session;
    if(!sh)
        return;
    sh->channel = NULL;
    channel->session = NULL;
}

UA_StatusCode
UA_SecureChannel_processHELACK(UA_SecureChannel *channel,
                               const UA_ConnectionConfig *localConfig,
                               const UA_ConnectionConfig *remoteConfig) {
    channel->config = *remoteConfig;

    /* The lowest common version is used by both sides */
    if(channel->config.protocolVersion > localConfig->protocolVersion)
        channel->config.protocolVersion = localConfig->protocolVersion;

    /* Can we receive the max send size? */
    if(channel->config.sendBufferSize > localConfig->recvBufferSize)
        channel->config.sendBufferSize = localConfig->recvBufferSize;

    /* Can we send the max receive size? */
    if(channel->config.recvBufferSize > localConfig->sendBufferSize)
        channel->config.recvBufferSize = localConfig->sendBufferSize;

    /* Chunks of at least 8192 bytes must be permissible.
     * See Part 6, Clause 6.7.1 */
    if(channel->config.recvBufferSize < 8192 ||
       channel->config.sendBufferSize < 8192 ||
       (channel->config.maxMessageSize != 0 &&
        channel->config.maxMessageSize < 8192))
        return UA_STATUSCODE_BADINTERNALERROR;

    return UA_STATUSCODE_GOOD;
}

/****************/
/* MessageQueue */
/****************/

static void
UA_MessageQueue_deleteMessage(UA_Message *me) {
    UA_ChunkPayload *cp;
    while((cp = SIMPLEQ_FIRST(&me->chunkPayloads))) {
        if(cp->copied)
            UA_ByteString_deleteMembers(&cp->bytes);
        SIMPLEQ_REMOVE_HEAD(&me->chunkPayloads, pointers);
        UA_free(cp);
    }
    UA_free(me);
}

static void
UA_MessageQueue_deleteLatestMessage(UA_SecureChannel *channel,
                                    UA_UInt32 requestId) {
    UA_Message *me = TAILQ_LAST(&channel->messages, UA_MessageQueue);
    if(!me)
        return;
    if(me->requestId != requestId)
        return;
    TAILQ_REMOVE(&channel->messages, me, pointers);
    UA_MessageQueue_deleteMessage(me);
}

/* If requestId is null, then start a new message. Otherwise see if an existing
 * message is to be extended.*/
static UA_StatusCode
UA_MessageQueue_addChunkPayload(UA_SecureChannel *channel, UA_UInt32 requestId,
                                UA_MessageType messageType, UA_ByteString *chunkPayload,
                                UA_Boolean final) {
    /* Can we continue an existing message? */
    UA_Message *latest = NULL;
    if(messageType == UA_MESSAGETYPE_MSG) {
        latest = TAILQ_LAST(&channel->messages, UA_MessageQueue);
        if(latest) {
            if(latest->requestId != requestId) {
                /* Start of a new message */
                if(!latest->final)
                    return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
                latest = NULL;
            } else {
                if(latest->messageType != messageType) /* MessageType mismatch */
                    return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
                if(latest->final) /* Correct message, but already finalized */
                    return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
            }
        }
    }

    /* Create a new message entry */
    if(!latest) {
        latest = (UA_Message *)UA_malloc(sizeof(UA_Message));
        if(!latest)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        memset(latest, 0, sizeof(UA_Message));
        latest->requestId = requestId;
        latest->messageType = messageType;
        SIMPLEQ_INIT(&latest->chunkPayloads);
        TAILQ_INSERT_TAIL(&channel->messages, latest, pointers);
    }

    /* Test against the connection settings */
    const UA_ConnectionConfig *config = &channel->config;
    UA_assert(config != NULL); /* clang-analyzer false positive */

    if(config->maxChunkCount > 0 &&
       config->maxChunkCount <= latest->chunkPayloadsSize)
        return UA_STATUSCODE_BADRESPONSETOOLARGE;

    if(config->maxMessageSize > 0 &&
       config->maxMessageSize < latest->messageSize + chunkPayload->length)
        return UA_STATUSCODE_BADRESPONSETOOLARGE;

    /* Create a new chunk entry */
    UA_ChunkPayload *cp = (UA_ChunkPayload *)UA_malloc(sizeof(UA_ChunkPayload));
    if(!cp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    cp->bytes = *chunkPayload;
    cp->copied = false;

    /* Add the chunk */
    SIMPLEQ_INSERT_TAIL(&latest->chunkPayloads, cp, pointers);
    latest->chunkPayloadsSize += 1;
    latest->messageSize += chunkPayload->length;
    latest->final = final;

    return UA_STATUSCODE_GOOD;
}

/*****************/
/* Send Messages */
/*****************/

/* Sends an OPN message using asymmetric encryption if defined */
UA_StatusCode
UA_SecureChannel_sendAsymmetricOPNMessage(UA_SecureChannel *channel,
                                          UA_UInt32 requestId, const void *content,
                                          const UA_DataType *contentType) {
    if(channel->securityMode == UA_MESSAGESECURITYMODE_INVALID)
        return UA_STATUSCODE_BADSECURITYMODEREJECTED;

    UA_Connection *connection = channel->connection;
    if(!connection)
        return UA_STATUSCODE_BADSECURECHANNELCLOSED;

    /* Allocate the message buffer */
    UA_ByteString buf = UA_BYTESTRING_NULL;
    UA_StatusCode retval =
        connection->getSendBuffer(connection, channel->config.sendBufferSize, &buf);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Restrict buffer to the available space for the payload */
    UA_Byte *buf_pos = buf.data;
    const UA_Byte *buf_end = &buf.data[buf.length];
    hideBytesAsym(channel, &buf_pos, &buf_end);

    /* Encode the message type and content */
    UA_NodeId typeId = UA_NODEID_NUMERIC(0, contentType->binaryEncodingId);
    retval |= UA_encodeBinary(&typeId, &UA_TYPES[UA_TYPES_NODEID],
                              &buf_pos, &buf_end, NULL, NULL);
    retval |= UA_encodeBinary(content, contentType,
                              &buf_pos, &buf_end, NULL, NULL);
    if(retval != UA_STATUSCODE_GOOD) {
        connection->releaseSendBuffer(connection, &buf);
        return retval;
    }

    const size_t securityHeaderLength = calculateAsymAlgSecurityHeaderLength(channel);

    /* Add padding to the chunk */
#ifdef UA_ENABLE_ENCRYPTION
    padChunkAsym(channel, &buf, securityHeaderLength, &buf_pos);
#endif

    /* The total message length */
    const UA_SecurityPolicy *securityPolicy = channel->securityPolicy;
    size_t pre_sig_length = (uintptr_t)buf_pos - (uintptr_t)buf.data;
    size_t total_length = pre_sig_length;
    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        total_length += securityPolicy->asymmetricModule.cryptoModule.signatureAlgorithm.
            getLocalSignatureSize(securityPolicy, channel->channelContext);

    /* The total message length is known here which is why we encode the headers
     * at this step and not earlier. */
    size_t finalLength = 0;
    retval = prependHeadersAsym(channel, buf.data, buf_end, total_length,
                                securityHeaderLength, requestId, &finalLength);
    if(retval != UA_STATUSCODE_GOOD)
        goto error;

#ifdef UA_ENABLE_ENCRYPTION
    retval = signAndEncryptAsym(channel, pre_sig_length, &buf, securityHeaderLength, total_length);
    if(retval != UA_STATUSCODE_GOOD)
        goto error;
#endif

    /* Send the message, the buffer is freed in the network layer */
    buf.length = finalLength;
    retval = connection->send(connection, &buf);
#ifdef UA_ENABLE_UNIT_TEST_FAILURE_HOOKS
    retval |= sendAsym_sendFailure;
#endif
    return retval;

error:
    connection->releaseSendBuffer(connection, &buf);
    return retval;
}

static UA_StatusCode
sendSymmetricChunk(UA_MessageContext *messageContext) {
    UA_SecureChannel *channel = messageContext->channel;
    const UA_SecurityPolicy *securityPolicy = channel->securityPolicy;
    UA_Connection *connection = channel->connection;
    if(!connection)
        return UA_STATUSCODE_BADINTERNALERROR;

    size_t bodyLength = 0;
    UA_StatusCode res = checkLimitsSym(messageContext, &bodyLength);
    if(res != UA_STATUSCODE_GOOD)
        goto error;

    /* Add padding */
#ifdef UA_ENABLE_ENCRYPTION
    padChunkSym(messageContext, bodyLength);
#endif

    /* The total message length */
    size_t pre_sig_length = (uintptr_t)(messageContext->buf_pos) -
        (uintptr_t)messageContext->messageBuffer.data;
    size_t total_length = pre_sig_length;
    if(channel->securityMode == UA_MESSAGESECURITYMODE_SIGN ||
       channel->securityMode == UA_MESSAGESECURITYMODE_SIGNANDENCRYPT)
        total_length += securityPolicy->symmetricModule.cryptoModule.signatureAlgorithm.
            getLocalSignatureSize(securityPolicy, channel->channelContext);

    /* Space for the padding and the signature have been reserved in setBufPos() */
    UA_assert(total_length <= channel->config.sendBufferSize);

    /* For giving the buffer to the network layer */
    messageContext->messageBuffer.length = total_length;

    UA_assert(res == UA_STATUSCODE_GOOD);
    res = encodeHeadersSym(messageContext, total_length);
    if(res != UA_STATUSCODE_GOOD)
        goto error;

#ifdef UA_ENABLE_ENCRYPTION
    res = signChunkSym(messageContext, pre_sig_length);
    if(res != UA_STATUSCODE_GOOD)
        goto error;

    res = encryptChunkSym(messageContext, total_length);
    if(res != UA_STATUSCODE_GOOD)
        goto error;
#endif

    /* Send the chunk, the buffer is freed in the network layer */
    return connection->send(channel->connection, &messageContext->messageBuffer);

error:
    connection->releaseSendBuffer(channel->connection, &messageContext->messageBuffer);
    return res;
}

/* Callback from the encoding layer. Send the chunk and replace the buffer. */
static UA_StatusCode
sendSymmetricEncodingCallback(void *data, UA_Byte **buf_pos, const UA_Byte **buf_end) {
    /* Set buf values from encoding in the messagecontext */
    UA_MessageContext *mc = (UA_MessageContext *)data;
    mc->buf_pos = *buf_pos;
    mc->buf_end = *buf_end;

    /* Send out */
    UA_StatusCode retval = sendSymmetricChunk(mc);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_SecureChannel *channel = mc->channel;
    if(!channel)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_Connection *connection = mc->channel->connection;
    if(!connection)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Set a new buffer for the next chunk */
    retval = connection->getSendBuffer(connection, channel->config.sendBufferSize,
                                       &mc->messageBuffer);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Hide bytes for header, padding and signature */
    setBufPos(mc);
    *buf_pos = mc->buf_pos;
    *buf_end = mc->buf_end;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_MessageContext_begin(UA_MessageContext *mc, UA_SecureChannel *channel,
                        UA_UInt32 requestId, UA_MessageType messageType) {
    UA_Connection *connection = channel->connection;
    if(!connection)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(messageType != UA_MESSAGETYPE_MSG && messageType != UA_MESSAGETYPE_CLO)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Create the chunking info structure */
    mc->channel = channel;
    mc->requestId = requestId;
    mc->chunksSoFar = 0;
    mc->messageSizeSoFar = 0;
    mc->final = false;
    mc->messageBuffer = UA_BYTESTRING_NULL;
    mc->messageType = messageType;

    /* Allocate the message buffer */
    UA_StatusCode retval =
        connection->getSendBuffer(connection, channel->config.sendBufferSize,
                                  &mc->messageBuffer);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Hide bytes for header, padding and signature */
    setBufPos(mc);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_MessageContext_encode(UA_MessageContext *mc, const void *content,
                         const UA_DataType *contentType) {
    UA_StatusCode retval =
        UA_encodeBinary(content, contentType, &mc->buf_pos, &mc->buf_end,
                        sendSymmetricEncodingCallback, mc);
    if(retval != UA_STATUSCODE_GOOD && mc->messageBuffer.length > 0)
        UA_MessageContext_abort(mc);
    return retval;
}

UA_StatusCode
UA_MessageContext_finish(UA_MessageContext *mc) {
    mc->final = true;
    return sendSymmetricChunk(mc);
}

void
UA_MessageContext_abort(UA_MessageContext *mc) {
    UA_Connection *connection = mc->channel->connection;
    connection->releaseSendBuffer(connection, &mc->messageBuffer);
}

UA_StatusCode
UA_SecureChannel_sendSymmetricMessage(UA_SecureChannel *channel, UA_UInt32 requestId,
                                      UA_MessageType messageType, void *payload,
                                      const UA_DataType *payloadType) {
    if(!channel || !channel->connection || !payload || !payloadType)
        return UA_STATUSCODE_BADINTERNALERROR;

    if(channel->connection->state == UA_CONNECTION_CLOSED)
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    UA_MessageContext mc;
    UA_StatusCode retval = UA_MessageContext_begin(&mc, channel, requestId, messageType);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Assert's required for clang-analyzer */
    UA_assert(mc.buf_pos == &mc.messageBuffer.data[UA_SECURE_MESSAGE_HEADER_LENGTH]);
    UA_assert(mc.buf_end <= &mc.messageBuffer.data[mc.messageBuffer.length]);

    UA_NodeId typeId = UA_NODEID_NUMERIC(0, payloadType->binaryEncodingId);
    retval = UA_MessageContext_encode(&mc, &typeId, &UA_TYPES[UA_TYPES_NODEID]);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_MessageContext_encode(&mc, payload, payloadType);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    return UA_MessageContext_finish(&mc);
}

/********************/
/* Process Messages */
/********************/

static UA_StatusCode
processMessage(UA_SecureChannel *channel, const UA_Message *message,
               void *application, UA_ProcessMessageCallback callback) {
    /* No need to combine chunks */
    if(message->chunkPayloadsSize == 1) {
        UA_ChunkPayload *cp = SIMPLEQ_FIRST(&message->chunkPayloads);
        callback(application, channel, message->messageType, message->requestId, &cp->bytes);
        return UA_STATUSCODE_GOOD;
    }

    /* Allocate memory */
    UA_ByteString bytes;
    bytes.data = (UA_Byte *)UA_malloc(message->messageSize);
    if(!bytes.data) {
        UA_LOG_ERROR(channel->securityPolicy->logger, UA_LOGCATEGORY_SECURECHANNEL,
                     "Could not allocate the memory to assemble the message");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    bytes.length = message->messageSize;

    /* Assemble the full message */
    size_t curPos = 0;
    UA_ChunkPayload *cp;
    SIMPLEQ_FOREACH(cp, &message->chunkPayloads, pointers) {
        memcpy(&bytes.data[curPos], cp->bytes.data, cp->bytes.length);
        curPos += cp->bytes.length;
    }

    /* Process the message */
    callback(application, channel, message->messageType, message->requestId, &bytes);
    UA_ByteString_deleteMembers(&bytes);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_SecureChannel_processCompleteMessages(UA_SecureChannel *channel, void *application,
                                         UA_ProcessMessageCallback callback) {
    UA_Message *message, *tmp_message;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    TAILQ_FOREACH_SAFE(message, &channel->messages, pointers, tmp_message) {
        /* Stop at the first incomplete message */
        if(!message->final)
            break;

        /* Has the channel been closed (during the last message)? */
        if(channel->state == UA_SECURECHANNELSTATE_CLOSED)
            break;

        /* Remove the current message before processing */
        TAILQ_REMOVE(&channel->messages, message, pointers);

        /* Process */
        retval = processMessage(channel, message, application, callback);
        if(retval != UA_STATUSCODE_GOOD)
            break;

        /* Clean up the message */
        UA_ChunkPayload *payload;
        while((payload = SIMPLEQ_FIRST(&message->chunkPayloads))) {
            if(payload->copied)
                UA_ByteString_deleteMembers(&payload->bytes);
            SIMPLEQ_REMOVE_HEAD(&message->chunkPayloads, pointers);
            UA_free(payload);
        }
        UA_free(message);
    }
    return retval;
}

/**********************************************/
/* Assemble Messages from Chunks from Packets */
/**********************************************/

static UA_StatusCode
MSGToMessageQueue(UA_SecureChannel *channel, UA_ByteString *chunkContent,
                  UA_ChunkType chunkType) {
    /* Decode and check the symmetric security header (tokenId) */
    size_t offset = 0;
    UA_SymmetricAlgorithmSecurityHeader symmetricSecurityHeader;
    UA_SymmetricAlgorithmSecurityHeader_init(&symmetricSecurityHeader);
    UA_StatusCode retval =
        UA_SymmetricAlgorithmSecurityHeader_decodeBinary(chunkContent, &offset,
                                                         &symmetricSecurityHeader);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Do some checks that depend on a configured SecurityPolicy */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    /* Help fuzzing by always setting the correct tokenId */
    symmetricSecurityHeader.tokenId = channel->securityToken.tokenId;
#endif
    retval = checkSymHeader(channel, symmetricSecurityHeader.tokenId);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    UA_UInt32 requestId = 0;
    UA_UInt32 sequenceNumber = 0;
    retval = decryptAndVerifyChunk(channel,
                                   &channel->securityPolicy->symmetricModule.cryptoModule,
                                   UA_MESSAGETYPE_MSG, chunkContent, offset, &requestId,
                                   &sequenceNumber, chunkContent);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Check the sequence number. Skip sequence number checking for fuzzer to
     * improve coverage */
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    retval = processSequenceNumberSym(channel, sequenceNumber);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
#endif

    /* Add to the MessageQueue */
    switch(chunkType) {
    case UA_CHUNKTYPE_INTERMEDIATE:
    case UA_CHUNKTYPE_FINAL:
        return UA_MessageQueue_addChunkPayload(channel, requestId, UA_MESSAGETYPE_MSG,
                                               chunkContent, chunkType == UA_CHUNKTYPE_FINAL); 
    case UA_CHUNKTYPE_ABORT:
        UA_MessageQueue_deleteLatestMessage(channel, requestId);
        return UA_STATUSCODE_GOOD;
    default:
        return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
    }
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
processIndividualChunk(UA_SecureChannel *channel, UA_Byte **posp,
                       const UA_Byte *end, UA_Boolean *done) {
    /* At least 12 byte needed for the header. Wait for the next chunk. */
    UA_Byte *pos = *posp;
    const size_t remaining = (uintptr_t)end - (uintptr_t)pos;
    if(remaining < 12) {
        *done = true;
        return UA_STATUSCODE_GOOD;
    }

    /* Decode the header out of the first 8 byte */
    UA_ByteString temp = { 12, (UA_Byte*)(uintptr_t)pos };
    size_t offset = 0;
    UA_SecureConversationMessageHeader scmh;
    /* Cannot fail... */
    UA_SecureConversationMessageHeader_decodeBinary(&temp, &offset, &scmh);

    /* The chunk size is not allowed */
    if(scmh.messageHeader.messageSize < 16 ||
       scmh.messageHeader.messageSize > channel->config.recvBufferSize)
        return UA_STATUSCODE_BADTCPMESSAGETOOLARGE;

    /* The chunk is incomplete */
    if(scmh.messageHeader.messageSize > remaining) {
        *done = true;
        return UA_STATUSCODE_GOOD;
    }

    /* The wrong ChannelId. Non-opened channels have the id zero. */
#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if(scmh.secureChannelId != channel->securityToken.channelId &&
       channel->state != UA_SECURECHANNELSTATE_FRESH)
        return UA_STATUSCODE_BADSECURECHANNELIDINVALID;
#endif

    /* Check the chunk type */
    UA_ChunkType chunkType = (UA_ChunkType)
        (scmh.messageHeader.messageTypeAndChunkType & UA_BITMASK_CHUNKTYPE);
    if(chunkType != UA_CHUNKTYPE_FINAL &&
       chunkType != UA_CHUNKTYPE_INTERMEDIATE &&
       chunkType != UA_CHUNKTYPE_ABORT)
        return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;

    /* Move received full chunks into the MessageQueue. The chunk content begins
     * after the SecureConversationMessageHeader. */
    *posp += scmh.messageHeader.messageSize;
    *done = false;
    UA_ByteString chunkContent =
        {scmh.messageHeader.messageSize - UA_SECURE_CONVERSATION_MESSAGE_HEADER_LENGTH,
         (UA_Byte*)pos + UA_SECURE_CONVERSATION_MESSAGE_HEADER_LENGTH};

    /* Dispatch on the message type */
    UA_MessageType msgType = (UA_MessageType)
        scmh.messageHeader.messageTypeAndChunkType & UA_BITMASK_MESSAGETYPE;

    /* MSG and CLO: Symmetric encryption */
    if(msgType == UA_MESSAGETYPE_MSG ||
       msgType == UA_MESSAGETYPE_CLO) {
        if(channel->state != UA_SECURECHANNELSTATE_OPEN)
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        return MSGToMessageQueue(channel, &chunkContent, chunkType);
    }

    /* No chunking allowed for the remaining chunk types */
    if(chunkType != UA_CHUNKTYPE_FINAL)
        return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;

    /* These messages are part of the initial handshake. We expect the
     * connection to be in a certain state to protect against DoS attacks. */
    switch(msgType) {
    case UA_MESSAGETYPE_HEL:
        if(channel->state != UA_SECURECHANNELSTATE_FRESH)
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        channel->state = UA_SECURECHANNELSTATE_HEL_RECEIVED;
        break;

    case UA_MESSAGETYPE_ACK:
        if(channel->state != UA_SECURECHANNELSTATE_HEL_SENT)
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        channel->state = UA_SECURECHANNELSTATE_ACK_RECEIVED;
        break;

    case UA_MESSAGETYPE_ERR:
        if(channel->state != UA_SECURECHANNELSTATE_HEL_SENT)
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;

    case UA_MESSAGETYPE_OPN:
        if(channel->state != UA_SECURECHANNELSTATE_ACK_SENT &&
           channel->state != UA_SECURECHANNELSTATE_OPN_SENT &&
           channel->state != UA_SECURECHANNELSTATE_OPEN)
            return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
        if(channel->state != UA_SECURECHANNELSTATE_OPEN)
            channel->state = UA_SECURECHANNELSTATE_OPN_RECEIVED;
        /* Attention! Don't add messages to the queue directly after an OPN.
         * First the OPN message has to be processed. This can switch out
         * encryption keys for the following messages. So we set "done" to
         * true. */
        *done = true;
        break;

    default:
        return UA_STATUSCODE_BADTCPMESSAGETYPEINVALID;
    }

    return UA_MessageQueue_addChunkPayload(channel, 0, msgType, &chunkContent, true);
}

static UA_StatusCode
bufferIncompleteChunk(UA_SecureChannel *channel,
                      const UA_Byte *pos, const UA_Byte *end) {
    UA_assert(channel->incompleteChunk.length == 0);
    UA_assert(pos < end);
    size_t length = (uintptr_t)end - (uintptr_t)pos;
    UA_StatusCode retval = UA_ByteString_allocBuffer(&channel->incompleteChunk, length);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    memcpy(channel->incompleteChunk.data, pos, length);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_SecureChannel_processPacket(UA_SecureChannel *channel,
                               const UA_ByteString *packet) {
    /* Has the SecureChannel timed out? */
    if(channel->state == UA_SECURECHANNELSTATE_CLOSED)
        return UA_STATUSCODE_BADSECURECHANNELCLOSED;

    UA_Byte *pos = packet->data;
    const UA_Byte *end = &packet->data[packet->length];
    UA_ByteString appended = channel->incompleteChunk;

    /* Prepend the incomplete last chunk. This is usually done in the
     * networklayer. But we test for a buffered incomplete chunk here again to
     * work around "lazy" network layers. */
    if(appended.length > 0) {
        channel->incompleteChunk = UA_BYTESTRING_NULL;
        UA_Byte *t = (UA_Byte*)UA_realloc(appended.data, appended.length + packet->length);
        if(!t) {
            UA_ByteString_deleteMembers(&appended);
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        memcpy(&t[appended.length], pos, packet->length);
        appended.data = t;
        appended.length += packet->length;
        pos = t;
        end = &t[appended.length];
    }

    UA_assert(channel->incompleteChunk.length == 0);

    /* Loop over the received chunks. pos is increased with each chunk. */
    UA_Boolean done = false;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    while(!done) {
        retval = processIndividualChunk(channel, &pos, end, &done);
        /* If an irrecoverable error happens: do not buffer incomplete chunk */
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    if(end > pos)
        retval = bufferIncompleteChunk(channel, pos, end);

 cleanup:
    UA_ByteString_deleteMembers(&appended);
    return retval;
}

UA_StatusCode
UA_SecureChannel_persistIncompleteMessages(UA_SecureChannel *channel) {
    UA_Message *me;
    TAILQ_FOREACH(me, &channel->messages, pointers) {
        UA_ChunkPayload *cp;
        SIMPLEQ_FOREACH(cp, &me->chunkPayloads, pointers) {
            if(cp->copied)
                continue;
            UA_ByteString copy;
            UA_StatusCode retval = UA_ByteString_copy(&cp->bytes, &copy);
            if(retval != UA_STATUSCODE_GOOD) {
                UA_SecureChannel_close(channel);
                return retval;
            }
            cp->bytes = copy;
            cp->copied = true;
        }
    }
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_SecureChannel_receiveChunksBlocking(UA_SecureChannel *channel, UA_UInt32 timeout) {
    UA_Connection *connection = channel->connection;
    if(!connection)
        return UA_STATUSCODE_BADSECURECHANNELCLOSED;
    
    UA_DateTime now = UA_DateTime_nowMonotonic();
    UA_DateTime maxDate = now + (timeout * UA_DATETIME_MSEC);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    while(true) {
        /* Listen for messages to arrive */
        UA_ByteString packet = UA_BYTESTRING_NULL;
        retval = connection->recv(connection, &packet, timeout);
        if(retval != UA_STATUSCODE_GOOD)
            break;

        /* Try to process one complete chunk */
        retval = UA_SecureChannel_processPacket(channel, &packet);
        retval |= UA_SecureChannel_persistIncompleteMessages(channel);
        connection->releaseRecvBuffer(connection, &packet);
        if(retval != UA_STATUSCODE_GOOD)
            break;

        /* Have one complete message */
        UA_Message *m = TAILQ_FIRST(&channel->messages);
        if(m && m->final)
            break;

        /* We received a message. But the chunk is incomplete. Compute the
         * remaining timeout. */
        now = UA_DateTime_nowMonotonic();

        /* >= avoid timeout to be set to 0 */
        if(now >= maxDate)
            return UA_STATUSCODE_GOODNONCRITICALTIMEOUT;

        /* round always to upper value to avoid timeout to be set to 0
         * if(maxDate - now) < (UA_DATETIME_MSEC/2) */
        timeout = (UA_UInt32)(((maxDate - now) + (UA_DATETIME_MSEC - 1)) / UA_DATETIME_MSEC);
    }
    return retval;
}

UA_StatusCode
UA_SecureChannel_receiveChunksNonBlocking(UA_SecureChannel *channel) {
    UA_Connection *connection = channel->connection;
    if(!connection)
        return UA_STATUSCODE_BADSECURECHANNELCLOSED;

    /* Listen for messages to arrive */
    UA_ByteString packet = UA_BYTESTRING_NULL;
    UA_StatusCode retval = connection->recv(connection, &packet, 1);
    if(retval != UA_STATUSCODE_GOOD) {
        if(retval != UA_STATUSCODE_GOODNONCRITICALTIMEOUT)
            retval = UA_STATUSCODE_GOOD;
        return retval;
    }

    /* Process the packet */
    retval = UA_SecureChannel_processPacket(channel, &packet);
    retval |= UA_SecureChannel_persistIncompleteMessages(channel);
    connection->releaseRecvBuffer(connection, &packet);
    return retval;
}
