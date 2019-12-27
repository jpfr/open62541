/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2015-2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2015-2016 (c) Sten Grüner
 *    Copyright 2015-2016 (c) Chris Iatrou
 *    Copyright 2015 (c) hfaham
 *    Copyright 2015-2017 (c) Florian Palm
 *    Copyright 2017-2018 (c) Thomas Stalder, Blue Time Concept SA
 *    Copyright 2015 (c) Holger Jeromin
 *    Copyright 2015 (c) Oleksiy Vasylyev
 *    Copyright 2016 (c) TorbenD
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2016 (c) Lykurg
 *    Copyright 2017 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2018 (c) Kalycito Infotech Private Limited
 */

#include <open62541/types_generated_encoding_binary.h>
#include <open62541/transport_generated.h>
#include <open62541/transport_generated_encoding_binary.h>
#include <open62541/transport_generated_handling.h>

#include "ua_client_internal.h"
#include "ua_connection_internal.h"
#include "ua_types_encoding_binary.h"

static const UA_NodeId
serviceFaultId = {0, UA_NODEIDTYPE_NUMERIC, {UA_NS0ID_SERVICEFAULT_ENCODING_DEFAULTBINARY}};

/********************/
/* Client Lifecycle */
/********************/

static void
UA_Client_init(UA_Client* client) {
    UA_SecureChannel_init(&client->channel,
                          &client->config.localConnectionConfig);
    if(client->config.stateCallback)
        client->config.stateCallback(client, UA_SECURECHANNELSTATE_FRESH,
                                     UA_SESSIONSTATE_FRESH);
    UA_Timer_init(&client->timer);
    UA_WorkQueue_init(&client->workQueue);
}

UA_Client UA_EXPORT *
UA_Client_newWithConfig(const UA_ClientConfig *config) {
    if(!config)
        return NULL;
    UA_Client *client = (UA_Client*)UA_malloc(sizeof(UA_Client));
    if(!client)
        return NULL;
    memset(client, 0, sizeof(UA_Client));
    client->config = *config;
    UA_Client_init(client);
    return client;
}

static void
UA_ClientConfig_clear(UA_ClientConfig *config) {
    UA_ApplicationDescription_clear(&config->clientDescription);

    UA_ExtensionObject_clear(&config->userIdentityToken);
    UA_String_clear(&config->securityPolicyUri);

    UA_EndpointDescription_clear(&config->endpoint);
    UA_UserTokenPolicy_clear(&config->userTokenPolicy);

    if(config->certificateVerification.clear)
        config->certificateVerification.clear(&config->certificateVerification);

    /* Delete the SecurityPolicies */
    if(config->securityPolicies == 0)
        return;
    for(size_t i = 0; i < config->securityPoliciesSize; i++)
        config->securityPolicies[i].clear(&config->securityPolicies[i]);
    UA_free(config->securityPolicies);
    config->securityPolicies = 0;

    if (config->logger.context && config->logger.clear) {
        config->logger.clear(config->logger.context);
        config->logger.context = NULL;
        config->logger.log = NULL;
        config->logger.clear = NULL;
    }
}

static void
UA_Client_clear(UA_Client *client) {
    UA_Client_disconnect(client);
    if(client->connection.free)
        client->connection.free(&client->connection);
    UA_NodeId_clear(&client->authenticationToken);
    UA_String_clear(&client->endpointUrl);

    /* Delete the async service calls */
    UA_Client_AsyncService_removeAll(client, UA_STATUSCODE_BADSHUTDOWN);

    /* Delete the subscriptions */
#ifdef UA_ENABLE_SUBSCRIPTIONS
    UA_Client_Subscriptions_clean(client);
#endif

    UA_Timer_deleteMembers(&client->timer); /* Delete the timed work */
    UA_WorkQueue_cleanup(&client->workQueue); /* Clean up the work queue */
}

void
UA_Client_reset(UA_Client* client) {
    UA_Client_clear(client);
    UA_Client_init(client);
}

void
UA_Client_delete(UA_Client* client) {
    UA_Client_clear(client);
    UA_ClientConfig_clear(&client->config);
    UA_free(client);
}

void
UA_Client_getState(UA_Client *client,
                   UA_SecureChannelState *channelState,
                   UA_SessionState *sessionState) {
    *channelState = client->channel.state;
    *sessionState = client->sessionState;
}

UA_ClientConfig *
UA_Client_getConfig(UA_Client *client) {
    if(!client)
        return NULL;
    return &client->config;
}

/****************/
/* Raw Services */
/****************/

/* For synchronous service calls. Execute async responses with a callback. When
 * the response with the correct requestId turns up, return it via the
 * SyncResponseDescription pointer. */
typedef struct {
    UA_Client *client;
    UA_Boolean received;
    UA_UInt32 requestId;
    void *response;
    const UA_DataType *responseType;
} SyncResponseDescription;

/* For both synchronous and asynchronous service calls */
static UA_StatusCode
sendSymmetricServiceRequest(UA_Client *client, const void *request,
                            const UA_DataType *requestType, UA_UInt32 *requestId) {
    /* Adjusting the request header. The const attribute is violated, but we
     * only touch the following members: */
    UA_RequestHeader *rr = (UA_RequestHeader*)(uintptr_t)request;
    rr->authenticationToken = client->authenticationToken; /* cleaned up at the end */
    rr->timestamp = UA_DateTime_now();
    rr->requestHandle = ++client->requestHandle;

    /* Send the request */
    UA_UInt32 rqId = ++client->requestId;
#ifdef UA_ENABLE_TYPEDESCRIPTION
    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Sending a request of type %s", requestType->typeName);
#else
    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Sending a request of type %i",
                         requestType->typeId.identifier.numeric);
#endif

    /* Change to the new security token if the secure channel has been renewed */
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(client->channel.nextSecurityToken.tokenId != 0) {
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Revolving the token");
        res = UA_SecureChannel_revolveTokens(&client->channel);
        if(res != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                                 "Could not revolve the tokens with StatusCode %s",
                                 UA_StatusCode_name(res));
            return res;
        }
    }

    res = UA_SecureChannel_sendSymmetricMessage(&client->channel, rqId,
                                                UA_MESSAGETYPE_MSG, rr, requestType);

    /* Do not return the token to the user */
    UA_NodeId_init(&rr->authenticationToken);

    if(res == UA_STATUSCODE_GOOD)
        *requestId = rqId;
    return res;
}

/* Processes the received service response. Either with an async callback or by
 * decoding the message and returning it "upwards" in the
 * SyncResponseDescription. */
static UA_StatusCode
UA_Client_processMSG(SyncResponseDescription *rd, UA_UInt32 requestId,
                     const UA_ByteString *message) {
    UA_Client *client = rd->client;
    const UA_DataType *expectedType = rd->responseType;
    AsyncServiceCall *ac = NULL;

    /* Async response? */
    if(!expectedType || requestId != rd->requestId) {
        LIST_FOREACH(ac, &client->asyncServiceCalls, pointers) {
            if(ac->requestId == requestId)
                break;
        }
        if(!ac)
            return UA_STATUSCODE_BADREQUESTHEADERINVALID;

        /* Remove from list. We might close the SecureChannel in the async callback */
        LIST_REMOVE(ac, pointers);
        expectedType = ac->responseType;
    }

    UA_NodeId expectedNodeId = UA_NODEID_NUMERIC(0, expectedType->binaryEncodingId);

    /* Stack-allocate the response for async responses */
    UA_STACKARRAY(UA_Byte, responseBuf, expectedType->memSize);
    void *response = rd->response;
    if(ac)
        response = (void*)(uintptr_t)&responseBuf[0]; /* workaround aliasing rules */

    /* Decode the data type identifier of the response */
    size_t offset = 0;
    UA_NodeId responseId;
    UA_StatusCode retval = UA_NodeId_decodeBinary(message, &offset, &responseId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_init(response, expectedType);
        goto process_response;
    }

    /* Check that the response type matches */
    if(UA_NodeId_equal(&responseId, &expectedNodeId)) {
        /* Expected response */
#ifdef UA_ENABLE_TYPEDESCRIPTION
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Decode a message of type %s", expectedType->typeName);
#else
        UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                             "Decode a message of type %u", responseId.identifier.numeric);
#endif
        retval = UA_decodeBinary(message, &offset, response, expectedType,
                                 client->config.customDataTypes);
    } else if(UA_NodeId_equal(&responseId, &serviceFaultId)) {
        /* Received a servicefault */
        UA_LOG_WARNING_CHANNEL(&client->config.logger, &client->channel,
                               "Received a ServiceFault response with StatusCode %s",
                               UA_StatusCode_name(((UA_ResponseHeader*)rd->response)->serviceResult));
        UA_init(response, expectedType);
        retval = UA_decodeBinary(message, &offset, response,
                                 &UA_TYPES[UA_TYPES_SERVICEFAULT], NULL);
    } else {
        /* Received a wrong response type */
        UA_LOG_ERROR_CHANNEL(&client->config.logger, &client->channel,
                             "Reply contains the wrong service response");
        UA_init(response, expectedType);
        retval = UA_STATUSCODE_BADCOMMUNICATIONERROR;
        UA_NodeId_clear(&responseId); /* The only place where ne need to clear */
    }

    if(retval == UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED)
        retval = UA_STATUSCODE_BADRESPONSETOOLARGE;

 process_response:

    /* Synchronous response. The response was decoded into rd. */
    if(!ac) {
        rd->received = true;
        return retval;
    }

    /* Asynchronous response */

    /* A problem occured, set in the serviceresult */
    if(retval != UA_STATUSCODE_GOOD)
        ((UA_ResponseHeader*)response)->serviceResult = retval;

    /* Call the async response callback */
    if(ac->callback)
        ac->callback(client, ac->userdata, requestId, response);

    /* Clean up */
    UA_clear(response, expectedType);
    UA_free(ac);
    return retval;
}

static void
processServiceResponse(void *application, UA_SecureChannel *channel,
                       UA_MessageType messageType, UA_UInt32 requestId,
                       const UA_ByteString *message) {
    SyncResponseDescription *rd = (SyncResponseDescription*)application;
    UA_Client *client = rd->client;

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    switch(messageType) {
    case UA_MESSAGETYPE_ACK:
        UA_LOG_TRACE_CHANNEL(&client->config.logger, channel, "Process an ACK message");
        res = UA_Client_processACK(client, message);
        break;

    case UA_MESSAGETYPE_ERR:
        UA_LOG_TRACE_CHANNEL(&client->config.logger, channel, "Process an ERR message");
        UA_Client_processERR(client, message); /* Closes the channel internally */
        break;

    case UA_MESSAGETYPE_OPN: {
        UA_LOG_TRACE_CHANNEL(&client->config.logger, channel, "Process an OPN response message");
        UA_ByteString editableMessage = *message; /* In situ edits for decryption */
        UA_Boolean renew = (channel->state == UA_SECURECHANNELSTATE_OPEN);
        res = UA_Client_processOPN(client, &editableMessage, renew);
        break;
    }

    case UA_MESSAGETYPE_MSG:
        UA_LOG_TRACE_CHANNEL(&client->config.logger, channel, "Process an MSG response message");
        res = UA_Client_processMSG(rd, requestId, message);
        break;

    default:
        UA_LOG_TRACE_CHANNEL(&client->config.logger, channel, "Received an unexpected message type");
        closeSecureChannel(client);
        break;
    }

    if(res != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR_CHANNEL(&client->config.logger, channel,
                             "Processing the message failed with StatusCode %s",
                             UA_StatusCode_name(res));
        closeSecureChannel(client);
    }
}

/* Receive and process messages until a synchronous message arrives or the
 * timout finishes */
static UA_StatusCode
receiveServiceResponse(UA_Client *client, void *response, const UA_DataType *responseType,
                       UA_DateTime maxDate, const UA_UInt32 *synchronousRequestId) {
    /* Prepare the response and the structure we give into processServiceResponse */
    SyncResponseDescription rd = { client, false, 0, response, responseType };

    /* Do we expect a synchronous response? */
    if(synchronousRequestId)
        rd.requestId = *synchronousRequestId;

    /* Process messages until the synchronous response is received (if there is one) */
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    UA_DateTime now = UA_DateTime_nowMonotonic();
    while(true) {
        if(now > maxDate)
            return UA_STATUSCODE_GOODNONCRITICALTIMEOUT;

        /* Avoid timeout to be set to 0 */
        UA_UInt32 timeout = (UA_UInt32)((maxDate - now) / UA_DATETIME_MSEC);
        if(timeout == 0)
            timeout = 1;

        /* Receive */
        UA_LOG_TRACE_CHANNEL(&client->config.logger, &client->channel,
                             "Receive blocking with a timout of %u msec", timeout);
        res = UA_SecureChannel_receiveBlocking(&client->channel, &rd,
                                               processServiceResponse, timeout);

        /* A problem has come up */
        if(res != UA_STATUSCODE_GOOD) {
            if(res == UA_STATUSCODE_GOODNONCRITICALTIMEOUT) {
                UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                                     "Timeout during recv");
            } else {
                UA_LOG_WARNING_CHANNEL(&client->config.logger, &client->channel,
                                       "Could not receive blocking with StatusCode %s",
                                       UA_StatusCode_name(res));
            }
            return res;
        }

        /* The synchronous response has been received */
        if(!synchronousRequestId || rd.received)
            break;

        now = UA_DateTime_nowMonotonic();
    }
    return res;
}

void
UA_Client_Service(UA_Client *client, const void *request,
                  const UA_DataType *requestType, void *response,
                  const UA_DataType *responseType) {
    UA_init(response, responseType);
    UA_ResponseHeader *respHeader = (UA_ResponseHeader*)response;

    /* Send the request */
    UA_UInt32 requestId;
    UA_StatusCode retval = sendSymmetricServiceRequest(client, request, requestType, &requestId);
    if(retval != UA_STATUSCODE_GOOD) {
        if(retval == UA_STATUSCODE_BADENCODINGLIMITSEXCEEDED)
            respHeader->serviceResult = UA_STATUSCODE_BADREQUESTTOOLARGE;
        else
            respHeader->serviceResult = retval;
        UA_Client_disconnect(client);
        return;
    }

    /* Retrieve the response */
    UA_DateTime maxDate = UA_DateTime_nowMonotonic() +
        (client->config.timeout * UA_DATETIME_MSEC);
    retval = receiveServiceResponse(client, response, responseType, maxDate, &requestId);
    if(retval == UA_STATUSCODE_GOODNONCRITICALTIMEOUT) {
        /* In synchronous service, if we have don't have a reply we need to close the connection */
        UA_Client_disconnect(client);
        retval = UA_STATUSCODE_BADCONNECTIONCLOSED;
    }
    if(retval != UA_STATUSCODE_GOOD)
        respHeader->serviceResult = retval;
}

void
UA_Client_AsyncService_cancel(UA_Client *client, AsyncServiceCall *ac,
                              UA_StatusCode statusCode) {
    /* Create an empty response with the statuscode */
    UA_STACKARRAY(UA_Byte, responseBuf, ac->responseType->memSize);
    void *resp = (void*)(uintptr_t)&responseBuf[0]; /* workaround aliasing rules */
    UA_init(resp, ac->responseType);
    ((UA_ResponseHeader*)resp)->serviceResult = statusCode;

    if(ac->callback)
        ac->callback(client, ac->userdata, ac->requestId, resp);

    /* Clean up the response. Users might move data into it. For whatever reasons. */
    UA_clear(resp, ac->responseType);
}

void UA_Client_AsyncService_removeAll(UA_Client *client, UA_StatusCode statusCode) {
    AsyncServiceCall *ac, *ac_tmp;
    LIST_FOREACH_SAFE(ac, &client->asyncServiceCalls, pointers, ac_tmp) {
        LIST_REMOVE(ac, pointers);
        UA_Client_AsyncService_cancel(client, ac, statusCode);
        UA_free(ac);
    }
}

UA_StatusCode
UA_Client_AsyncService_customTimeout(UA_Client *client, const void *request,
                                     const UA_DataType *requestType,
                                     UA_ClientAsyncServiceCallback callback,
                                     const UA_DataType *responseType,
                                     void *context, UA_UInt32 *requestId,
                                     UA_UInt32 timeout) {
    /* Prepare the entry for the linked list */
    AsyncServiceCall *ac = (AsyncServiceCall*)UA_malloc(sizeof(AsyncServiceCall));
    if(!ac)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    ac->callback = callback;
    ac->responseType = responseType;
    ac->userdata = context;
    ac->timeout = timeout;

    /* Call the service and set the requestId */
    UA_StatusCode retval = sendSymmetricServiceRequest(client, request, requestType, &ac->requestId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_free(ac);
        return retval;
    }

    ac->start = UA_DateTime_nowMonotonic();

    /* Store the entry for async processing */
    LIST_INSERT_HEAD(&client->asyncServiceCalls, ac, pointers);
    if(requestId)
        *requestId = ac->requestId;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Client_AsyncService(UA_Client *client, const void *request,
                       const UA_DataType *requestType,
                       UA_ClientAsyncServiceCallback callback,
                       const UA_DataType *responseType,
                       void *context, UA_UInt32 *requestId) {
    return UA_Client_AsyncService_customTimeout(client, request, requestType, callback,
                                                responseType, context, requestId,
                                                client->config.timeout);
}

UA_StatusCode UA_EXPORT
UA_Client_addTimedCallback(UA_Client *client, UA_ClientCallback callback,
                           void *data, UA_DateTime date, UA_UInt64 *callbackId) {
    return UA_Timer_addTimedCallback(&client->timer, (UA_ApplicationCallback) callback,
                                     client, data, date, callbackId);
}

UA_StatusCode
UA_Client_addRepeatedCallback(UA_Client *client, UA_ClientCallback callback,
                              void *data, UA_Double interval_ms, UA_UInt64 *callbackId) {
    return UA_Timer_addRepeatedCallback(&client->timer, (UA_ApplicationCallback) callback,
                                        client, data, interval_ms, callbackId);
}

UA_StatusCode
UA_Client_changeRepeatedCallbackInterval(UA_Client *client, UA_UInt64 callbackId,
                                         UA_Double interval_ms) {
    return UA_Timer_changeRepeatedCallbackInterval(&client->timer, callbackId,
                                                   interval_ms);
}

void
UA_Client_removeCallback(UA_Client *client, UA_UInt64 callbackId) {
    UA_Timer_removeCallback(&client->timer, callbackId);
}

static void
asyncServiceTimeoutCheck(UA_Client *client) {
    UA_DateTime now = UA_DateTime_nowMonotonic();

    /* Timeout occurs, remove the callback */
    AsyncServiceCall *ac, *ac_tmp;
    LIST_FOREACH_SAFE(ac, &client->asyncServiceCalls, pointers, ac_tmp) {
        if(!ac->timeout)
           continue;

        if(ac->start + (UA_DateTime)(ac->timeout * UA_DATETIME_MSEC) <= now) {
            LIST_REMOVE(ac, pointers);
            UA_Client_AsyncService_cancel(client, ac, UA_STATUSCODE_BADTIMEOUT);
            UA_free(ac);
        }
    }
}

static void
backgroundConnectivityCallback(UA_Client *client, void *userdata,
                               UA_UInt32 requestId, const UA_ReadResponse *response) {
    if(response->responseHeader.serviceResult == UA_STATUSCODE_BADTIMEOUT) {
        UA_LOG_WARNING_CHANNEL(&client->config.logger, &client->channel,
                               "Closed session. The server is unresponsive.");
        UA_Client_setSessionState(client, UA_SESSIONSTATE_CLOSED);
    }
    client->pendingConnectivityCheck = false;
    client->lastConnectivityCheck = UA_DateTime_nowMonotonic();
}

static void
UA_Client_backgroundConnectivity(UA_Client *client) {
    UA_LOG_DEBUG_CHANNEL(&client->config.logger, &client->channel,
                         "Background connectivity check");

    /* No open channel */
    if(client->channel.state != UA_SECURECHANNELSTATE_OPEN)
        return;

    /* Renew the channel */
    UA_DateTime now = UA_DateTime_nowMonotonic();
    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(client->nextChannelRenewal <= now) {
        res = UA_Client_sendOPN(client, true);
        if(res != UA_STATUSCODE_GOOD)
            return;
    }

    /* A read request is already in transit */
    if(client->pendingConnectivityCheck)
        return;

    /* Nothing to do */
    if(client->sessionState != UA_SESSIONSTATE_ACTIVATED)
        return;
    
    /* The next timeout is not yet reached */
    UA_DateTime nextDate = client->lastConnectivityCheck +
        (UA_DateTime)(client->config.connectivityCheckInterval * UA_DATETIME_MSEC);
    if(now <= nextDate)
        return;

    /* Send a read request on the server state to see if the session is open */

    UA_ReadValueId rvid;
    UA_ReadValueId_init(&rvid);
    rvid.attributeId = UA_ATTRIBUTEID_VALUE;
    rvid.nodeId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVER_SERVERSTATUS_STATE);

    UA_ReadRequest request;
    UA_ReadRequest_init(&request);
    request.nodesToRead = &rvid;
    request.nodesToReadSize = 1;

    res = UA_Client_AsyncService(client, &request, &UA_TYPES[UA_TYPES_READREQUEST],
                                 (UA_ClientAsyncServiceCallback)backgroundConnectivityCallback,
                                 &UA_TYPES[UA_TYPES_READRESPONSE], NULL, NULL);
    if(res == UA_STATUSCODE_GOOD)
        client->pendingConnectivityCheck = true;
}

static void
clientExecuteRepeatedCallback(UA_Client *client, UA_ApplicationCallback cb,
                              void *callbackApplication, void *data) {
    cb(callbackApplication, data);
}

UA_StatusCode
UA_Client_run_iterate(UA_Client *client, UA_UInt16 timeout) {
    /* The channel is open, we want a session, no session in progress -> start
     * the handshake */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(client->channel.state == UA_SECURECHANNELSTATE_OPEN &&
       client->sessionState == UA_SESSIONSTATE_FRESH &&
       client->autoConnectSession) {
        retval = connectSessionAsync(client);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }

#ifdef UA_ENABLE_SUBSCRIPTIONS
    UA_StatusCode retvalPublish = UA_Client_Subscriptions_backgroundPublish(client);
    if(retvalPublish != UA_STATUSCODE_GOOD)
        return retvalPublish;
#endif

    UA_DateTime now = UA_DateTime_nowMonotonic();
    UA_Timer_process(&client->timer, now,
                     (UA_TimerExecutionCallback)clientExecuteRepeatedCallback, client);

    /* TODO: Make this a repeated callback */
    UA_Client_backgroundConnectivity(client);

    UA_DateTime maxDate = now + (timeout * UA_DATETIME_MSEC);
    retval = receiveServiceResponse(client, NULL, NULL, maxDate, NULL);

#ifdef UA_ENABLE_SUBSCRIPTIONS
    /* The inactivity check must be done after receiveServiceResponse*/
    UA_Client_Subscriptions_backgroundPublishInactivityCheck(client);
#endif
    asyncServiceTimeoutCheck(client);

#if UA_MULTITHREADING < 200
    /* Process delayed callbacks when all callbacks and network events are
     * done */
    UA_WorkQueue_manuallyProcessDelayed(&client->workQueue);
#endif

    if(retval == UA_STATUSCODE_GOOD &&
       client->connectionResult != UA_STATUSCODE_GOOD)
        retval = client->connectionResult;
    return retval;
}

UA_StatusCode
UA_Client_run(UA_Client *client, const volatile UA_Boolean *running) {
    while(*running) {
        UA_StatusCode res = UA_Client_run_iterate(client, (UA_UInt16)client->config.timeout);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }
    return UA_STATUSCODE_GOOD;
}
