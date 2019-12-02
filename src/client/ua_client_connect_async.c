/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <open62541/transport_generated.h>
#include <open62541/transport_generated_encoding_binary.h>
#include <open62541/transport_generated_handling.h>
#include <open62541/types_generated_encoding_binary.h>

#include "ua_client_internal.h"

#define UA_MINMESSAGESIZE                8192
#define UA_SESSION_LOCALNONCELENGTH      32
#define MAX_DATA_SIZE 4096

static void
processDecodedOPNResponseAsync(void *application, UA_SecureChannel *channel,
                               UA_MessageType messageType, UA_UInt32 requestId,
                               const UA_ByteString *message) {
    /* Does the request id match? */
    UA_Client *client = (UA_Client*)application;
    if(requestId != client->requestId) {
        UA_Client_disconnect(client);
        return;
    }

    /* Is the content of the expected type? */
    size_t offset = 0;
    UA_NodeId responseId;
    UA_NodeId expectedId = UA_NODEID_NUMERIC(
            0, UA_TYPES[UA_TYPES_OPENSECURECHANNELRESPONSE].binaryEncodingId);
    UA_StatusCode retval = UA_NodeId_decodeBinary(message, &offset,
                                                  &responseId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_disconnect(client);
        return;
    }
    if(!UA_NodeId_equal(&responseId, &expectedId)) {
        UA_NodeId_deleteMembers(&responseId);
        UA_Client_disconnect(client);
        return;
    }
    UA_NodeId_deleteMembers (&responseId);

    /* Decode the response */
    UA_OpenSecureChannelResponse response;
    retval = UA_OpenSecureChannelResponse_decodeBinary(message, &offset,
                                                       &response);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_Client_disconnect(client);
        return;
    }

    /* Response.securityToken.revisedLifetime is UInt32 we need to cast it to
     * DateTime=Int64 we take 75% of lifetime to start renewing as described in
     * standard */
    client->nextChannelRenewal = UA_DateTime_nowMonotonic()
            + (UA_DateTime) (response.securityToken.revisedLifetime
                    * (UA_Double) UA_DATETIME_MSEC * 0.75);

    /* Replace the token and nonce */
    UA_ChannelSecurityToken_deleteMembers(&client->channel.securityToken);
    UA_ByteString_deleteMembers(&client->channel.remoteNonce);
    client->channel.securityToken = response.securityToken;
    client->channel.remoteNonce = response.serverNonce;
    UA_ResponseHeader_deleteMembers(&response.responseHeader); /* the other members were moved */
    if(client->channel.state == UA_SECURECHANNELSTATE_OPEN)
        UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL, "SecureChannel renewed");
    else
        UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL, "SecureChannel opened");
    client->channel.state = UA_SECURECHANNELSTATE_OPEN;

    if(client->state < UA_CLIENTSTATE_SECURECHANNEL)
        setClientState(client, UA_CLIENTSTATE_SECURECHANNEL);
}

/* OPN messges to renew the channel are sent asynchronous */
static UA_StatusCode
openSecureChannelAsync(UA_Client *client/*, UA_Boolean renew*/) {
    /* Check if sc is still valid */
    /*if(renew && client->nextChannelRenewal - UA_DateTime_nowMonotonic () > 0)
        return UA_STATUSCODE_GOOD;*/

    UA_Connection *conn = &client->connection;
    if(conn->state != UA_CONNECTION_ESTABLISHED)
        return UA_STATUSCODE_BADSERVERNOTCONNECTED;

    /* Prepare the OpenSecureChannelRequest */
    UA_OpenSecureChannelRequest opnSecRq;
    UA_OpenSecureChannelRequest_init(&opnSecRq);
    opnSecRq.requestHeader.timestamp = UA_DateTime_now();
    opnSecRq.requestHeader.authenticationToken = client->authenticationToken;
    /*if(renew) {
        opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_RENEW;
        UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL,
                     "Requesting to renew the SecureChannel");
    } else {*/
        opnSecRq.requestType = UA_SECURITYTOKENREQUESTTYPE_ISSUE;
        UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL,
                     "Requesting to open a SecureChannel");
    //}
    opnSecRq.securityMode = client->channel.securityMode;

    opnSecRq.clientNonce = client->channel.localNonce;
    opnSecRq.requestedLifetime = client->config.secureChannelLifeTime;

    /* Prepare the entry for the linked list */
    UA_UInt32 requestId = ++client->requestId;
    /*AsyncServiceCall *ac = NULL;
    if(renew) {
        ac = (AsyncServiceCall*)UA_malloc(sizeof(AsyncServiceCall));
        if (!ac)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        ac->callback =
                (UA_ClientAsyncServiceCallback) processDecodedOPNResponseAsync;
        ac->responseType = &UA_TYPES[UA_TYPES_OPENSECURECHANNELRESPONSE];
        ac->requestId = requestId;
        ac->userdata = NULL;
    }*/

    /* Send the OPN message */
    UA_StatusCode retval = UA_SecureChannel_sendAsymmetricOPNMessage (
            &client->channel, requestId, &opnSecRq,
            &UA_TYPES[UA_TYPES_OPENSECURECHANNELREQUEST]);
    client->connectStatus = retval;

    if(retval != UA_STATUSCODE_GOOD) {
        client->connectStatus = retval;
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL,
                      "Sending OPN message failed with error %s",
                      UA_StatusCode_name(retval));
        UA_Client_disconnect(client);
        //if(renew)
        //    UA_free(ac);
        return retval;
    }

    UA_LOG_DEBUG(&client->config.logger, UA_LOGCATEGORY_SECURECHANNEL,
                 "OPN message sent");

    /* Store the entry for async processing and return */
    /*if(renew) {
        LIST_INSERT_HEAD(&client->asyncServiceCalls, ac, pointers);
        return retval;
    }*/
    return retval;
}



/* Combination of UA_Client_getEndpointsInternal and getEndpoints */
static void
responseGetEndpoints(UA_Client *client, void *userdata, UA_UInt32 requestId,
                     void *response) {
    UA_EndpointDescription* endpointArray = NULL;
    size_t endpointArraySize = 0;
    UA_GetEndpointsResponse* resp;
    resp = (UA_GetEndpointsResponse*)response;

    if (resp->responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
        client->connectStatus = resp->responseHeader.serviceResult;
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "GetEndpointRequest failed with error code %s",
                     UA_StatusCode_name (client->connectStatus));
        UA_GetEndpointsResponse_deleteMembers(resp);
        return;
    }
    endpointArray = resp->endpoints;
    endpointArraySize = resp->endpointsSize;
    resp->endpoints = NULL;
    resp->endpointsSize = 0;

    UA_Boolean endpointFound = false;
    UA_Boolean tokenFound = false;
    UA_String securityNone = UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None");
    UA_String binaryTransport = UA_STRING("http://opcfoundation.org/UA-Profile/"
                                          "Transport/uatcp-uasc-uabinary");

    // TODO: compare endpoint information with client->endpointUri
    for(size_t i = 0; i < endpointArraySize; ++i) {
        UA_EndpointDescription* endpoint = &endpointArray[i];
        /* look out for binary transport endpoints */
        /* Note: Siemens returns empty ProfileUrl, we will accept it as binary */
        if(endpoint->transportProfileUri.length != 0
                && !UA_String_equal (&endpoint->transportProfileUri,
                                     &binaryTransport))
            continue;

        /* Look for an endpoint corresponding to the client security policy */
        if(!UA_String_equal(&endpoint->securityPolicyUri, &client->channel.securityPolicy->policyUri))
            continue;

        endpointFound = true;

        /* Look for a user token policy with an anonymous token */
        for(size_t j = 0; j < endpoint->userIdentityTokensSize; ++j) {
            UA_UserTokenPolicy* userToken = &endpoint->userIdentityTokens[j];

            /* Usertokens also have a security policy... */
            if(userToken->securityPolicyUri.length > 0 &&
               !UA_String_equal(&userToken->securityPolicyUri, &securityNone))
                continue;

            /* Does the token type match the client configuration? */
            if((userToken->tokenType == UA_USERTOKENTYPE_ANONYMOUS &&
                client->config.userIdentityToken.content.decoded.type !=
                &UA_TYPES[UA_TYPES_ANONYMOUSIDENTITYTOKEN] &&
                client->config.userIdentityToken.content.decoded.type != NULL) ||
               (userToken->tokenType == UA_USERTOKENTYPE_USERNAME &&
                client->config.userIdentityToken.content.decoded.type !=
                &UA_TYPES[UA_TYPES_USERNAMEIDENTITYTOKEN]) ||
               (userToken->tokenType == UA_USERTOKENTYPE_CERTIFICATE &&
                client->config.userIdentityToken.content.decoded.type !=
                &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN]) ||
               (userToken->tokenType == UA_USERTOKENTYPE_ISSUEDTOKEN &&
                client->config.userIdentityToken.content.decoded.type !=
                &UA_TYPES[UA_TYPES_ISSUEDIDENTITYTOKEN]))
                continue;

            /* Endpoint with matching usertokenpolicy found */
            tokenFound = true;
            UA_EndpointDescription_deleteMembers(&client->config.endpoint);
            UA_EndpointDescription_copy(endpoint, &client->config.endpoint);
            UA_UserTokenPolicy_deleteMembers(&client->config.userTokenPolicy);
            UA_UserTokenPolicy_copy(userToken, &client->config.userTokenPolicy);
            break;
        }
    }

    UA_Array_delete(endpointArray, endpointArraySize,
                    &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);

    if(!endpointFound) {
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "No suitable endpoint found");
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
    } else if(!tokenFound) {
        UA_LOG_ERROR(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "No suitable UserTokenPolicy found for the possible endpoints");
        client->connectStatus = UA_STATUSCODE_BADINTERNALERROR;
    }
    requestSession(client, &requestId);
}

static UA_StatusCode
requestGetEndpoints(UA_Client *client, UA_UInt32 *requestId) {
    UA_GetEndpointsRequest request;
    UA_GetEndpointsRequest_init(&request);
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    /* assume the endpointurl outlives the service call */
    UA_String_copy(&client->endpointUrl, &request.endpointUrl);

    client->connectStatus = UA_Client_sendAsyncRequest(
            client, &request, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST],
            (UA_ClientAsyncServiceCallback) responseGetEndpoints,
            &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE], NULL, requestId);
    UA_GetEndpointsRequest_deleteMembers(&request);
    return client->connectStatus;

}

UA_StatusCode
UA_Client_connect_async(UA_Client *client, const char *endpointUrl,
                        UA_ClientAsyncServiceCallback callback,
                        void *userdata) {
    UA_LOG_TRACE(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                 "Client internal async");

    if(client->state >= UA_CLIENTSTATE_WAITING_FOR_ACK)
        return UA_STATUSCODE_GOOD;

    UA_ChannelSecurityToken_init(&client->channel.securityToken);
    client->channel.state = UA_SECURECHANNELSTATE_FRESH;
    client->endpointsHandshake = true;
    client->channel.sendSequenceNumber = 0;
    client->requestId = 0;

    UA_String_deleteMembers(&client->endpointUrl);
    client->endpointUrl = UA_STRING_ALLOC(endpointUrl);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    client->connection =
        client->config.initConnectionFunc(client->config.localConnectionConfig,
                                          client->endpointUrl,
                                          client->config.timeout, &client->config.logger);
    if(client->connection.state != UA_CONNECTION_OPENING) {
        UA_LOG_TRACE(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "Could not init async connection");
        retval = UA_STATUSCODE_BADCONNECTIONCLOSED;
        goto cleanup;
    }

    /* Set the channel SecurityMode if not done so far */
    if(client->channel.securityMode == UA_MESSAGESECURITYMODE_INVALID)
        client->channel.securityMode = UA_MESSAGESECURITYMODE_NONE;

    /* Set the channel SecurityPolicy if not done so far */
    if(!client->channel.securityPolicy) {
        UA_SecurityPolicy *sp =
            getSecurityPolicy(client, UA_STRING("http://opcfoundation.org/UA/SecurityPolicy#None"));
        if(!sp) {
            retval = UA_STATUSCODE_BADINTERNALERROR;
            goto cleanup;
        }
        UA_ByteString remoteCertificate = UA_BYTESTRING_NULL;
        retval = UA_SecureChannel_setSecurityPolicy(&client->channel, sp,
                                                    &remoteCertificate);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    client->asyncConnectCall.callback = callback;
    client->asyncConnectCall.userdata = userdata;

    if(!client->connection.connectCallbackID) {
        UA_LOG_TRACE(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                     "Adding async connection callback");
        retval = UA_Client_addRepeatedCallback(
                     client, client->config.pollConnectionFunc, &client->connection, 100.0,
                     &client->connection.connectCallbackID);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    retval = UA_SecureChannel_generateLocalNonce(&client->channel);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    /* Delete async service. TODO: Move this from connect to the disconnect/cleanup phase */
    UA_Client_AsyncService_removeAll(client, UA_STATUSCODE_BADSHUTDOWN);

#ifdef UA_ENABLE_SUBSCRIPTIONS
    client->currentlyOutStandingPublishRequests = 0;
#endif

    UA_NodeId_deleteMembers(&client->authenticationToken);

    /* Generate new local and remote key */
    retval = UA_SecureChannel_generateNewKeys(&client->channel);
    if(retval != UA_STATUSCODE_GOOD)
        goto cleanup;

    return retval;

 cleanup:
    UA_LOG_TRACE(&client->config.logger, UA_LOGCATEGORY_CLIENT,
                 "Failure during async connect");
    UA_Client_disconnect(client);
    return retval;
}

/* Async disconnection */
static void
sendCloseSecureChannelAsync(UA_Client *client, void *userdata,
                             UA_UInt32 requestId, void *response) {
    UA_NodeId_deleteMembers (&client->authenticationToken);
    client->requestHandle = 0;

    UA_SecureChannel *channel = &client->channel;
    UA_CloseSecureChannelRequest request;
    UA_CloseSecureChannelRequest_init(&request);
    request.requestHeader.requestHandle = ++client->requestHandle;
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.requestHeader.authenticationToken = client->authenticationToken;
    UA_SecureChannel_sendSymmetricMessage(
            channel, ++client->requestId, UA_MESSAGETYPE_CLO, &request,
            &UA_TYPES[UA_TYPES_CLOSESECURECHANNELREQUEST]);
    UA_SecureChannel_close(&client->channel);
    UA_SecureChannel_deleteMembers(&client->channel);
}

static void
sendCloseSessionAsync(UA_Client *client, UA_UInt32 *requestId) {
    UA_CloseSessionRequest request;
    UA_CloseSessionRequest_init(&request);

    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.deleteSubscriptions = true;

    UA_Client_sendAsyncRequest(
            client, &request, &UA_TYPES[UA_TYPES_CLOSESESSIONREQUEST],
            (UA_ClientAsyncServiceCallback) sendCloseSecureChannelAsync,
            &UA_TYPES[UA_TYPES_CLOSESESSIONRESPONSE], NULL, requestId);
}

UA_StatusCode
UA_Client_disconnect_async(UA_Client *client, UA_UInt32 *requestId) {
    /* Is a session established? */
    if (client->state == UA_CLIENTSTATE_SESSION) {
        client->state = UA_CLIENTSTATE_SESSION_DISCONNECTED;
        sendCloseSessionAsync(client, requestId);
    }

    /* Close the TCP connection
     * shutdown and close (in tcp.c) are already async*/
    if (client->state >= UA_CLIENTSTATE_CONNECTED)
        client->connection.close(&client->connection);
    else
        UA_Client_removeRepeatedCallback(client, client->connection.connectCallbackID);

#ifdef UA_ENABLE_SUBSCRIPTIONS
// TODO REMOVE WHEN UA_SESSION_RECOVERY IS READY
    /* We need to clean up the subscriptions */
    UA_Client_Subscriptions_clean(client);
#endif

    setClientState(client, UA_CLIENTSTATE_DISCONNECTED);
    return UA_STATUSCODE_GOOD;
}
