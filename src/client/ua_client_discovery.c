/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */

#include "ua_client_internal.h"

UA_StatusCode
UA_Client_getEndpoints(UA_Client *client, const char *serverUrl,
                       size_t* endpointDescriptionsSize,
                       UA_EndpointDescription** endpointDescriptions) {
    /* Client is already connected to a different server? */
    UA_Boolean connected = (client->channel.state > UA_SECURECHANNELSTATE_FRESH);
    if(connected && strncmp((const char*)client->config.endpoint.endpointUrl.data, serverUrl,
                            client->config.endpoint.endpointUrl.length) != 0) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(client->channel.state != UA_SECURECHANNELSTATE_OPEN) {
        res = UA_Client_connect_noSession(client, serverUrl);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    UA_GetEndpointsRequest request;
    UA_GetEndpointsRequest_init(&request);
    request.requestHeader.timestamp = UA_DateTime_now();
    request.requestHeader.timeoutHint = 10000;
    request.endpointUrl = UA_STRING((char*)(uintptr_t)serverUrl);
    UA_GetEndpointsResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_GETENDPOINTSREQUEST],
                        &response, &UA_TYPES[UA_TYPES_GETENDPOINTSRESPONSE]);

    /* Process the response */
    res = response.responseHeader.serviceResult;
    if(res == UA_STATUSCODE_GOOD) {
        *endpointDescriptionsSize = response.endpointsSize;
        *endpointDescriptions = response.endpoints;
        response.endpointsSize = 0;
        response.endpoints = NULL;
    } else {
        *endpointDescriptionsSize = 0;
        *endpointDescriptions = NULL;
    }
    UA_GetEndpointsResponse_clear(&response);

    if(!connected)
        UA_Client_disconnect(client);
    return res;
}

UA_StatusCode
UA_Client_findServers(UA_Client *client, const char *serverUrl,
                      size_t serverUrisSize, UA_String *serverUris,
                      size_t localeIdsSize, UA_String *localeIds,
                      size_t *registeredServersSize,
                      UA_ApplicationDescription **registeredServers) {
    /* Client is already connected to a different server? */
    UA_Boolean connected = (client->channel.state > UA_SECURECHANNELSTATE_FRESH);
    if(connected && strncmp((const char*)client->config.endpoint.endpointUrl.data, serverUrl,
                            client->config.endpoint.endpointUrl.length) != 0) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(client->channel.state != UA_SECURECHANNELSTATE_OPEN) {
        res = UA_Client_connect_noSession(client, serverUrl);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    /* Prepare the request */
    UA_FindServersRequest request;
    UA_FindServersRequest_init(&request);
    request.serverUrisSize = serverUrisSize;
    request.serverUris = serverUris;
    request.localeIdsSize = localeIdsSize;
    request.localeIds = localeIds;

    /* Send the request */
    UA_FindServersResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_FINDSERVERSREQUEST],
                        &response, &UA_TYPES[UA_TYPES_FINDSERVERSRESPONSE]);

    /* Process the response */
    res = response.responseHeader.serviceResult;
    if(res == UA_STATUSCODE_GOOD) {
        *registeredServersSize = response.serversSize;
        *registeredServers = response.servers;
        response.serversSize = 0;
        response.servers = NULL;
    } else {
        *registeredServersSize = 0;
        *registeredServers = NULL;
    }
    UA_FindServersResponse_deleteMembers(&response);

    if(!connected)
        UA_Client_disconnect(client);
    return res;
}

#ifdef UA_ENABLE_DISCOVERY

UA_StatusCode
UA_Client_findServersOnNetwork(UA_Client *client, const char *serverUrl,
                               UA_UInt32 startingRecordId, UA_UInt32 maxRecordsToReturn,
                               size_t serverCapabilityFilterSize, UA_String *serverCapabilityFilter,
                               size_t *serverOnNetworkSize, UA_ServerOnNetwork **serverOnNetwork) {
    /* Client is already connected to a different server? */
    UA_Boolean connected = (client->channel.state > UA_SECURECHANNELSTATE_FRESH);
    if(connected && strncmp((const char*)client->config.endpoint.endpointUrl.data, serverUrl,
                            client->config.endpoint.endpointUrl.length) != 0) {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    UA_StatusCode res = UA_STATUSCODE_GOOD;
    if(client->channel.state != UA_SECURECHANNELSTATE_OPEN) {
        res = UA_Client_connect_noSession(client, serverUrl);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    /* Prepare the request */
    UA_FindServersOnNetworkRequest request;
    UA_FindServersOnNetworkRequest_init(&request);
    request.startingRecordId = startingRecordId;
    request.maxRecordsToReturn = maxRecordsToReturn;
    request.serverCapabilityFilterSize = serverCapabilityFilterSize;
    request.serverCapabilityFilter = serverCapabilityFilter;

    /* Send the request */
    UA_FindServersOnNetworkResponse response;
    __UA_Client_Service(client, &request, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKREQUEST],
                        &response, &UA_TYPES[UA_TYPES_FINDSERVERSONNETWORKRESPONSE]);

    /* Process the response */
    res = response.responseHeader.serviceResult;
    if(res == UA_STATUSCODE_GOOD) {
        *serverOnNetworkSize = response.serversSize;
        *serverOnNetwork = response.servers;
        response.serversSize = 0;
        response.servers = NULL;
    } else {
        *serverOnNetworkSize = 0;
        *serverOnNetwork = NULL;
    }
    UA_FindServersOnNetworkResponse_deleteMembers(&response);

    if(!connected)
        UA_Client_disconnect(client);
    return res;
}

#endif
