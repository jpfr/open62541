/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2015-2016 (c) Sten Grüner
 *    Copyright 2015-2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2015 (c) Oleksiy Vasylyev
 *    Copyright 2016-2017 (c) Florian Palm
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Mark Giraud, Fraunhofer IOSB
 */

#ifndef UA_CLIENT_INTERNAL_H_
#define UA_CLIENT_INTERNAL_H_

#define UA_INTERNAL
#include <open62541/client.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_subscriptions.h>

#include "open62541_queue.h"
#include "ua_securechannel.h"
#include "ua_timer.h"
#include "ua_workqueue.h"

_UA_BEGIN_DECLS

/**************************/
/* Subscriptions Handling */
/**************************/

#ifdef UA_ENABLE_SUBSCRIPTIONS

typedef struct UA_Client_NotificationsAckNumber {
    LIST_ENTRY(UA_Client_NotificationsAckNumber) listEntry;
    UA_SubscriptionAcknowledgement subAck;
} UA_Client_NotificationsAckNumber;

typedef struct UA_Client_MonitoredItem {
    LIST_ENTRY(UA_Client_MonitoredItem) listEntry;
    UA_UInt32 monitoredItemId;
    UA_UInt32 clientHandle;
    void *context;
    UA_Client_DeleteMonitoredItemCallback deleteCallback;
    union {
        UA_Client_DataChangeNotificationCallback dataChangeCallback;
        UA_Client_EventNotificationCallback eventCallback;
    } handler;
    UA_Boolean isEventMonitoredItem; /* Otherwise a DataChange MoniitoredItem */
} UA_Client_MonitoredItem;

typedef struct UA_Client_Subscription {
    LIST_ENTRY(UA_Client_Subscription) listEntry;
    UA_UInt32 subscriptionId;
    void *context;
    UA_Double publishingInterval;
    UA_UInt32 maxKeepAliveCount;
    UA_Client_StatusChangeNotificationCallback statusChangeCallback;
    UA_Client_DeleteSubscriptionCallback deleteCallback;
    UA_UInt32 sequenceNumber;
    UA_DateTime lastActivity;
    LIST_HEAD(UA_ListOfClientMonitoredItems, UA_Client_MonitoredItem) monitoredItems;
} UA_Client_Subscription;

void
UA_Client_Subscriptions_clean(UA_Client *client);

void
UA_Client_MonitoredItem_remove(UA_Client *client, UA_Client_Subscription *sub,
                               UA_Client_MonitoredItem *mon);

void
UA_Client_Subscriptions_processPublishResponse(UA_Client *client,
                                               UA_PublishRequest *request,
                                               UA_PublishResponse *response);

UA_StatusCode
UA_Client_preparePublishRequest(UA_Client *client, UA_PublishRequest *request);

UA_StatusCode
UA_Client_Subscriptions_backgroundPublish(UA_Client *client);

void
UA_Client_Subscriptions_backgroundPublishInactivityCheck(UA_Client *client);

#endif /* UA_ENABLE_SUBSCRIPTIONS */

/**********/
/* Client */
/**********/

typedef struct AsyncServiceCall {
    LIST_ENTRY(AsyncServiceCall) pointers;
    UA_UInt32 requestId;
    UA_ClientAsyncServiceCallback callback;
    const UA_DataType *responseType;
    void *userdata;
    UA_DateTime start;
    UA_UInt32 timeout;
    void *responsedata;
} AsyncServiceCall;

void UA_Client_AsyncService_cancel(UA_Client *client, AsyncServiceCall *ac,
                                   UA_StatusCode statusCode);

void UA_Client_AsyncService_removeAll(UA_Client *client, UA_StatusCode statusCode);

typedef struct CustomCallback {
    LIST_ENTRY(CustomCallback)
    pointers;
    //to find the correct callback
    UA_UInt32 callbackId;

    UA_ClientAsyncServiceCallback userCallback;
    void *userData;

    bool isAsync;
    void *clientData;
} CustomCallback;

struct UA_Client {
    UA_ClientConfig config;
    UA_Timer timer;
    UA_WorkQueue workQueue;
    UA_Connection connection;

    /* SecureChannel */
    UA_SecureChannelState lastChannelState; /* Signal changes only */
    UA_SecureChannel channel;
    UA_UInt32 requestId;
    UA_DateTime nextChannelRenewal;

    /* Session */
    UA_Boolean autoConnectSession; /* Restore or create a session automatically */
    UA_Boolean endpointsRequested;
    UA_SessionState sessionState;
    UA_NodeId authenticationToken;
    UA_UInt32 requestHandle;
    UA_ExtensionObject credentials; /* For automatic reconnect */

    UA_String endpointUrl; /* Only for the async connect */

    /* Async Service */
    AsyncServiceCall asyncConnectCall;
    LIST_HEAD(ListOfAsyncServiceCall, AsyncServiceCall) asyncServiceCalls;
    /*When using highlevel functions these are the callbacks that can be accessed by the user*/
    LIST_HEAD(ListOfCustomCallback, CustomCallback) customCallbacks;

    /* Subscriptions */
#ifdef UA_ENABLE_SUBSCRIPTIONS
    UA_UInt32 monitoredItemHandles;
    LIST_HEAD(, UA_Client_NotificationsAckNumber) pendingNotificationsAcks;
    LIST_HEAD(, UA_Client_Subscription) subscriptions;
    UA_UInt16 currentlyOutStandingPublishRequests;
#endif

    /* Connectivity check */
    UA_DateTime lastConnectivityCheck;
    UA_Boolean pendingConnectivityCheck;
};

static UA_INLINE CustomCallback *
UA_Client_findCustomCallback(UA_Client *client, UA_UInt32 requestId) {
    CustomCallback *cc;
    LIST_FOREACH(cc, &client->customCallbacks, pointers) {
        if(cc->callbackId == requestId)
            break;
    }
    return cc;
}

UA_StatusCode
connectSessionAsync(UA_Client *client);

void
closeSecureChannel(UA_Client *client);

UA_StatusCode
UA_Client_processACK(UA_Client *client, const UA_ByteString *payload);

void
UA_Client_processERR(UA_Client *client, const UA_ByteString *message);

UA_StatusCode
UA_Client_processOPN(UA_Client *client, UA_ByteString *message, UA_Boolean renew);

_UA_END_DECLS

#endif /* UA_CLIENT_INTERNAL_H_ */
