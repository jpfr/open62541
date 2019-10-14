/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2019 (c) Mark Giraud, Fraunhofer IOSB
 */

#ifndef OPEN62541_SOCKETS_H
#define OPEN62541_SOCKETS_H

#include <open62541/plugin/network.h>

_UA_BEGIN_DECLS

/* Creates all listener sockets for the specified port. If the underlying
 * network architecture has a IPv4/IPv6 dual stack, a socket will be created for
 * each feasible combination of IP version and network interface. */
UA_StatusCode
UA_TCP_ListenSockets(UA_NetworkManager *nm, UA_UInt32 listenPort, void *application,
                     UA_SocketReceiveCallback receiveCallback,
                     UA_SocketCallback detachCallback,
                     size_t *outSocketsSize, UA_UInt64 **outSocketIds,
                     UA_String **outDomainNames);

/* Creates a new data socket according to the socket config */
UA_StatusCode
UA_TCP_DataSocket(UA_NetworkManager *nm, void *application,
                  UA_String domain, UA_UInt32 port, 
                  UA_SocketReceiveCallback receiveCallback,
                  UA_SocketCallback detachCallback);

#ifdef UA_ENABLE_WEBSOCKET_SERVER
UA_StatusCode
UA_WSS_ServerSocket(const UA_SocketConfig *socketConfig,
                    UA_SocketCallbackFunction const creationCallback);

UA_StatusCode
UA_WSS_ClientSocket(const UA_SocketConfig *socketConfig,
                    UA_SocketCallbackFunction const creationCallback);
#endif

_UA_END_DECLS

#endif //OPEN62541_SOCKETS_H
