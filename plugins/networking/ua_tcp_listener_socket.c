/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018-2019 (c) Mark Giraud, Fraunhofer IOSB
 */

#include "ua_types_generated_handling.h"
#include "ua_sockets.h"
#include "ua_types.h"
#include "ua_plugin_network_manager.h"

#define MAXBACKLOG     100

typedef enum {
    UA_SOCKSTATE_NEW,
    UA_SOCKSTATE_OPEN,
    UA_SOCKSTATE_CLOSED,
} SocketState;

typedef struct {
    UA_Socket socket;

    SocketState state;
    UA_UInt32 recvBufferSize;
    UA_UInt32 sendBufferSize;
    UA_String customHostname;
} UA_Socket_tcpListener;

static UA_StatusCode
tcp_sock_setDiscoveryUrl(UA_Socket *sock, UA_UInt16 port, UA_ByteString *customHostname) {
    if(sock == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Get the discovery url from the hostname */
    UA_String du = UA_STRING_NULL;
    char discoveryUrlBuffer[256];
    if(!UA_ByteString_equal(customHostname, &UA_BYTESTRING_NULL)) {
        du.length = (size_t)UA_snprintf(discoveryUrlBuffer, 255, "opc.tcp://%.*s:%d/",
                                        (int)customHostname->length,
                                        customHostname->data,
                                        port);
        du.data = (UA_Byte *)discoveryUrlBuffer;
    } else {
        char hostnameBuffer[256];
        if(UA_gethostname(hostnameBuffer, 255) == 0) {
            du.length = (size_t)UA_snprintf(discoveryUrlBuffer, 255, "opc.tcp://%s:%d/",
                                            hostnameBuffer, port);
            du.data = (UA_Byte *)discoveryUrlBuffer;
        } else {
            UA_LOG_ERROR(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                         "Could not get the hostname");
        }
    }
    UA_LOG_INFO(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                "New TCP listener socket will listen on %.*s",
                (int)du.length, du.data);
    return UA_String_copy(&du, &sock->discoveryUrl);
}

static UA_StatusCode
tcp_sock_open(UA_Socket *sock) {
    UA_Socket_tcpListener *const internalSock = (UA_Socket_tcpListener *const)sock;

    if(internalSock->state != UA_SOCKSTATE_NEW) {
        UA_LOG_ERROR(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                     "Calling open on already open socket not supported");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(UA_listen((UA_SOCKET)sock->id, MAXBACKLOG) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                           "Error listening on server socket: %s", errno_str));
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    internalSock->state = UA_SOCKSTATE_OPEN;

    struct sockaddr_in returned_addr;
    memset(&returned_addr, 0, sizeof(returned_addr));
    socklen_t len = sizeof(returned_addr);
    if(UA_getsockname((UA_SOCKET)sock->id, (struct sockaddr *)&returned_addr, &len) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                           "Error getting the socket port on server socket: %s", errno_str));
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_UInt16 port = UA_ntohs(returned_addr.sin_port);

    tcp_sock_setDiscoveryUrl(sock, port, &internalSock->customHostname);

    return UA_SocketHook_call(sock->openHook, sock);
}

static UA_StatusCode
tcp_sock_close(UA_Socket *sock) {
    UA_Socket_tcpListener *const internalSock = (UA_Socket_tcpListener *const)sock;

    if(internalSock->state == UA_SOCKSTATE_CLOSED)
        return UA_STATUSCODE_GOOD;

    UA_shutdown((UA_SOCKET)sock->id, UA_SHUT_RDWR);
    internalSock->state = UA_SOCKSTATE_CLOSED;
    return UA_STATUSCODE_GOOD;
}

static UA_Boolean
tcp_sock_mayDelete(UA_Socket *sock) {
    UA_Socket_tcpListener *const internalSock = (UA_Socket_tcpListener *const)sock;
    return internalSock->state == UA_SOCKSTATE_CLOSED;
}

static UA_StatusCode
tcp_sock_free(UA_Socket *sock) {
    if(sock == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_Socket_tcpListener *const internalSock = (UA_Socket_tcpListener *const)sock;

    UA_SocketHook_call(sock->freeHook, sock);

    UA_String_deleteMembers(&internalSock->customHostname);
    UA_ByteString_deleteMembers(&sock->discoveryUrl);
    UA_SocketFactory_deleteMembers(sock->socketFactory);
    UA_close((int)sock->id);
    UA_free(sock->socketFactory);
    UA_free(sock);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
tcp_sock_activity(UA_Socket *sock) {
    if(sock == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(sock->mayDelete(sock))
        return UA_STATUSCODE_GOOD;

    if(sock->socketFactory != NULL && sock->socketFactory->buildSocket != NULL) {
        return sock->socketFactory->buildSocket(sock->socketFactory, sock, NULL);
    } else {
        UA_LOG_WARNING(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                       "No socket factory configured. Cannot create new socket");
        return UA_STATUSCODE_GOODDATAIGNORED;
    }
}

static UA_StatusCode
tcp_sock_buildSocket(UA_SocketFactory *factory, UA_Socket *listenerSocket, void *additionalData) {
    (void)additionalData;
    UA_Socket_tcpListener *const internalSock = (UA_Socket_tcpListener *const)listenerSocket;
    return UA_TCP_DataSocket_AcceptFrom(listenerSocket, factory->logger,
                                        internalSock->sendBufferSize,
                                        internalSock->recvBufferSize,
                                        factory->creationHook, factory->openHook, factory->freeHook,
                                        factory->socketDataCallback);
}

static UA_StatusCode
tcp_sock_send(UA_Socket *sock, UA_ByteString *buf) {
    UA_LOG_ERROR(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                 "Sending is not supported on listener sockets");
    // TODO: Can we support sending here? does it make sense at all?
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

static UA_StatusCode
tcp_sock_set_func_pointers(UA_Socket *sock) {
    sock->open = tcp_sock_open;
    sock->close = tcp_sock_close;
    sock->mayDelete = tcp_sock_mayDelete;
    sock->free = tcp_sock_free;
    sock->activity = tcp_sock_activity;
    sock->send = tcp_sock_send;
    sock->socketFactory->buildSocket = tcp_sock_buildSocket;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_TCP_ListenerSocketFromAddrinfo(struct addrinfo *addrinfo, UA_SocketConfig *socketConfig,
                                  UA_NetworkManager *nm, UA_Socket **p_socket) {
    UA_StatusCode retval;
    if(socketConfig == NULL) {
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_SOCKET socket_fd = UA_socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(socket_fd == UA_INVALID_SOCKET) {
        UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                       "Error opening the listener socket");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    UA_Socket_tcpListener *sock = (UA_Socket_tcpListener *)UA_malloc(sizeof(UA_Socket_tcpListener));
    if(sock == NULL) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    memset(sock, 0, sizeof(UA_Socket_tcpListener));

    sock->socket.isListener = true;
    sock->socket.id = (UA_UInt64)socket_fd;

    sock->socket.socketFactory = (UA_SocketFactory *)UA_malloc(sizeof(UA_SocketFactory));
    if(sock->socket.socketFactory == NULL) {
        UA_free(sock);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    sock->socket.networkManager = nm;
    sock->state = UA_SOCKSTATE_NEW;
    sock->recvBufferSize = socketConfig->recvBufferSize;
    sock->sendBufferSize = socketConfig->sendBufferSize;
    UA_String_copy(&socketConfig->customHostname, &sock->customHostname);

    retval = UA_SocketFactory_init(sock->socket.socketFactory, nm->logger);
    if(retval != UA_STATUSCODE_GOOD)
        goto error;

    int optVal = 1;
#if UA_IPV6
    if(addrinfo->ai_family == AF_INET6 &&
       UA_setsockopt(socket_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                     (const char *)&optVal, sizeof(optVal)) == -1) {
        UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not set an IPv6 socket to IPv6 only");
        goto error;
    }
#endif
    if(UA_setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                     (const char *)&optVal, sizeof(optVal)) == -1) {
        UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not make the socket reusable");
        goto error;
    }

    if(UA_socket_set_nonblocking(socket_fd) != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not set the server socket to non blocking");
        goto error;
    }

    if(UA_bind(socket_fd, addrinfo->ai_addr, (socklen_t)addrinfo->ai_addrlen) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                           "Error binding a server socket: %s", errno_str));
        goto error;
    }

    retval = tcp_sock_set_func_pointers((UA_Socket *)sock);
    if(retval != UA_STATUSCODE_GOOD) {
        goto error;
    }

    *p_socket = (UA_Socket *)sock;

    UA_LOG_TRACE(nm->logger, UA_LOGCATEGORY_NETWORK,
                 "Created new listener socket %p", (void *)sock);
    return UA_STATUSCODE_GOOD;

error:
    if(socket_fd != UA_INVALID_SOCKET)
        UA_close(socket_fd);
    UA_free(sock);
    return UA_STATUSCODE_BADINTERNALERROR;
}


UA_StatusCode
UA_TCP_ListenerSockets(UA_SocketConfig *socketConfig,
                       UA_NetworkManager *nm,
                       UA_SocketHook creationHook) {

    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(socketConfig == NULL)
        return retval;

    char portNumber[6];
    UA_snprintf(portNumber, 6, "%d", socketConfig->port);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP;
    if(UA_getaddrinfo(NULL, portNumber, &hints, &res) != 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* There might be several addrinfos (for different network cards,
     * IPv4/IPv6). Add a server socket for all of them. */
    size_t sockets_size = 0;
    for(struct addrinfo *ai = res;
        sockets_size < FD_SETSIZE && ai != NULL;
        ai = ai->ai_next, ++sockets_size) {
        UA_Socket *sock = NULL;
        UA_TCP_ListenerSocketFromAddrinfo(ai, socketConfig, nm, &sock);
        /* Instead of allocating an array to return the sockets, we call a hook for each one */
        retval = UA_SocketHook_call(creationHook, sock);
        if(retval != UA_STATUSCODE_GOOD)
            UA_LOG_ERROR(nm->logger, UA_LOGCATEGORY_NETWORK,
                         "Error calling socket hook %s",
                         UA_StatusCode_name(retval));
    }
    UA_freeaddrinfo(res);

    return retval;
}
