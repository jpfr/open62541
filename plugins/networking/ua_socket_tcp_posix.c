/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018-2019 (c) Mark Giraud, Fraunhofer IOSB
 */

#include <open62541/types.h>
#include <open62541/util.h>
#include <open62541/types_generated_handling.h>
#include <open62541/plugin/networking/sockets.h>

#define MAXBACKLOG 100

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef struct {
    UA_Socket socket;
    UA_UInt32 recvBufferSize;
    UA_UInt32 sendBufferSize;
    UA_SocketReceiveCallback receiveCallback; /* To be set in the data socket. */
    UA_SocketCallback detachCallback; /* To be set in the data socket. */
} UA_Socket_tcpListener;

typedef struct {
    UA_Socket socket;
    UA_SocketReceiveCallback receiveCallback;
    UA_SocketCallback detachCallback;
} UA_Socket_tcpDataSocket;

typedef struct {
    UA_Socket_tcpDataSocket socket;
    UA_String endpointUrl;
    UA_UInt32 timeout;
    struct addrinfo *server;
} UA_Socket_tcpClientDataSocket;

static void
tcp_sock_close(UA_Socket *sock) {
    if(!sock)
        return;
    if(sock->state == UA_SOCKETSTATE_CLOSED)
        return;

    UA_LOG_DEBUG(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                 "Shutting down socket %lu", sock->id);

    if((UA_SOCKET)sock->id != UA_INVALID_SOCKET)
        UA_shutdown((UA_SOCKET)sock->id, UA_SHUT_RDWR);
    sock->state = UA_SOCKETSTATE_CLOSED;
}

static UA_StatusCode
tcp_sock_acquireSendBuffer(UA_Socket *sock, size_t bufferSize, UA_ByteString *p_buffer) {
    if(!p_buffer)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    return UA_ByteString_allocBuffer(p_buffer, bufferSize);
}

static void
tcp_sock_releaseSendBuffer(UA_Socket *sock, UA_ByteString *buffer) {
    if(!buffer)
        return;
    UA_ByteString_clear(buffer);
}

/***************/
/* Data Socket */
/***************/

static void
UA_TCP_DataSocket_clear(UA_Socket *sock) {
    if(!sock)
        return;
    
    UA_Socket_tcpDataSocket *internalSocket = (UA_Socket_tcpDataSocket *)sock;
    UA_LOG_DEBUG(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                 "Detach socket %i from the application", (int)sock->id);

    if(internalSocket->detachCallback)
        internalSocket->detachCallback(sock);
}

/* #define UA_HOSTNAME_MAX_LENGTH 512 */

/* static UA_StatusCode */
/* TCP_ClientDataSocket_open(UA_Socket *sock) { */
/*     if(!sock) */
/*         return UA_STATUSCODE_BADINVALIDARGUMENT; */

/*     /\* Non blocking connect *\/ */
/*     UA_Socket_tcpClientDataSocket *internalSocket = (UA_Socket_tcpClientDataSocket *)sock; */
/*     int error = UA_connect((UA_SOCKET)sock->id, internalSocket->server->ai_addr, */
/*                            (socklen_t)internalSocket->server->ai_addrlen); */

/*     UA_StatusCode retval = UA_STATUSCODE_GOOD; */
/*     if((error == -1) && (UA_ERRNO != UA_ERR_CONNECTION_PROGRESS)) { */
/*         UA_LOG_SOCKET_ERRNO_WRAP( */
/*             UA_LOG_WARNING(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                            "Connection to %.*s failed with error: %s", */
/*                            (int)internalSocket->endpointUrl.length, */
/*                            internalSocket->endpointUrl.data, errno_str)); */
/*         retval = UA_STATUSCODE_BADCOMMUNICATIONERROR; */
/*         goto error; */
/*     } */

/* #ifdef SO_NOSIGPIPE */
/*     int val = 1; */
/*     int sso_result = UA_setsockopt((UA_SOCKET)sock->id, SOL_SOCKET, */
/*                                    SO_NOSIGPIPE, (void*)&val, sizeof(val)); */
/*     if(sso_result < 0) */
/*         UA_LOG_WARNING(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                        "Couldn't set SO_NOSIGPIPE"); */
/* #endif */

/*     /\* The open callback will be called later if the connection succeeds *\/ */
/*     return retval; */

/* error: */
/*     sock->close(sock); */
/*     return retval; */
/* } */

static void
UA_TCP_DataSocket_activity(UA_Socket *sock) {
    if(!sock) 
        return;
    if(sock->state != UA_SOCKETSTATE_OPEN)
        return;

    UA_LOG_DEBUG(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                 "Socket %i | Receiving data", (int)sock->id);

    UA_ByteString recvBuf;
    UA_StatusCode retval = UA_ByteString_allocBuffer(&recvBuf, 16664);
    if(retval != UA_STATUSCODE_GOOD)
        return;

    // we want to read as many bytes as possible.
    // the code called in the callback is responsible for disassembling the data
    // into e.g. chunks and copying it.
    ssize_t bytesReceived = UA_recv((int)sock->id, (char *)recvBuf.data, recvBuf.length, 0);

    if(bytesReceived < 0) {
        UA_ByteString_clear(&recvBuf);
        if(UA_ERRNO == UA_WOULDBLOCK || UA_ERRNO == UA_EAGAIN || UA_ERRNO == UA_INTERRUPTED)
            return;
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_ERROR(sock->networkManager->logger,
                                              UA_LOGCATEGORY_NETWORK,
                                              "Error while receiving data from socket: %s",
                                              errno_str));
        sock->close(sock);
        return;
    }

    if(bytesReceived == 0) {
        UA_LOG_INFO(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                    "Socket %i | Performing orderly shutdown", (int)sock->id);
        tcp_sock_close(sock);
        UA_ByteString_clear(&recvBuf);
        return;
    }

    /* Receive Callback */
    recvBuf.length = (size_t)bytesReceived;
    UA_Socket_tcpDataSocket *internalSocket = (UA_Socket_tcpDataSocket *)sock;
    internalSocket->receiveCallback(sock->application, sock, recvBuf);
    UA_ByteString_clear(&recvBuf);
}

static UA_StatusCode
UA_TCP_DataSocket_send(UA_Socket *sock, UA_ByteString *buffer) {
    if(!sock) {
        UA_ByteString_clear(buffer);
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    int flags = MSG_NOSIGNAL;
    size_t totalBytesSent = 0;
    do {
        ssize_t bytesSent = 0;
        do {
            bytesSent = UA_send((int)sock->id,
                                (const char *)buffer->data + totalBytesSent,
                                buffer->length - totalBytesSent, flags);
            if(bytesSent < 0 && UA_ERRNO != UA_EAGAIN && UA_ERRNO != UA_INTERRUPTED) {
                UA_LOG_ERROR(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                             "Error while sending data over socket");
                UA_ByteString_clear(buffer);
                return UA_STATUSCODE_BADCOMMUNICATIONERROR;
            }
        } while(bytesSent < 0);
        totalBytesSent += (size_t)bytesSent;
    } while(totalBytesSent < buffer->length);

    UA_ByteString_clear(buffer);
    return UA_STATUSCODE_GOOD;
}

static void
UA_TCP_DataSocket_logPeerName(UA_Socket *sock, struct sockaddr_storage *remote) {
#ifdef UA_getnameinfo
    /* Get the peer name for logging */
    char remote_name[100];
    int res = UA_getnameinfo((struct sockaddr *)remote,
                             sizeof(struct sockaddr_storage),
                             remote_name, sizeof(remote_name),
                             NULL, 0, NI_NUMERICHOST);
    if(res == 0) {
        UA_LOG_INFO(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                    "Socket %i | New connection over TCP from %s",
                    (int)sock->id, remote_name);
    } else {
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_WARNING(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                                                "Socket %i | New connection over TCP, "
                                                "getnameinfo failed with error: %s",
                                                (int)sock->id, errno_str));
    }
#else
    UA_LOG_INFO(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                "Socket %i | New connection over TCP",
                (int)sock->id);
#endif
}

/* static void */
/* UA_TCP_ClientDataSocket_clear(UA_Socket *sock) { */
/*     UA_Socket_tcpClientDataSocket *internalSocket = (UA_Socket_tcpClientDataSocket *)sock; */
/*     UA_String_deleteMembers(&internalSocket->endpointUrl); */
/*     if(internalSocket->server != NULL) */
/*         UA_freeaddrinfo(internalSocket->server); */
/*     UA_TCP_DataSocket_clear(sock); */
/* } */

UA_StatusCode
UA_TCP_DataSocket(UA_NetworkManager *nm, void *application,
                  UA_String domain, UA_UInt32 port, 
                  UA_SocketReceiveCallback receiveCallback,
                  UA_SocketCallback detachCallback) {
/*     if(socketParameters == NULL || socketParameters->createSocket == NULL) */
/*         return UA_STATUSCODE_BADINTERNALERROR; */

/*     UA_NetworkManager *networkManager = socketParameters->networkManager; */
/*     UA_Socket_tcpClientDataSocket *const sock = (UA_Socket_tcpClientDataSocket *const)UA_malloc( */
/*         sizeof(UA_Socket_tcpClientDataSocket)); */
/*     if(sock == NULL) { */
/*         UA_LOG_ERROR(networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                      "Failed to allocate data socket internal data. Out of memory"); */
/*         return UA_STATUSCODE_BADOUTOFMEMORY; */
/*     } */
/*     memset(sock, 0, sizeof(UA_Socket_tcpClientDataSocket)); */

/*     UA_StatusCode retval = UA_TCP_DataSocket_init((UA_UInt64)UA_INVALID_SOCKET, */
/*                                                   socketParameters->sendBufferSize, */
/*                                                   socketParameters->recvBufferSize, */
/*                                                   networkManager, */
/*                                                   (UA_Socket_tcpDataSocket *)sock, */
/*                                                   socketParameters->application); */
/*     if(retval != UA_STATUSCODE_GOOD) { */
/*         UA_LOG_ERROR(networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                      "Failed to allocate socket resources with error %s", */
/*                      UA_StatusCode_name(retval)); */
/*         UA_free(sock); */
/*         return retval; */
/*     } */

/*     UA_String_copy(&((const UA_ClientSocketConfig *)socketParameters)->targetEndpointUrl, &sock->endpointUrl); */
/*     sock->timeout = ((const UA_ClientSocketConfig *)socketParameters)->timeout; */

/*     sock->socket.socket.open = UA_TCP_ClientDataSocket_open; */
/*     sock->socket.socket.clear = UA_TCP_ClientDataSocket_clear; */

/*     UA_String hostnameString = UA_STRING_NULL; */
/*     UA_String pathString = UA_STRING_NULL; */
/*     UA_UInt16 port = 0; */
/*     char hostname[UA_HOSTNAME_MAX_LENGTH]; */

/*     retval = UA_parseEndpointUrl(&sock->endpointUrl, &hostnameString, */
/*                                  &port, &pathString); */
/*     if(retval != UA_STATUSCODE_GOOD || hostnameString.length >= UA_HOSTNAME_MAX_LENGTH) { */
/*         UA_LOG_WARNING(networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                        "Server url is invalid: %.*s", */
/*                        (int)sock->endpointUrl.length, sock->endpointUrl.data); */

/*         retval = UA_STATUSCODE_BADINTERNALERROR; */
/*         goto error; */
/*     } */
/*     memcpy(hostname, hostnameString.data, hostnameString.length); */
/*     hostname[hostnameString.length] = 0; */

/*     if(port == 0) { */
/*         port = 4840; */
/*         UA_LOG_INFO(networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                     "No port defined, using default port %d", port); */
/*     } */

/*     struct addrinfo hints; */
/*     sock->server = NULL; */
/*     memset(&hints, 0, sizeof(hints)); */
/*     hints.ai_family = AF_UNSPEC; */
/*     hints.ai_socktype = SOCK_STREAM; */
/*     hints.ai_protocol = IPPROTO_TCP; */
/*     char portStr[6]; */
/*     UA_snprintf(portStr, 6, "%d", port); */
/*     int error = UA_getaddrinfo(hostname, portStr, &hints, &sock->server); */
/*     if(error != 0 || sock->server == NULL) { */
/*         UA_LOG_SOCKET_ERRNO_GAI_WRAP(UA_LOG_WARNING(networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                                                     "DNS lookup of %s failed with error %s", hostname, errno_str)); */
/*         retval = UA_STATUSCODE_BADINTERNALERROR; */
/*         goto error; */
/*     } */

/*     UA_SOCKET client_sockfd = UA_socket(sock->server->ai_family, */
/*                                         sock->server->ai_socktype, */
/*                                         sock->server->ai_protocol); */
/*     if(client_sockfd == UA_INVALID_SOCKET) { */
/*         UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_WARNING(networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                                                 "Could not create client socket: %s", errno_str)); */
/*         retval = UA_STATUSCODE_BADINTERNALERROR; */
/*         goto error; */
/*     } */

/*     /\* Non blocking connect to be able to timeout *\/ */
/*     retval = UA_socket_set_nonblocking(client_sockfd); */
/*     if(retval != UA_STATUSCODE_GOOD) { */
/*         UA_LOG_WARNING(networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                        "Could not set the client socket to non blocking"); */
/*         goto error; */
/*     } */

/*     sock->socket.socket.id = (UA_UInt64)client_sockfd; */

/*     retval = UA_SocketCallback_call(socketParameters->networkManagerCallback, (UA_Socket *)sock); */
/*     if(retval != UA_STATUSCODE_GOOD) { */
/*         UA_LOG_ERROR(socketParameters->networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                      "Creation callback returned error %s.", */
/*                      UA_StatusCode_name(retval)); */
/*         goto after_nm_register_error; */
/*     } */

/*     retval = UA_SocketCallback_call(creationCallback, (UA_Socket *)sock); */
/*     if(retval != UA_STATUSCODE_GOOD) { */
/*         UA_LOG_ERROR(socketParameters->networkManager->logger, UA_LOGCATEGORY_NETWORK, */
/*                      "Creation callback returned error %s.", */
/*                      UA_StatusCode_name(retval)); */
/*         goto after_nm_register_error; */
/*     } */
/*     return retval; */

/* error: */
/*     sock->socket.socket.close((UA_Socket *)sock); */
/*     sock->socket.socket.clear((UA_Socket *)sock); */
/*     return retval; */

/* after_nm_register_error: */
/*     sock->socket.socket.close((UA_Socket *)sock); */
    return UA_STATUSCODE_GOOD;
}

/*******************/
/* Listener Socket */
/*******************/

static void
tcp_sock_clear(UA_Socket *sock) {
    if(sock == NULL)
        return;
    UA_Socket_tcpListener *internalSock = (UA_Socket_tcpListener *)sock;
    if(internalSock->detachCallback)
        internalSock->detachCallback(sock);
}

/* Activity on the listener socket with a new data socket opening */
static void
tcp_sock_activity(UA_Socket *sock) {
    if(!sock)
        return;

    UA_Socket_tcpListener *internalSock = (UA_Socket_tcpListener *)sock;
    UA_NetworkManager *nm = sock->networkManager;

    struct sockaddr_storage remote;
    socklen_t remote_size = sizeof(remote);
    UA_SOCKET newsockfd = UA_accept((UA_SOCKET)sock->id,
                                    (struct sockaddr*)&remote, &remote_size);
    if(newsockfd == UA_INVALID_SOCKET) {
        if(errno == UA_WOULDBLOCK || errno == UA_EAGAIN)
            return;
        UA_LOG_TRACE(nm->logger, UA_LOGCATEGORY_NETWORK,
                     "Connection %i | Could not accept a new socket",
                     (int)sock->id);
        return;
    }

    UA_LOG_TRACE(nm->logger, UA_LOGCATEGORY_NETWORK,
                 "Connection %i | New TCP connection on server socket %i",
                 (int)newsockfd, (int)sock->id);
        
    UA_Socket_tcpDataSocket *newSock = NULL;
    UA_StatusCode retval = sock->networkManager->
        createSocket(sock->networkManager, sizeof(UA_Socket_tcpDataSocket),
                     (UA_Socket**)&newSock);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                     "Error while accepting new socket connection: %s",
                     UA_StatusCode_name(retval));
        goto error;
    }

    retval = UA_socket_set_nonblocking(newsockfd);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(nm->logger, UA_LOGCATEGORY_NETWORK,
                     "Encountered error %s while setting socket to non blocking.",
                     UA_StatusCode_name(retval));
        goto error;
    }

    /* Disable Nagle's Algorithm so packets don't get batched */
    int dummy = 1;
    if(UA_setsockopt(newsockfd, IPPROTO_TCP, TCP_NODELAY,
                     (const char *)&dummy, sizeof(dummy)) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_ERROR(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                         "Cannot set socket option TCP_NODELAY. Error: %s",
                         errno_str));
        retval = UA_STATUSCODE_BADUNEXPECTEDERROR;
        goto error;
    }

    newSock->socket.application = sock->application;
    newSock->socket.id = (UA_UInt64)newsockfd;
    newSock->socket.close = tcp_sock_close;
    newSock->socket.clear = UA_TCP_DataSocket_clear;
    newSock->socket.activity = UA_TCP_DataSocket_activity;
    newSock->socket.send = UA_TCP_DataSocket_send;
    newSock->socket.acquireSendBuffer = tcp_sock_acquireSendBuffer;
    newSock->socket.releaseSendBuffer = tcp_sock_releaseSendBuffer;
    newSock->socket.networkManager = nm;
    newSock->socket.state = UA_SOCKETSTATE_NEW;
    newSock->receiveCallback = internalSock->receiveCallback;
    newSock->detachCallback = internalSock->detachCallback;

    nm->registerSocket(nm, &newSock->socket);
    newSock->socket.state = UA_SOCKETSTATE_OPEN;
    UA_TCP_DataSocket_logPeerName(&newSock->socket, &remote);
    return;

 error:
    if(newSock) {
        tcp_sock_close(&newSock->socket);
        nm->deleteSocket(nm, &newSock->socket);
    }
}

static UA_StatusCode
tcp_sock_send(UA_Socket *sock, UA_ByteString *buffer) {
    UA_LOG_ERROR(sock->networkManager->logger, UA_LOGCATEGORY_NETWORK,
                 "Sending is not supported on listener sockets");
    // TODO: Can we support sending here? does it make sense at all?
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

static UA_StatusCode
UA_TCP_ServerSocketFromAddrinfo(UA_NetworkManager *nm,
                                struct addrinfo *addrinfo, void *application,
                                UA_SocketReceiveCallback receiveCallback,
                                UA_SocketCallback detachCallback,
                                UA_UInt64 *outSocketId,
                                UA_String *outDomainNames) {
    UA_Socket_tcpListener *sock;
    nm->createSocket(nm, sizeof(UA_Socket_tcpListener), (UA_Socket**)&sock);
    if(!sock)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    memset(sock, 0, sizeof(UA_Socket_tcpListener));
    sock->socket.application = application;
    sock->socket.state = UA_SOCKETSTATE_NEW;
    sock->socket.networkManager = nm;
    sock->socket.close = tcp_sock_close;
    sock->socket.clear = tcp_sock_clear;
    sock->socket.activity = tcp_sock_activity;
    sock->socket.send = tcp_sock_send;
    sock->socket.acquireSendBuffer = tcp_sock_acquireSendBuffer;
    sock->socket.releaseSendBuffer = tcp_sock_releaseSendBuffer;
    sock->receiveCallback = receiveCallback;
    sock->detachCallback = detachCallback;

    UA_SOCKET socket_fd = UA_socket(addrinfo->ai_family, addrinfo->ai_socktype,
                                    addrinfo->ai_protocol);
    if(socket_fd == UA_INVALID_SOCKET) {
        UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                       "Error opening the listener socket");
        nm->deleteSocket(nm, &sock->socket);
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    sock->socket.id = (UA_UInt64)socket_fd;

    /* Set to IPV6 only */
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

    /* Make the socket reusable */
    if(UA_setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                     (const char *)&optVal, sizeof(optVal)) == -1) {
        UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not make the socket reusable");
        goto error;
    }

    /* Set non-blocking */
    if(UA_socket_set_nonblocking(socket_fd) != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not set the listen socket to non blocking");
        goto error;
    }

    /* Bind the socket */
    if(UA_bind(socket_fd, addrinfo->ai_addr, (socklen_t)addrinfo->ai_addrlen) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                           "Error binding a listen socket: %s", errno_str));
        goto error;
    }

    /* Start to listen */
    if(UA_listen(socket_fd, MAXBACKLOG) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                           "Error listening on server socket: %s", errno_str));
        goto error;
    }

    /* Get the port */
    struct sockaddr_storage returned_addr;
    memset(&returned_addr, 0, sizeof(returned_addr));
    socklen_t len = sizeof(returned_addr);
    if(UA_getsockname((UA_SOCKET)sock->socket.id, (struct sockaddr *)&returned_addr, &len) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                           "Error getting the socket port on server socket: %s", errno_str));
        goto error;
    }
    UA_UInt16 port = 0;
    if(returned_addr.ss_family == AF_INET)
        port = UA_ntohs(((struct sockaddr_in *)&returned_addr)->sin_port);
    else if(returned_addr.ss_family == AF_INET6)
        port = UA_ntohs(((struct sockaddr_in6 *)&returned_addr)->sin6_port);

    /* Get the domain name we are listening on */
    char hostname[NI_MAXHOST];
    int error = getnameinfo(addrinfo->ai_addr, addrinfo->ai_addrlen,
                            hostname, NI_MAXHOST, NULL, 0, 0); 
    if(error != 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_WARNING(nm->logger, UA_LOGCATEGORY_NETWORK,
                                                "Error binding a server socket: %s", errno_str));
        goto error;
    }

    nm->registerSocket(nm, &sock->socket);
    sock->socket.state = UA_SOCKETSTATE_OPEN;

    UA_LOG_TRACE(nm->logger, UA_LOGCATEGORY_NETWORK,
                 "Socket %i | New socket listening on %s:%u",
                 (int)socket_fd, hostname, port);

    *outSocketId = sock->socket.id;
    *outDomainNames = UA_STRING_ALLOC(hostname);
    return UA_STATUSCODE_GOOD;

error:
    tcp_sock_close(&sock->socket);
    nm->deleteSocket(nm, &sock->socket);
    return UA_STATUSCODE_BADINTERNALERROR;
}

UA_StatusCode
UA_TCP_ListenSockets(UA_NetworkManager *nm, UA_UInt32 listenPort, void *application,
                     UA_SocketReceiveCallback receiveCallback,
                     UA_SocketCallback detachCallback,
                     size_t *outSocketsSize, UA_UInt64 **outSocketIds,
                     UA_String **outDomainNames) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK,
                 "Create listen sockets on port %u", listenPort);

    char portNumber[6];
    UA_snprintf(portNumber, 6, "%d", listenPort);

    /* There might be several addrinfos (for different network cards,
     * IPv4/IPv6). Add a server socket for all of them. */
    struct addrinfo hints, *res, *tmp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP;
    if(UA_getaddrinfo(NULL, portNumber, &hints, &res) != 0)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Count the number of addrinfo to be used */
    size_t sockets_size = 0;
    tmp = res;
    while(tmp) {
        sockets_size++;
        tmp = tmp->ai_next;
    }
    if(sockets_size > FD_SETSIZE)
        sockets_size = FD_SETSIZE;

    /* Return domain names if this is requested */
    *outSocketIds = NULL;
    *outDomainNames = (UA_String*)
        UA_Array_new(sockets_size, &UA_TYPES[UA_TYPES_STRING]);
    if(!*outDomainNames)
        goto cleanup;
    *outSocketIds = (UA_UInt64*)
        UA_Array_new(sockets_size, &UA_TYPES[UA_TYPES_UINT64]);
    if(!*outSocketIds)
        goto cleanup;
    
    tmp = res;
    for(size_t i = 0; i < sockets_size; i++, tmp = tmp->ai_next) {
        retval = UA_TCP_ServerSocketFromAddrinfo(nm, tmp, application,
                                                 receiveCallback, detachCallback,
                                                 &(*outSocketIds)[i],
                                                 &(*outDomainNames)[i]);
        if(retval != UA_STATUSCODE_GOOD)
            goto cleanup;
    }

    *outSocketsSize = sockets_size;
    UA_freeaddrinfo(res);
    return UA_STATUSCODE_GOOD;

 cleanup:
    UA_LOG_ERROR(nm->logger, UA_LOGCATEGORY_NETWORK,
                 "Error calling socket callback %s",
                 UA_StatusCode_name(retval));
    if(*outDomainNames) {
        UA_Array_delete(*outDomainNames, sockets_size, &UA_TYPES[UA_TYPES_STRING]);
        *outDomainNames = NULL;
    }
    if(*outSocketIds) {
        UA_free(*outSocketIds);
        *outSocketIds = NULL;
    }
    UA_freeaddrinfo(res);
    return retval;
}
