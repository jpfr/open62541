/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2018-2019 (c) Mark Giraud, Fraunhofer IOSB
 */

#include <open62541/plugin/log.h>
#include <open62541/types_generated_handling.h>
#include <open62541/plugin/networking/networkmanagers.h>
#include "open62541_queue.h"

#ifndef container_of
#define container_of(ptr, type, member) \
    (type *)((uintptr_t)ptr - offsetof(type,member))
#endif

typedef struct UA_SocketListEntry {
    LIST_ENTRY(UA_SocketListEntry) pointers;
    UA_Socket socket;
} UA_SocketListEntry;

typedef struct {
    LIST_HEAD(, UA_SocketListEntry) sockets;
    size_t numSockets;
} SocketList;

static UA_StatusCode
select_nm_createSocket(UA_NetworkManager *nm, size_t socketSize,
                       UA_Socket **outSocket) {
    UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK,
                 "Creating new socket in network manager");
    size_t size = socketSize + sizeof(UA_SocketListEntry) - sizeof(UA_Socket);
    UA_SocketListEntry *newSocket = (UA_SocketListEntry*)UA_malloc(size);
    if(!newSocket)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    memset(newSocket, 0, size);
    *outSocket = &newSocket->socket;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
select_nm_registerSocket(UA_NetworkManager *nm, UA_Socket *socket) {
    SocketList *sl = (SocketList*)nm->context;
    if(sl->numSockets >= FD_SETSIZE) {
        UA_LOG_ERROR(nm->logger, UA_LOGCATEGORY_NETWORK,
                     "The select based network manager cannot handle "
                     "more than %i concurrent connections", FD_SETSIZE);
        return UA_STATUSCODE_BADMAXCONNECTIONSREACHED;
    }

    UA_SocketListEntry *entry = container_of(socket, UA_SocketListEntry, socket);
    LIST_INSERT_HEAD(&sl->sockets, entry, pointers);
    ++sl->numSockets;
    UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK,
                 "Registered socket with id %i", (int)socket->id);
    return UA_STATUSCODE_GOOD;
}

static void
select_nm_deleteSocket(UA_NetworkManager *nm, UA_Socket *socket) {
    SocketList *sl = (SocketList*)nm->context;
    UA_SocketListEntry *entry = container_of(socket, UA_SocketListEntry, socket);
    LIST_REMOVE(entry, pointers);
    --sl->numSockets;
    entry->socket.clear(&entry->socket);
    UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK,
                 "Removed socket with id %i", (int)socket->id);
    UA_free(entry);
}

static UA_Socket *
select_nm_getSocket(UA_NetworkManager *nm, UA_UInt64 socketId) {
    SocketList *sl = (SocketList*)nm->context;
    UA_SocketListEntry *socketListEntry;
    LIST_FOREACH(socketListEntry, &sl->sockets, pointers) {
        if(socketListEntry->socket.id == socketId)
            return &socketListEntry->socket;
    }
    return NULL;
}

static UA_Int32
setFDSet(SocketList *sl, fd_set *readfdset, fd_set *writefdset, fd_set *errfdset) {
    FD_ZERO(readfdset);
    FD_ZERO(writefdset);
    FD_ZERO(errfdset);
    UA_Int32 highestfd = -1;
    UA_SocketListEntry *socketListEntry;
    LIST_FOREACH(socketListEntry, &sl->sockets, pointers) {
        UA_fd_set((UA_SOCKET)socketListEntry->socket.id, readfdset);
        UA_fd_set((UA_SOCKET)socketListEntry->socket.id, errfdset);
        if((UA_Int32)socketListEntry->socket.id > highestfd)
            highestfd = (UA_Int32)socketListEntry->socket.id;
    }
    return highestfd;
}

static void
select_nm_process(UA_NetworkManager *nm, UA_UInt32 timeout) {
    if(nm == NULL)
        return;
    SocketList *sl = (SocketList*)nm->context;

    /* UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK, */
    /*              "Call select on %lu open sockets with a timeout of " */
    /*              "%u msec", sl->numSockets, timeout); */

    fd_set readfdset, writefdset, errfdset;
    UA_Int32 highestfd = setFDSet(sl, &readfdset, &writefdset, &errfdset);
    long int secs = timeout / 1000;
    long int microsecs = (timeout * 1000) % 1000000;
    struct timeval tmptv = {secs, microsecs};
    if(highestfd < 0)
        return;
    int res = UA_select(highestfd + 1, &readfdset, &writefdset, &errfdset, &tmptv);
    if(res < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK,
                                              "Socket select failed with %s", errno_str));
        return;
    }

    /* Read from established sockets and check if sockets can be cleaned up */
    UA_SocketListEntry *socketListEntry, *e_tmp;
    LIST_FOREACH_SAFE(socketListEntry, &sl->sockets, pointers, e_tmp) {
        UA_Socket *socket = &socketListEntry->socket;
        if(socket->state == UA_SOCKETSTATE_CLOSED) {
            UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK,
                         "Socket %i | Delete a closed socket", (int)socket->id);
            select_nm_deleteSocket(nm, socket);
            continue;
        }

        UA_Boolean errActivity = UA_fd_isset((UA_SOCKET)socket->id, &errfdset);
        if(errActivity) {
            UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK,
                         "Socket %i | Exception. Close the socket.", (int)socket->id);
            socket->close(socket);
            continue;
        }

        socket->activity(socket);
    }
}

static void
select_nm_processSocket(UA_NetworkManager *nm, UA_UInt32 timeout, UA_Socket *sock) {
    if(nm == NULL || sock == NULL)
        return;

    fd_set readfdset, errfdset;
    FD_ZERO(&readfdset);
    FD_ZERO(&errfdset);
    UA_fd_set((UA_SOCKET)sock->id, &readfdset);
    UA_fd_set((UA_SOCKET)sock->id, &errfdset);

    long int secs = timeout / 1000;
    long int microsecs = (timeout * 1000) % 1000000;
    struct timeval tmptv = {secs, microsecs};

    int resultsize = UA_select((UA_Int32)(sock->id + 1), &readfdset, NULL, &errfdset, &tmptv);
    if(resultsize == 1) {
        UA_Boolean readActivity = UA_fd_isset((UA_SOCKET)sock->id, &readfdset);
        UA_Boolean errActivity = UA_fd_isset((UA_SOCKET)sock->id, &errfdset);
        if(!readActivity && !errActivity)
            return;
        if(errActivity) {
            sock->close(sock);
            return;
        }
        sock->activity(sock);
        return;
    }

    if(resultsize == 0) {
        UA_LOG_ERROR(nm->logger, UA_LOGCATEGORY_NETWORK, "Socket select timed out");
        return;
    }

    if(resultsize == -1) {
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_ERROR(nm->logger, UA_LOGCATEGORY_NETWORK,
                                              "Socket select failed with %s", errno_str));
    }
}

static void
select_nm_clear(UA_NetworkManager *nm) {
    if(nm == NULL)
        return;

    UA_LOG_INFO(nm->logger, UA_LOGCATEGORY_NETWORK, "Shutting down network manager");

    /* Close all sockets */
    UA_SocketListEntry *socketListEntry, *e_tmp;
    SocketList *sl = (SocketList*)nm->context;
    LIST_FOREACH(socketListEntry, &sl->sockets, pointers) {
        UA_LOG_INFO(nm->logger, UA_LOGCATEGORY_NETWORK,
                    "Closing remaining socket with id %i",
                    (int)socketListEntry->socket.id);
        socketListEntry->socket.close(&socketListEntry->socket);
    }

    /* Process a last time to clean up to closed sockets */
    nm->process(nm, 0);

    LIST_FOREACH_SAFE(socketListEntry, &sl->sockets, pointers, e_tmp) {
        UA_LOG_DEBUG(nm->logger, UA_LOGCATEGORY_NETWORK,
                     "Removing remaining socket with id %i", (int)socketListEntry->socket.id);
        socketListEntry->socket.clear(&socketListEntry->socket);
        LIST_REMOVE(socketListEntry, pointers);
        UA_free(socketListEntry);
    }
    UA_free(nm->context);
}

UA_StatusCode
UA_SelectBasedNetworkManager(const UA_Logger *logger, UA_NetworkManager *nm) {
    if(!nm || !logger)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_LOG_DEBUG(logger, UA_LOGCATEGORY_NETWORK, "Setting up select based network manager");

    SocketList *sl= (SocketList*)UA_calloc(1, sizeof(SocketList));
    if(!sl) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_NETWORK,
                     "Could not allocate NetworkManager: Out of memory");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    nm->createSocket = select_nm_createSocket;
    nm->deleteSocket = select_nm_deleteSocket;
    nm->registerSocket = select_nm_registerSocket;
    nm->getSocket = select_nm_getSocket;
    nm->process = select_nm_process;
    nm->processSocket = select_nm_processSocket;
    nm->clear = select_nm_clear;
    nm->logger = logger;
    nm->context = sl;

    return UA_STATUSCODE_GOOD;
}
