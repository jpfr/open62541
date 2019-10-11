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

typedef enum {
    UA_NETWORKMANAGER_NEW,
    UA_NETWORKMANAGER_RUNNING,
    UA_NETWORKMANAGER_SHUTDOWN,
} UA_NetworkManagerState;

typedef struct {
    UA_NetworkManager baseManager;
    UA_NetworkManagerState state;
    LIST_HEAD(, UA_SocketListEntry) sockets;
    size_t numSockets;
} UA_NetworkManager_selectBased;

static UA_StatusCode
select_nm_createSocket(UA_NetworkManager *networkManager, size_t socketSize,
                       UA_Socket **outSocket) {
    UA_NetworkManager_selectBased *const internalManager =
        (UA_NetworkManager_selectBased *const)networkManager;
    if(internalManager->state != UA_NETWORKMANAGER_RUNNING) {
        UA_LOG_ERROR(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                     "Cannot create socket on uninitialized or shutdown network manager");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_LOG_DEBUG(networkManager->logger, UA_LOGCATEGORY_NETWORK,
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
select_nm_registerSocket(UA_NetworkManager *networkManager, UA_Socket *socket) {
    UA_NetworkManager_selectBased *const internalManager =
        (UA_NetworkManager_selectBased *const)networkManager;
    if(internalManager->numSockets >= FD_SETSIZE) {
        UA_LOG_ERROR(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                     "The select based network manager cannot handle "
                     "more than %i concurrent connections", FD_SETSIZE);
        return UA_STATUSCODE_BADMAXCONNECTIONSREACHED;
    }

    UA_SocketListEntry *entry = container_of(socket, UA_SocketListEntry, socket);
    LIST_INSERT_HEAD(&internalManager->sockets, entry, pointers);
    UA_LOG_DEBUG(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                 "Registered socket with id %i", (int)socket->id);
    ++internalManager->numSockets;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
select_nm_deleteSocket(UA_NetworkManager *networkManager, UA_Socket *socket) {
    UA_NetworkManager_selectBased *const internalManager =
        (UA_NetworkManager_selectBased *const)networkManager;
    UA_SocketListEntry *entry = container_of(socket, UA_SocketListEntry, socket);
    LIST_REMOVE(entry, pointers);
    --internalManager->numSockets;
    entry->socket.clear(&entry->socket);
    UA_free(entry);
    UA_LOG_DEBUG(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                 "Removed socket with id %i", (int)socket->id);
    return UA_STATUSCODE_GOOD;
}

static UA_Int32
setFDSet(UA_NetworkManager_selectBased *networkManager,
         fd_set *readfdset, fd_set *writefdset) {
    FD_ZERO(readfdset);
    FD_ZERO(writefdset);
    UA_Int32 highestfd = -1;
    UA_SocketListEntry *socketListEntry;
    LIST_FOREACH(socketListEntry, &networkManager->sockets, pointers) {
        if(socketListEntry->socket.waitForWriteActivity)
            UA_fd_set((UA_SOCKET)socketListEntry->socket.id, writefdset);
        if(socketListEntry->socket.waitForReadActivity)
            UA_fd_set((UA_SOCKET)socketListEntry->socket.id, readfdset);
        if((UA_Int32)socketListEntry->socket.id > highestfd)
            highestfd = (UA_Int32)socketListEntry->socket.id;
    }
    return highestfd;
}

static UA_StatusCode
select_nm_process(UA_NetworkManager *networkManager, UA_UInt16 timeout) {
    if(networkManager == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_NetworkManager_selectBased *const internalManager =
        (UA_NetworkManager_selectBased *const)networkManager;

    fd_set readfdset, writefdset;
    UA_Int32 highestfd = setFDSet(internalManager, &readfdset, &writefdset);
    long int secs = timeout / 1000;
    long int microsecs = (timeout * 1000) % 1000000;
    struct timeval tmptv = {secs, microsecs};
    if(highestfd < 0)
        return UA_STATUSCODE_GOOD;
    if(UA_select(highestfd + 1, &readfdset, &writefdset, NULL, &tmptv) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_DEBUG(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                         "Socket select failed with %s", errno_str));
        return UA_STATUSCODE_GOOD;
    }

    /* Read from established sockets and check if sockets can be cleaned up */
    UA_SocketListEntry *socketListEntry, *e_tmp;
    LIST_FOREACH_SAFE(socketListEntry, &internalManager->sockets, pointers, e_tmp) {
        UA_Socket *const socket = &socketListEntry->socket;
        UA_Boolean readActivity = UA_fd_isset((UA_SOCKET)socket->id, &readfdset);
        UA_Boolean writeActivity = UA_fd_isset((UA_SOCKET)socket->id, &writefdset);
        if(!readActivity && !writeActivity)
            continue;

        UA_LOG_TRACE(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                     "Activity on socket with id %i", (int)socket->id);

        if(socket->socketState == UA_SOCKETSTATE_CLOSED) {
            select_nm_deleteSocket(networkManager, socket);
            continue;
        }

        socket->activity(socket, readActivity, writeActivity);
    }
    return retval;
}

static UA_StatusCode
select_nm_processSocket(UA_NetworkManager *networkManager, UA_UInt32 timeout,
                        UA_Socket *sock) {
    if(networkManager == NULL || sock == NULL)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    fd_set readfdset;
    FD_ZERO(&readfdset);
    fd_set writefdset;
    FD_ZERO(&writefdset);

    if(sock->waitForWriteActivity)
        UA_fd_set((UA_SOCKET)sock->id, &writefdset);
    if(sock->waitForReadActivity)
        UA_fd_set((UA_SOCKET)sock->id, &readfdset);

    long int secs = timeout / 1000;
    long int microsecs = (timeout * 1000) % 1000000;
    struct timeval tmptv = {secs, microsecs};

    int resultsize = UA_select((UA_Int32)(sock->id + 1), &readfdset, &writefdset, NULL, &tmptv);
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    if(resultsize == 1) {
        UA_Boolean readActivity = UA_fd_isset((UA_SOCKET)sock->id, &readfdset);
        UA_Boolean writeActivity = UA_fd_isset((UA_SOCKET)sock->id, &writefdset);
        sock->activity(sock, readActivity, writeActivity);
    }

    if(resultsize == 0) {
        UA_LOG_ERROR(networkManager->logger, UA_LOGCATEGORY_NETWORK, "Socket select timed out");
        return UA_STATUSCODE_BADTIMEOUT;
    }

    if(resultsize == -1) {
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_ERROR(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                                              "Socket select failed with %s", errno_str));
        retval = UA_STATUSCODE_BADINTERNALERROR;
    }
    return retval;
}

static UA_StatusCode
select_nm_start(UA_NetworkManager *networkManager) {
    if(networkManager == NULL)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_NetworkManager_selectBased *const internalManager =
        (UA_NetworkManager_selectBased *const)networkManager;
    UA_LOG_INFO(networkManager->logger, UA_LOGCATEGORY_NETWORK, "Starting network manager");
    UA_initialize_architecture_network();
    internalManager->state = UA_NETWORKMANAGER_RUNNING;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
select_nm_shutdown(UA_NetworkManager *networkManager) {
    if(!networkManager)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_NetworkManager_selectBased *internalManager =
        (UA_NetworkManager_selectBased *)networkManager;

    if(internalManager->state == UA_NETWORKMANAGER_NEW) {
        UA_LOG_ERROR(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                     "Cannot call shutdown before start");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(internalManager->state == UA_NETWORKMANAGER_SHUTDOWN)
        return UA_STATUSCODE_GOOD;

    UA_LOG_INFO(networkManager->logger, UA_LOGCATEGORY_NETWORK, "Shutting down network manager");

    /* Close all sockets */
    UA_SocketListEntry *socketListEntry;
    LIST_FOREACH(socketListEntry, &internalManager->sockets, pointers) {
        UA_LOG_INFO(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                    "Closing remaining socket with id %i", (int)socketListEntry->socket.id);
        socketListEntry->socket.close(&socketListEntry->socket);
    }

    /* Process a last time to clean up to closed sockets */
    networkManager->process(networkManager, 0);

    internalManager->state = UA_NETWORKMANAGER_SHUTDOWN;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
select_nm_clear(UA_NetworkManager *networkManager) {
    if(networkManager == NULL)
        return UA_STATUSCODE_GOOD;

    UA_NetworkManager_selectBased *const internalManager =
        (UA_NetworkManager_selectBased *const)networkManager;
    UA_LOG_DEBUG(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                 "Deleting select based network manager");

    if(internalManager->state != UA_NETWORKMANAGER_SHUTDOWN)
        networkManager->shutdown(networkManager);

    UA_SocketListEntry *socketListEntry, *e_tmp;
    LIST_FOREACH_SAFE(socketListEntry, &internalManager->sockets, pointers, e_tmp) {
        UA_LOG_DEBUG(networkManager->logger, UA_LOGCATEGORY_NETWORK,
                     "Removing remaining socket with id %i", (int)socketListEntry->socket.id);
        socketListEntry->socket.clear(&socketListEntry->socket);
        LIST_REMOVE(socketListEntry, pointers);
        UA_free(socketListEntry);
    }

    UA_free(networkManager);

    UA_deinitialize_architecture_network();

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_SelectBasedNetworkManager(const UA_Logger *logger, UA_NetworkManager **p_networkManager) {
    if(!p_networkManager || !logger)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_LOG_DEBUG(logger, UA_LOGCATEGORY_NETWORK, "Setting up select based network manager");

    UA_NetworkManager_selectBased *networkManager = (UA_NetworkManager_selectBased *)
        UA_malloc(sizeof(UA_NetworkManager_selectBased));
    if(!networkManager) {
        UA_LOG_ERROR(logger, UA_LOGCATEGORY_NETWORK,
                     "Could not allocate NetworkManager: Out of memory");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    memset(networkManager, 0, sizeof(UA_NetworkManager_selectBased));
    networkManager->baseManager.createSocket = select_nm_createSocket;
    networkManager->baseManager.registerSocket = select_nm_registerSocket;
    networkManager->baseManager.deleteSocket = select_nm_deleteSocket;
    networkManager->baseManager.process = select_nm_process;
    networkManager->baseManager.processSocket = select_nm_processSocket;
    networkManager->baseManager.start = select_nm_start;
    networkManager->baseManager.shutdown = select_nm_shutdown;
    networkManager->baseManager.clear = select_nm_clear;
    networkManager->baseManager.logger = logger;
    networkManager->numSockets = 0;
    networkManager->state = UA_NETWORKMANAGER_NEW;

    *p_networkManager = (UA_NetworkManager *)networkManager;
    return UA_STATUSCODE_GOOD;
}
