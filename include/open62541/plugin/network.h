/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2019 (c) Mark Giraud, Fraunhofer IOSB
 */

#ifndef OPEN62541_NETWORKMANAGER_H
#define OPEN62541_NETWORKMANAGER_H

#include <open62541/types.h>
#include <open62541/plugin/log.h>

_UA_BEGIN_DECLS

/**
 * Socket
 * ------
 *
 */

typedef struct UA_Socket UA_Socket;
typedef struct UA_NetworkManager UA_NetworkManager;

typedef void (*UA_SocketCallback)(UA_Socket *socket);
typedef UA_StatusCode (*UA_SocketApplicationCallback)(void *application, UA_Socket *socket);
typedef UA_StatusCode (*UA_SocketReceiveCallback)
    (void *application, UA_Socket *socket, const UA_ByteString data);

typedef enum {
    UA_SOCKETSTATE_NEW,
    UA_SOCKETSTATE_OPEN,
    UA_SOCKETSTATE_CLOSED,
} UA_SocketState;

struct UA_Socket {
    UA_UInt64 id; /* The socket id. Used by the NetworkManager to map to an
                   * internal representation (e.g. file descriptor) */
    UA_SocketState socketState;
    void *application; /* The application pointer points to the application the
                        * socket is associated with. (e.g server/client) */
    void *context; /* The context is reserved for the application to set to the
                    * pointer. The NetworkManager can set a hidden context by
                    * allocating a longer (opaque) struct for the socket. */

    /* If set to true, the network manager will call the activity function if
     * the socket is writeable. */
    UA_Boolean waitForWriteActivity;

    /* If set to true, the networkm manager will call the activity function if
     * the socket is readable. */
    UA_Boolean waitForReadActivity;

    UA_NetworkManager *networkManager;

    /**
     * The discovery url that can be used to connect to the server on this
     * socket. Data sockets have discovery urls as well, because it needs to be
     * checked, if the discovery url in a hello message is the same as the one
     * used to connect to the listener socket. That means the discovery url is
     * inherited from the listener socket.
     */
    UA_String discoveryUrl;

    /**
     * This flag indicates if the socket is a listener socket that accepts new
     * connections.
     */
    UA_Boolean isListener;

    /* Closes the socket. This typically also signals the mayDelete function to
     * return true, indicating that the socket can be safely deleted on the next
     * NetworkManager iteration. */
    UA_SocketCallback close;

    /* This function deletes all data and callbacks attached to the socket. This
     * function is only called by the network manager after the socket has been
     * closed. */
    UA_SocketCallback clear;

    /**
     * This function can be called to process data pending on the socket.
     * Normally it should only be called once the socket is available
     * for writing or reading (e.g. after it was selected by a select call).
     *
     * Internally depending on the implementation a callback may be called
     * if there was data that needs to be further processed by the application.
     *
     * Listener sockets will typically create a new socket and call the
     * appropriate creation callbacks.
     *
     * \param socket The socket to perform the operation on.
     */
    void (*activity)(UA_Socket *socket, UA_Boolean readActivity,
                     UA_Boolean writeActivity);

    /**
     * Sends the data contained in the send buffer. The data in the buffer is lost
     * after calling send.
     * Always call getSendBuffer to get a buffer and write the data to that buffer.
     * The length needs to be set to the amount of bytes to send.
     * The length may not exceed the originally allocated length.
     * \param socket the socket to perform the operation on.
     */
    UA_StatusCode (*send)(UA_Socket *socket, UA_ByteString *buffer);

    /**
     * This function can be used to get a send buffer from the socket implementation.
     * To send data, directly write to this buffer. Calling send, will send the
     * contained data. The length of the buffer determines the bytes sent.
     *
     * \param socket the socket to perform the operation on.
     * \param buffer the pointer the the allocated buffer
     */
    UA_StatusCode (*acquireSendBuffer)(UA_Socket *socket, size_t bufferSize,
                                       UA_ByteString *p_buffer);

    /**
     * Releases a previously acquired send buffer.
     *
     * \param socket the socket to perform the operation on.
     * \param buffer the pointer to the buffer that will be released.
     */
    void (*releaseSendBuffer)(UA_Socket *socket, UA_ByteString *buffer);
};

/**
 * Network Manager
 * ---------------
 *
 */

struct UA_NetworkManager {
    /* On successful creation, the socket is kept in the network manager, until
     * it is closed. The network manager will free the socket and the socket
     * will call its free callback.
     *
     * \param socketSize The length of the socket struct. It must be at least
     *        sizeof(UA_Socket) long.
     */
    UA_StatusCode (*createSocket)(UA_NetworkManager *networkManager,
                                  size_t socketSize, UA_Socket **outSocket);

    UA_StatusCode (*registerSocket)(UA_NetworkManager *networkManager,
                                    UA_Socket *socket);

    UA_StatusCode (*deleteSocket)(UA_NetworkManager *networkManager,
                                  UA_Socket *socket);

    /* Processes all registered sockets.
     *
     * If a socket has pending data on it, the sockets activity function is called.
     * The activity function will perform internal processing specific to the socket.
     * When the socket has data that is ready to be processed, the dataCallback will
     * be called.
     *
     * \param timeout The process function will wait for timeout milliseconds or until
     *                one of the registered sockets is active. */
    UA_StatusCode (*process)(UA_NetworkManager *networkManager, UA_UInt16 timeout);

    /**
     * Checks if the supplied socket has pending activity and calls the activity callback chain
     * if there is activity.
     *
     * \param networkManager The NetworkManager to perform the operation on.
     * \param timeout The processSocket function will wait for timeout milliseconds or
     *                until the socket is active.
     * \return
     */
    UA_StatusCode (*processSocket)(UA_NetworkManager *networkManager,
                                   UA_UInt32 timeout, UA_Socket *socket);

    /**
     * Starts the network manager.
     * Performs initial setup and needs to be called before using the network manager.
     * \param networkManager The NetworkManager to perform the operation on.
     */
    UA_StatusCode (*start)(UA_NetworkManager *networkManager);

    /**
     * Shuts down the NetworkManager. This will shut down and free all registered sockets.
     *
     * \param networkManager The NetworkManager to perform the operation on.
     */
    UA_StatusCode (*shutdown)(UA_NetworkManager *networkManager);

    /**
     * Cleans up all internally allocated data in the NetworkManager and then frees it.
     *
     * \param networkManager The NetworkManager to perform the operation on.
     */
    UA_StatusCode (*clear)(UA_NetworkManager *networkManager);

    const UA_Logger *logger;
};

_UA_END_DECLS

#endif //OPEN62541_NETWORKMANAGER_H
