/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2018-2019 (c) Mark Giraud, Fraunhofer IOSB
 */

#ifndef OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H
#define OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H

#include "ua_plugin_socket.h"

_UA_BEGIN_DECLS

struct UA_NetworkManager {
    UA_Logger *logger;
    
    /**
     * Registers the supplied socket in the NetworkManager
     * The NetworkManager gains ownership over the pointer and will free the socket
     * if it is closed.
     *
     * To regain ownership the unregisterSocket function can be used.
     * The socket has a freeHook that can be set by the code that registers the socket.
     * Upon being freed the socket will call the hook to enable other code to clean up
     * references to the socket before it is finally freed.
     *
     * \param networkManager The NetworkManager to perform the operation on.
     * \param socket The socket to register in the NetworkManager.
     */
    UA_StatusCode (*registerSocket)(UA_NetworkManager *networkManager, UA_Socket *socket);

    /**
     * Unregisters the supplied socket. Upon unregistering, the
     * caller gains ownership over the socket and is responsible for
     * freeing the socket, if it is no longer needed.
     * The freeHook will be called regardless of who calls the sockets free
     * function.
     *
     * \param networkManager The NetworkManager to perform the operation on.
     * \param socket The socket to unregister from the NetworkManager.
     */
    UA_StatusCode (*unregisterSocket)(UA_NetworkManager *networkManager, UA_Socket *socket);

    /**
     * Processes all registered sockets.
     * If a socket has pending data on it, the sockets activity function is called.
     * The activity function will perform internal processing specific to the socket.
     * When the socket has data that is ready to be processed, the dataCallback will
     * be called.
     * \param networkManager The NetworkManager to perform the operation on.
     * \param timeout The process function will wait for timeout milliseconds or until
     *                one of the registered sockets is active.
     */
    UA_StatusCode (*process)(UA_NetworkManager *networkManager, UA_Double timeout);

    /**
     * Gets all known discovery urls of listener sockets registered with the network manager.
     * This function will allocate an array of strings, which needs to be freed by the caller.
     *
     * \param networkManager the network manager to perform the operation on.
     * \param discoveryUrls the newly allocated array of discoveryUrls.
     * \param discoveryUrlsSize the size of the discoveryUrls array.
     */
    UA_StatusCode (*getDiscoveryUrls)(const UA_NetworkManager *networkManager,
                                      UA_String *discoveryUrls[],
                                      size_t *discoveryUrlsSize);

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
    UA_StatusCode (*free)(UA_NetworkManager *networkManager);

    /**
     * This function can be used to get a send buffer from the socket implementation.
     * To send data, directly write to this buffer. Calling send, will send the
     * contained data. The length of the buffer determines the bytes sent.
     *
     * \param socket the socket to perform the operation on.
     * \param buffer the pointer the the allocated buffer
     * \return
     */
    UA_ByteString (*getSendBuffer)(UA_NetworkManager *nm, size_t bufferSize);

    void (*deleteSendBuffer)(UA_NetworkManager *nm, UA_ByteString *buffer);
};

_UA_END_DECLS

#endif //OPEN62541_UA_PLUGIN_NETWORK_MANAGER_H
