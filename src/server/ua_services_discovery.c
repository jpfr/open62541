/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ua_server_internal.h"
#include "ua_services.h"
#include "ua_mdns_internal.h"

#ifdef _MSC_VER
# ifndef UNDER_CE
#  include <io.h> //access
#  define access _access
# endif
#else
# include <unistd.h> //access
#endif

#ifdef UA_ENABLE_DISCOVERY
static UA_StatusCode
setApplicationDescriptionFromRegisteredServer(const UA_FindServersRequest *request,
                                              const UA_RegisteredServer *registeredServer,
                                              UA_ApplicationDescription *target) {
    UA_StatusCode retval = UA_String_copy(&registeredServer->serverUri, &target->applicationUri);
    retval |= UA_String_copy(&registeredServer->productUri, &target->productUri);

    // if the client requests a specific locale, select the corresponding server name
    if(request->localeIdsSize) {
        UA_Boolean appNameFound = UA_FALSE;
        for(size_t i = 0; i < request->localeIdsSize && !appNameFound; i++) {
            for(size_t j = 0; j < registeredServer->serverNamesSize; j++) {
                if(UA_String_equal(&request->localeIds[i],
                                   &registeredServer->serverNames[j].locale)) {
                    retval |= UA_LocalizedText_copy(&registeredServer->serverNames[j],
                                                    &target->applicationName);
                    appNameFound = UA_TRUE;
                    break;
                }
            }
        }

        // server does not have the requested local, therefore we can select the
        // most suitable one
        if(!appNameFound && registeredServer->serverNamesSize)
            retval |= UA_LocalizedText_copy(&registeredServer->serverNames[0],
                                            &target->applicationName);
    } else if(registeredServer->serverNamesSize) {
        // just take the first name
        retval |= UA_LocalizedText_copy(&registeredServer->serverNames[0],
                                        &target->applicationName);
    }

    target->applicationType = registeredServer->serverType;
    retval |= UA_String_copy(&registeredServer->gatewayServerUri,
                             &target->gatewayServerUri);
    // TODO where do we get the discoveryProfileUri for application data?

    target->discoveryUrlsSize = registeredServer->discoveryUrlsSize;
    if(registeredServer->discoveryUrlsSize) {
        size_t duSize = sizeof(UA_String) * registeredServer->discoveryUrlsSize;
        target->discoveryUrls = (UA_String *)UA_malloc(duSize);
        if(!target->discoveryUrls)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        for(size_t i = 0; i < registeredServer->discoveryUrlsSize; i++)
            retval |= UA_String_copy(&registeredServer->discoveryUrls[i],
                                     &target->discoveryUrls[i]);
    }

    return retval;
}

#endif

static UA_StatusCode
setApplicationDescriptionFromServer(UA_ApplicationDescription *target,
                                    const UA_Server *server) {
    /* Copy ApplicationDescription from the config */
    UA_StatusCode result =
        UA_ApplicationDescription_copy(&server->config.applicationDescription,
                                       target);
    if(result != UA_STATUSCODE_GOOD)
        return result;

    /* UaExpert does not list DiscoveryServer, thus set it to Server
     * See http://forum.unified-automation.com/topic1987.html */
    if(target->applicationType == UA_APPLICATIONTYPE_DISCOVERYSERVER)
        target->applicationType = UA_APPLICATIONTYPE_SERVER;

    /* Add the discoveryUrls from the networklayers */
    size_t existing = target->discoveryUrlsSize;
    size_t discSize = sizeof(UA_String) * (existing + server->config.networkLayersSize);
    UA_String* disc = (UA_String *)UA_realloc(target->discoveryUrls, discSize);
    if(!disc)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    target->discoveryUrls = disc;
    target->discoveryUrlsSize += server->config.networkLayersSize;

    // TODO: Add nl only if discoveryUrl not already present
    for(size_t i = 0; i < server->config.networkLayersSize; i++) {
        UA_ServerNetworkLayer* nl = &server->config.networkLayers[i];
        result |= UA_String_copy(&nl->discoveryUrl, &target->discoveryUrls[existing + i]);
    }
    return result;
}

void Service_FindServers(UA_Server *server, UA_Session *session,
                         const UA_FindServersRequest *request,
                         UA_FindServersResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logger, session,
                         "Processing FindServersRequest");

    /* Add registered servers. Temporarily store all the pointers which we found
     * to avoid reiterating through the list */
    size_t matchesSize = 0;
#ifdef UA_ENABLE_DISCOVERY
    UA_RegisteredServer **matches =
        UA_alloca(sizeof(UA_RegisteredServer*) * server->registeredServersSize);
    registeredServer_list_entry* current;
    LIST_FOREACH(current, &server->registeredServers, pointers) {
        if(request->serverUrisSize == 0) {
            matches[matchesSize] = &current->registeredServer;
            ++matchesSize;
            continue;
        }
        
        for(size_t i = 0; i < request->serverUrisSize; i++) {
            if(!UA_String_equal(&current->registeredServer.serverUri,
                                &request->serverUris[i]))
                continue;
            matches[matchesSize] = &current->registeredServer;
            ++matchesSize;
            break;
        }
    }
#endif

    /* Add self? */
    UA_Boolean addSelf = UA_FALSE;
    if(request->serverUrisSize == 0) {
        addSelf = true;
        ++matchesSize;
    } else {
        for(size_t i = 0; i < request->serverUrisSize; i++) {
            if(!addSelf && UA_String_equal(&request->serverUris[i],
                                           &server->config.applicationDescription.applicationUri)) {
                addSelf = UA_TRUE;
                ++matchesSize;
                break;
            }
        }
    }

    /* Quit early if no results */
    if(matchesSize == 0)
        return;

    /* Instantiate results array */
    response->servers = UA_Array_new(matchesSize, &UA_TYPES[UA_TYPES_APPLICATIONDESCRIPTION]);
    if(!response->servers) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }

    /* Copy the results */
    if(addSelf) {
        response->responseHeader.serviceResult =
            setApplicationDescriptionFromServer(&response->servers[0], server);
        if(response->responseHeader.serviceResult != UA_STATUSCODE_GOOD)
            goto cleanup;
        --response->serversSize;
        --matchesSize;
    }

#ifdef UA_ENABLE_DISCOVERY
    for(size_t i = 0; i < matchesSize; ++i) {
        response->responseHeader.serviceResult =
            setApplicationDescriptionFromRegisteredServer(request, matches[i],
                                                          &response->servers[response->serversSize]);
        if(response->responseHeader.serviceResult != UA_STATUSCODE_GOOD)
            goto cleanup;
        response->serversSize++;
    }
#endif

    return;

    /* If something went wrong, clean up */
 cleanup:
    for(size_t i = 0; i < response->serversSize; i++)
        UA_ApplicationDescription_deleteMembers(&response->servers[i]);
    UA_free(response->servers);
    response->servers = NULL;
    response->serversSize = 0;
}

void Service_GetEndpoints(UA_Server *server, UA_Session *session,
                          const UA_GetEndpointsRequest *request,
                          UA_GetEndpointsResponse *response) {
    /* If the client expects to see a specific endpointurl, mirror it back. If
       not, clone the endpoints with the discovery url of all networklayers. */
    const UA_String *endpointUrl = &request->endpointUrl;
    if(endpointUrl->length > 0) {
        UA_LOG_DEBUG_SESSION(server->config.logger, session,
                             "Processing GetEndpointsRequest with endpointUrl "
                             UA_PRINTF_STRING_FORMAT, UA_PRINTF_STRING_DATA(*endpointUrl));
    } else {
        UA_LOG_DEBUG_SESSION(server->config.logger, session,
                             "Processing GetEndpointsRequest with an empty endpointUrl");
    }

    /* Test if the supported binary profile shall be returned */
    size_t reSize = sizeof(UA_Boolean) * server->endpointDescriptionsSize;
    UA_Boolean *relevant_endpoints = (UA_Boolean *)UA_alloca(reSize);
    memset(relevant_endpoints, 0, sizeof(UA_Boolean) * server->endpointDescriptionsSize);
    size_t relevant_count = 0;
    if(request->profileUrisSize == 0) {
        for(size_t j = 0; j < server->endpointDescriptionsSize; ++j)
            relevant_endpoints[j] = true;
        relevant_count = server->endpointDescriptionsSize;
    } else {
        for(size_t j = 0; j < server->endpointDescriptionsSize; ++j) {
            for(size_t i = 0; i < request->profileUrisSize; ++i) {
                if(!UA_String_equal(&request->profileUris[i],
                                    &server->endpointDescriptions[j].transportProfileUri))
                    continue;
                relevant_endpoints[j] = true;
                ++relevant_count;
                break;
            }
        }
    }

    if(relevant_count == 0) {
        response->endpointsSize = 0;
        return;
    }

    /* Clone the endpoint for each networklayer? */
    size_t clone_times = 1;
    UA_Boolean nl_endpointurl = false;
    if(endpointUrl->length == 0) {
        clone_times = server->config.networkLayersSize;
        nl_endpointurl = true;
    }

    response->endpoints =
        (UA_EndpointDescription*)UA_Array_new(relevant_count * clone_times,
                                              &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(!response->endpoints) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }
    response->endpointsSize = relevant_count * clone_times;

    size_t k = 0;
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    for(size_t i = 0; i < clone_times; ++i) {
        if(nl_endpointurl)
            endpointUrl = &server->config.networkLayers[i].discoveryUrl;
        for(size_t j = 0; j < server->endpointDescriptionsSize; ++j) {
            if(!relevant_endpoints[j])
                continue;
            retval |= UA_EndpointDescription_copy(&server->endpointDescriptions[j],
                                                  &response->endpoints[k]);
            retval |= UA_String_copy(endpointUrl, &response->endpoints[k].endpointUrl);
            ++k;
        }
    }

    if(retval != UA_STATUSCODE_GOOD) {
        response->responseHeader.serviceResult = retval;
        UA_Array_delete(response->endpoints, response->endpointsSize,
                        &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
        response->endpoints = NULL;
        response->endpointsSize = 0;
        return;
    }
}

#ifdef UA_ENABLE_DISCOVERY

static UA_StatusCode
RegisterServer(UA_Server *server, UA_Session *session,
               const UA_RegisteredServer *requestServer,
               const size_t requestDiscoveryConfigurationSize,
               const UA_ExtensionObject *requestDiscoveryConfiguration,
               size_t *responseConfigurationResultsSize,
               UA_StatusCode **responseConfigurationResults) {
    /* Find the server from the request in the registered list */
    registeredServer_list_entry *registeredServer_entry;
    LIST_FOREACH(registeredServer_entry, &server->registeredServers, pointers) {
        if(UA_String_equal(&registeredServer_entry->registeredServer.serverUri,
                           &requestServer->serverUri))
            break;
    }

    /* Select the response configuration */
    UA_MdnsDiscoveryConfiguration *mdnsConfig = NULL;
    const UA_String* mdnsServerName = NULL;
    if(requestDiscoveryConfigurationSize > 0) {
        *responseConfigurationResults =
            (UA_StatusCode*)UA_Array_new(requestDiscoveryConfigurationSize,
                                         &UA_TYPES[UA_TYPES_STATUSCODE]);
        if(!(*responseConfigurationResults))
            return UA_STATUSCODE_BADOUTOFMEMORY;
        *responseConfigurationResultsSize = requestDiscoveryConfigurationSize;

        for(size_t i = 0; i < requestDiscoveryConfigurationSize; i++) {
            const UA_ExtensionObject *config = &requestDiscoveryConfiguration[i];
            if(!mdnsConfig && (config->encoding == UA_EXTENSIONOBJECT_DECODED ||
                               config->encoding == UA_EXTENSIONOBJECT_DECODED_NODELETE) &&
               (config->content.decoded.type == &UA_TYPES[UA_TYPES_MDNSDISCOVERYCONFIGURATION])) {
                mdnsConfig = (UA_MdnsDiscoveryConfiguration*)config->content.decoded.data;
                mdnsServerName = &mdnsConfig->mdnsServerName;
                /* already: (*responseConfigurationResults)[i] = UA_STATUSCODE_GOOD; */
                continue;
            }
            (*responseConfigurationResults)[i] = UA_STATUSCODE_BADNOTSUPPORTED;
        }
    }

    /* Correct the server name */
    if(!mdnsServerName && requestServer->serverNamesSize > 0)
        mdnsServerName = &requestServer->serverNames[0].text;
    if(!mdnsServerName)
        return UA_STATUSCODE_BADSERVERNAMEMISSING;

    /* No discovery Urls defined */
    if(requestServer->discoveryUrlsSize == 0)
        return UA_STATUSCODE_BADDISCOVERYURLMISSING;

    /* Check the existence of the semaphore file */
    if(requestServer->semaphoreFilePath.length) {
#ifdef UA_ENABLE_DISCOVERY_SEMAPHORE
        size_t fpSize = sizeof(char) * requestServer->semaphoreFilePath.length + 1;
        char* filePath = (char*)UA_alloca(fpSize);
        memcpy(filePath, requestServer->semaphoreFilePath.data,
               requestServer->semaphoreFilePath.length);
        filePath[requestServer->semaphoreFilePath.length] = '\0';
        if(access(filePath, 0) == -1)
            return UA_STATUSCODE_BADSEMPAHOREFILEMISSING;
#else
        UA_LOG_WARNING(server->config.logger, UA_LOGCATEGORY_CLIENT,
                       "Ignoring semaphore file path. open62541 not compiled "
                       "with UA_ENABLE_DISCOVERY_SEMAPHORE=ON");
#endif
    }

    /* Update mdns information */
#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    if(server->config.applicationDescription.applicationType == UA_APPLICATIONTYPE_DISCOVERYSERVER) {
        for(size_t i = 0; i < requestServer->discoveryUrlsSize; i++) {
            /* Create TXT if is online and first index, delete TXT if is offline and last index.
             * Todo: Explain and cite the exact reasoning for that. */
            UA_Boolean updateTxt = (requestServer->isOnline && i==0) ||
                (!requestServer->isOnline && i == requestServer->discoveryUrlsSize);
            UA_Discovery_update_MdnsForDiscoveryUrl(server, mdnsServerName, mdnsConfig,
                                                    &requestServer->discoveryUrls[i],
                                                    requestServer->isOnline, updateTxt);
        }
    }
#endif

    /* Server is shutting down. Remove it from the registered servers list. */
    if(!requestServer->isOnline) {
        if(!registeredServer_entry) {
            UA_LOG_WARNING_SESSION(server->config.logger, session,
                                   "Could not unregister server %.*s. Not registered.",
                                   (int)requestServer->serverUri.length,
                                   requestServer->serverUri.data);
            return UA_STATUSCODE_BADNOTFOUND;
        }

        /* Let userland know a server will be unregistered */
        if(server->registerServerCallback)
            server->registerServerCallback(requestServer, server->registerServerCallbackData);

        /* Server found, remove from list */
        LIST_REMOVE(registeredServer_entry, pointers);
        UA_RegisteredServer_deleteMembers(&registeredServer_entry->registeredServer);
#ifndef UA_ENABLE_MULTITHREADING
        UA_free(registeredServer_entry);
        server->registeredServersSize--;
#else
        UA_Server_delayedFree(server, registeredServer_entry);
        server->registeredServersSize = UA_atomic_add(&server->registeredServersSize, -1);
#endif
        return UA_STATUSCODE_GOOD;
    }

    /* Server not yet registered, register it by adding it to the list. */
    if(!registeredServer_entry) {
        UA_LOG_DEBUG_SESSION(server->config.logger, session,
                             "Registering new server: %.*s",
                             (int)requestServer->serverUri.length,
                             requestServer->serverUri.data);
        registeredServer_entry =
            (registeredServer_list_entry*)UA_malloc(sizeof(registeredServer_list_entry));
        if(!registeredServer_entry)
            return UA_STATUSCODE_BADOUTOFMEMORY;

        LIST_INSERT_HEAD(&server->registeredServers, registeredServer_entry, pointers);
#ifndef UA_ENABLE_MULTITHREADING
        server->registeredServersSize++;
#else
        server->registeredServersSize = UA_atomic_add(&server->registeredServersSize, 1);
#endif
        /* Let userland know a new server was registered */
        if(server->registerServerCallback)
            server->registerServerCallback(requestServer, server->registerServerCallbackData);
    } else {
        UA_RegisteredServer_deleteMembers(&registeredServer_entry->registeredServer);
    }

    /* Copy the data from the request to the newly registered server */
    UA_RegisteredServer_copy(requestServer, &registeredServer_entry->registeredServer);
    registeredServer_entry->lastSeen = UA_DateTime_nowMonotonic();
    return UA_STATUSCODE_GOOD;
}

void Service_RegisterServer(UA_Server *server, UA_Session *session,
                            const UA_RegisterServerRequest *request,
                            UA_RegisterServerResponse *response) {
    UA_LOG_DEBUG_SESSION(server->config.logger, session,
                         "Processing RegisterServerRequest");
    response->responseHeader.serviceResult =
        RegisterServer(server, session, &request->server, 0, NULL, 0, NULL);
}

void Service_RegisterServer2(UA_Server *server, UA_Session *session,
                            const UA_RegisterServer2Request *request,
                             UA_RegisterServer2Response *response) {
    UA_LOG_DEBUG_SESSION(server->config.logger, session,
                         "Processing RegisterServer2Request");
    response->responseHeader.serviceResult =
        RegisterServer(server, session, &request->server,
                       request->discoveryConfigurationSize,
                       request->discoveryConfiguration,
                       &response->configurationResultsSize,
                       &response->configurationResults);
}

static void
cleanupTimedOut(UA_Server *server, UA_DateTime timedOut,
                registeredServer_list_entry *current) {
#ifdef UA_ENABLE_DISCOVERY_SEMAPHORE
    if(current->registeredServer.semaphoreFilePath.length) {
        size_t fpSize = sizeof(char)*current->registeredServer.semaphoreFilePath.length + 1;
        char* filePath = (char *)UA_alloca(fpSize);
        memcpy(filePath, current->registeredServer.semaphoreFilePath.data,
               current->registeredServer.semaphoreFilePath.length);
        filePath[current->registeredServer.semaphoreFilePath.length] = '\0';
#ifdef UNDER_CE
        FILE *fp = fopen(filePath, "rb");
        if(fp) {
            fclose(fp);
        } else
#else
        if(access(filePath, 0) == -1)
#endif
        {
            UA_LOG_INFO(server->config.logger, UA_LOGCATEGORY_SERVER,
                        "Registration of server with URI %.*s is removed because "
                        "the semaphore file '%.*s' was deleted.",
                        (int)current->registeredServer.serverUri.length,
                        current->registeredServer.serverUri.data,
                        (int)current->registeredServer.semaphoreFilePath.length,
                        current->registeredServer.semaphoreFilePath.data);
            goto remove;
        }
    }
#endif

    if(server->config.discoveryCleanupTimeout == 0 || current->lastSeen >= timedOut)
        return;
    
    UA_LOG_INFO(server->config.logger, UA_LOGCATEGORY_SERVER,
                "Registration of server with URI %.*s has timed out and is removed.",
                (int)current->registeredServer.serverUri.length,
                current->registeredServer.serverUri.data);

    remove:
        LIST_REMOVE(current, pointers);
        UA_RegisteredServer_deleteMembers(&current->registeredServer);
#ifndef UA_ENABLE_MULTITHREADING
        UA_free(current);
        server->registeredServersSize--;
#else
        UA_Server_delayedFree(server, current);
        server->registeredServersSize = UA_atomic_add(&server->registeredServersSize, -1);
#endif
}

/* Cleanup server registration: If the semaphore file path is set, then it just
 * checks the existence of the file. When it is deleted, the registration is
 * removed. If there is no semaphore file, then the registration will be removed
 * if it is older than 60 minutes. */
void UA_Discovery_cleanupTimedOut(UA_Server *server, UA_DateTime nowMonotonic) {
    UA_DateTime timedOut = nowMonotonic;
    /* Registration is timed out if lastSeen is older than 60 minutes (default
     * value, can be modified by user). */
    if(server->config.discoveryCleanupTimeout)
        timedOut -= server->config.discoveryCleanupTimeout * UA_SEC_TO_DATETIME;

    registeredServer_list_entry* current, *temp;
    LIST_FOREACH_SAFE(current, &server->registeredServers, pointers, temp)
        cleanupTimedOut(server, timedOut, current);
}

/* Called by the UA_Server callback. The OPC UA specification says:
 *
 * > If an error occurs during registration (e.g. the Discovery Server is not
 * > running) then the Server must periodically re-attempt registration. The
 * > frequency of these attempts should start at 1 second but gradually increase
 * > until the registration frequency is the same as what it would be if not
 * > errors occurred. The recommended approach would double the period each
 * > attempt until reaching the maximum.
 *
 * We will do so by using the additional data parameter which holds information
 * if the next interval is default or if it is a repeaded call. */
static void
periodicServerRegister(UA_Server *server, void *data) {
    PeriodicServerRegisterCallbackData *cbData =
        (PeriodicServerRegisterCallbackData*)data;

    const char * server_url;
    if(cbData->discoveryServerUrl)
        server_url = cbData->discoveryServerUrl;
    else
        server_url = "opc.tcp://localhost:4840"; /* fixme: remove magic urls */

    UA_StatusCode retval = UA_Server_register_discovery(server, server_url, NULL);

    // You can also use a semaphore file. That file must exist. When the file is
    // deleted, the server is automatically unregistered. The semaphore file has
    // to be accessible by the discovery server
    //
    // UA_StatusCode retval = UA_Server_register_discovery(server,
    // "opc.tcp://localhost:4840", "/path/to/some/file");
    if(retval == UA_STATUSCODE_GOOD) {
        UA_LOG_DEBUG(server->config.logger, UA_LOGCATEGORY_SERVER,
                     "Server successfully registered. "
                     "Next periodical register will be in %d seconds",
                     (int)(cbData->regularInternvalMs/1000));
        cbData->currentIntervalMs = cbData->regularInternvalMs;
    } else {
        UA_LOG_ERROR(server->config.logger, UA_LOGCATEGORY_SERVER,
                     "Could not register server with discovery server. "
                     "Is the discovery server started? StatusCode %s",
                     UA_StatusCode_name(retval));
        if(cbData->currentIntervalMs == cbData->regularInternvalMs)
            cbData->currentIntervalMs = 1000; /* 1 second is the default */
        else
            cbData->currentIntervalMs *= 2; /* Double the interval for the next retry */
    }

    retval = UA_Server_removeRepeatedCallback(server, cbData->callbackId);
    if(retval != UA_STATUSCODE_GOOD)
        return;
    retval = UA_Server_addRepeatedCallback(server, periodicServerRegister,
                                           cbData, cbData->currentIntervalMs,
                                           &cbData->callbackId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(server->config.logger, UA_LOGCATEGORY_SERVER,
                     "Could not update the job for registering "
                     "at the discovery server: StatusCode %s",
                     UA_StatusCode_name(retval));
    }
}

UA_StatusCode
UA_Server_addPeriodicServerRegisterCallback(UA_Server *server,
                                            const char* discoveryServerUrl,
                                            const UA_UInt32 intervalMs,
                                            const UA_UInt32 delayFirstRegisterMs,
                                            UA_UInt64* periodicJobId) {
    /* Prepare the data element */
    struct PeriodicServerRegisterCallbackData *cbData =
        (struct PeriodicServerRegisterCallbackData*)
        UA_malloc(sizeof(struct PeriodicServerRegisterCallbackData));
    if(!cbData)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    cbData->currentIntervalMs = delayFirstRegisterMs;
    cbData->regularInternvalMs = intervalMs;
    cbData->discoveryServerUrl = (char*)UA_malloc(strlen(discoveryServerUrl));
    if(!cbData->discoveryServerUrl) {
        UA_free(cbData);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    memcpy(cbData->discoveryServerUrl, discoveryServerUrl, strlen(discoveryServerUrl));

    /* Registering the callback */
    UA_StatusCode retval =
        UA_Server_addRepeatedCallback(server, periodicServerRegister, cbData,
                                      delayFirstRegisterMs,
                                      &cbData->callbackId);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(server->config.logger, UA_LOGCATEGORY_SERVER,
                     "Could not create periodic job for server register. "
                     "StatusCode %s", UA_StatusCode_name(retval));
        UA_free(cbData->discoveryServerUrl);
        UA_free(cbData);
        return retval;
    }

    /* Attach the callback data to the linked list */
    LIST_INSERT_HEAD(&server->registerCallbacks, cbData, pointers);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_removePeriodicServerRegisterCallback(UA_Server *server,
                                               UA_UInt64 periodicCallbackId) {
    PeriodicServerRegisterCallbackData *data;
    LIST_FOREACH(data, &server->registerCallbacks, pointers) {
        if(data->callbackId != periodicCallbackId)
            continue;
        UA_StatusCode retval =  UA_Server_removeRepeatedCallback(server, periodicCallbackId);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        LIST_REMOVE(data, pointers);
        UA_free(data->discoveryServerUrl);
        UA_free(data);
        return UA_STATUSCODE_GOOD;
    }
    return UA_STATUSCODE_BADNOTFOUND;
}

void
UA_Server_setRegisterServerCallback(UA_Server *server,
                                    UA_Server_registerServerCallback cb,
                                    void* data) {
    server->registerServerCallback = cb;
    server->registerServerCallbackData = data;
}

#endif // UA_ENABLE_DISCOVERY
