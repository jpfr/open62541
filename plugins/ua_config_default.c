/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Julian Grothoff
 *    Copyright 2017-2018 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Thomas Stalder, Blue Time Concept SA
 *    Copyright 2018 (c) Daniel Feist, Precitec GmbH & Co. KG
 *    Copyright 2018 (c) Fabian Arndt, Root-Core
 *    Copyright 2019 (c) Kalycito Infotech Private Limited
 *    Copyright 2017-2020 (c) HMS Industrial Networks AB (Author: Jonas Green)
 *    Copyright 2020 (c) Wind River Systems, Inc.
 */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#ifdef UA_ENABLE_WEBSOCKET_SERVER
#include <open62541/network_ws.h>
#endif
#include <open62541/plugin/accesscontrol_default.h>
#include <open62541/plugin/nodestore_default.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/plugin/pki_default.h>
#include <open62541/plugin/securitypolicy_default.h>
#include <open62541/server_config_default.h>

#include <stdio.h> /* For printf */

/* Struct initialization works across ANSI C/C99/C++ if it is done when the
 * variable is first declared. Assigning values to existing structs is
 * heterogeneous across the three. */
static UA_INLINE UA_UInt32Range
UA_UINT32RANGE(UA_UInt32 min, UA_UInt32 max) {
    UA_UInt32Range range = {min, max};
    return range;
}

static UA_INLINE UA_DurationRange
UA_DURATIONRANGE(UA_Duration min, UA_Duration max) {
    UA_DurationRange range = {min, max};
    return range;
}

UA_Server *
UA_Server_new(void) {
    UA_ServerConfig config;
    memset(&config, 0, sizeof(UA_ServerConfig));
    UA_StatusCode res = UA_ServerConfig_setDefault(&config);
    if(res != UA_STATUSCODE_GOOD)
        return NULL;
    return UA_Server_newWithConfig(&config);
}

#if defined(UA_ARCHITECTURE_POSIX) || defined(UA_ARCHITECTURE_WIN32)

/* Required for the definition of SIGINT */
#include <signal.h>

struct InterruptContext {
    UA_Server *server;
    UA_Boolean running;
};

static void
interruptServer(UA_InterruptManager *im, uintptr_t interruptHandle,
                void *context, const UA_KeyValueMap *parameters) {
    struct InterruptContext *ic = (struct InterruptContext*)context;
    UA_ServerConfig *config = UA_Server_getConfig(ic->server);
    UA_LOG_INFO(&config->logger, UA_LOGCATEGORY_USERLAND,
                "Received SIGINT interrupt. Stopping the server.");
    ic->running = false;
}

UA_StatusCode
UA_Server_runUntilInterrupt(UA_Server *server) {
    if(!server)
        return UA_STATUSCODE_BADINTERNALERROR;
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_EventLoop *el = config->eventLoop;
    if(!el)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Get the interrupt manager */
    UA_EventSource *es = el->eventSources;
    while(es) {
        if(es->eventSourceType == UA_EVENTSOURCETYPE_INTERRUPTMANAGER)
            break;
        es = es->next;
    }
    if(!es) {
        UA_LOG_ERROR(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "No Interrupt EventSource configured");
        return UA_STATUSCODE_BADINTERNALERROR;
    }
    UA_InterruptManager *im = (UA_InterruptManager*)es;

    /* Register the interrupt */
    struct InterruptContext ic;
    ic.server = server;
    ic.running = true;
    UA_StatusCode retval =
        im->registerInterrupt(im, SIGINT, &UA_KEYVALUEMAP_NULL,
                              interruptServer, &ic);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(&config->logger, UA_LOGCATEGORY_USERLAND,
                     "Could not register the interrupt with status code %s",
                     UA_StatusCode_name(retval));
        return retval;
    }

    /* Run the server */
    retval = UA_Server_run_startup(server);
    if(retval != UA_STATUSCODE_GOOD)
        goto deregister_interrupt;
    while(ic.running) {
        UA_Server_run_iterate(server, true);
    }

    /* Shut down the server */
    retval = UA_Server_run_shutdown(server);

    /* Deregister the interrupt */
 deregister_interrupt:
    im->deregisterInterrupt(im, SIGINT);
    return retval;
}

#endif /* defined(UA_ARCHITECTURE_POSIX) || defined(UA_ARCHITECTURE_WIN32) */

/*******************************/
/* Default Connection Settings */
/*******************************/

const UA_ConnectionConfig UA_ConnectionConfig_default = {
    0,       /* .protocolVersion */
    2 << 16, /* .sendBufferSize, 64k per chunk */
    2 << 16, /* .recvBufferSize, 64k per chunk */
    2 << 29, /* .localMaxMessageSize, 512 MB */
    2 << 29, /* .remoteMaxMessageSize, 512 MB */
    2 << 14, /* .localMaxChunkCount, 16k */
    2 << 14  /* .remoteMaxChunkCount, 16k */
};

/***************************/
/* Default Server Settings */
/***************************/

#define MANUFACTURER_NAME "open62541"
#define PRODUCT_NAME "open62541 OPC UA Server"
#define PRODUCT_URI "http://open62541.org"
#define APPLICATION_NAME "open62541-based OPC UA Application"
#define APPLICATION_URI "urn:unconfigured:application"
#define APPLICATION_URI_SERVER "urn:open62541.server.application"

#define STRINGIFY(arg) #arg
#define VERSION(MAJOR, MINOR, PATCH, LABEL) \
    STRINGIFY(MAJOR) "." STRINGIFY(MINOR) "." STRINGIFY(PATCH) LABEL

static UA_StatusCode
addEndpoint(UA_ServerConfig *conf,
            const UA_SecurityPolicy *securityPolicy,
            UA_MessageSecurityMode securityMode) {
    /* Test if the endpoint already exists */
    for(size_t i = 0; i < conf->endpointsSize; i++) {
        UA_EndpointDescription *ep = &conf->endpoints[i];
        if(!UA_String_equal(&securityPolicy->policyUri, &ep->securityPolicyUri))
            continue;
        if(ep->securityMode != securityMode)
            continue;
        return UA_STATUSCODE_GOOD;
    }

    /* Reallocate the array size */
    UA_EndpointDescription *tmp = (UA_EndpointDescription *)
        UA_realloc(conf->endpoints,
                   sizeof(UA_EndpointDescription) * (1 + conf->endpointsSize));
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    conf->endpoints = tmp;

    UA_EndpointDescription *endpoint = &conf->endpoints[conf->endpointsSize];
    UA_EndpointDescription_init(endpoint);

    /* Add security level value for the corresponding message security mode */
    endpoint->securityMode = securityMode;
    endpoint->securityLevel = (UA_Byte)securityMode;

    /* Enable all login mechanisms from the access control plugin  */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= UA_Array_copy(conf->accessControl.userTokenPolicies,
                            conf->accessControl.userTokenPoliciesSize,
                            (void **)&endpoint->userIdentityTokens,
                            &UA_TYPES[UA_TYPES_USERTOKENPOLICY]);
    if(retval == UA_STATUSCODE_GOOD)
        endpoint->userIdentityTokensSize = conf->accessControl.userTokenPoliciesSize;

    retval |= UA_String_copy(&securityPolicy->policyUri, &endpoint->securityPolicyUri);
    endpoint->transportProfileUri =
        UA_STRING_ALLOC("http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary");
    retval |= UA_String_copy(&securityPolicy->localCertificate,
                             &endpoint->serverCertificate);
    retval |= UA_ApplicationDescription_copy(&conf->applicationDescription,
                                             &endpoint->server);

    if(retval == UA_STATUSCODE_GOOD) {
        conf->endpointsSize++;
    } else {
        UA_EndpointDescription_clear(endpoint);
        if(conf->endpointsSize == 0) {
            UA_free(conf->endpoints);
            conf->endpoints = NULL;
        }
    }

    return retval;
}

static const size_t usernamePasswordsSize = 2;
static UA_UsernamePasswordLogin usernamePasswords[2] = {
    {UA_STRING_STATIC("user1"), UA_STRING_STATIC("password")},
    {UA_STRING_STATIC("user2"), UA_STRING_STATIC("password1")}};

static UA_StatusCode
setDefaultConfig(UA_ServerConfig *conf, UA_UInt16 portNumber) {
    if(!conf)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* NodeStore */
    if(conf->nodestore.context == NULL)
        UA_Nodestore_HashMap(&conf->nodestore);

    /* Logging */
    if(!conf->logger.log)
        conf->logger = UA_Log_Stdout_withLevel(UA_LOGLEVEL_TRACE);
    if(conf->logging == NULL)
        conf->logging = &conf->logger;

    /* EventLoop */
    if(conf->eventLoop == NULL) {
        conf->eventLoop = UA_EventLoop_new_POSIX(&conf->logger);
        if(conf->eventLoop == NULL) {
           return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        conf->externalEventLoop = false;

        /* Add the TCP connection manager */
        UA_ConnectionManager *tcpCM =
            UA_ConnectionManager_new_POSIX_TCP(UA_STRING("tcp connection manager"));
        if(tcpCM)
            conf->eventLoop->registerEventSource(conf->eventLoop, (UA_EventSource *)tcpCM);

        /* Add the UDP connection manager */
        UA_ConnectionManager *udpCM =
            UA_ConnectionManager_new_POSIX_UDP(UA_STRING("udp connection manager"));
        if(udpCM)
            conf->eventLoop->registerEventSource(conf->eventLoop, (UA_EventSource *)udpCM);

        /* Add the Ethernet connection manager */
#ifdef __linux__
        UA_ConnectionManager *ethCM =
            UA_ConnectionManager_new_POSIX_Ethernet(UA_STRING("eth connection manager"));
        if(ethCM)
            conf->eventLoop->registerEventSource(conf->eventLoop, (UA_EventSource *)ethCM);
#endif

        /* Add the interrupt manager */
        UA_InterruptManager *im = UA_InterruptManager_new_POSIX(UA_STRING("interrupt manager"));
        if(im) {
            conf->eventLoop->registerEventSource(conf->eventLoop, &im->eventSource);
        } else {
            UA_LOG_WARNING(&conf->logger, UA_LOGCATEGORY_USERLAND,
                           "Cannot create the Interrupt Manager (only relevant if used)");
        }
#ifdef UA_ENABLE_MQTT
        /* Add the MQTT connection manager */
        UA_ConnectionManager *mqttCM =
            UA_ConnectionManager_new_MQTT(UA_STRING("mqtt connection manager"));
        if(mqttCM)
            conf->eventLoop->registerEventSource(conf->eventLoop, (UA_EventSource *)mqttCM);
#endif
    }
    if(conf->eventLoop != NULL) {
        if(conf->eventLoop->state != UA_EVENTLOOPSTATE_STARTED) {
            UA_StatusCode statusCode = conf->eventLoop->start(conf->eventLoop);
            if(statusCode != UA_STATUSCODE_GOOD) {
                return statusCode;
            }
        }
    }

    /* --> Start setting the default static config <-- */

    conf->shutdownDelay = 0.0;

    /* Server Description */
    UA_BuildInfo_clear(&conf->buildInfo);
    conf->buildInfo.productUri = UA_STRING_ALLOC(PRODUCT_URI);
    conf->buildInfo.manufacturerName = UA_STRING_ALLOC(MANUFACTURER_NAME);
    conf->buildInfo.productName = UA_STRING_ALLOC(PRODUCT_NAME);
    conf->buildInfo.softwareVersion =
        UA_STRING_ALLOC(VERSION(UA_OPEN62541_VER_MAJOR, UA_OPEN62541_VER_MINOR,
                                UA_OPEN62541_VER_PATCH, UA_OPEN62541_VER_LABEL));
#ifdef UA_PACK_DEBIAN
    conf->buildInfo.buildNumber = UA_STRING_ALLOC("deb");
#else
    conf->buildInfo.buildNumber = UA_STRING_ALLOC(__DATE__ " " __TIME__);
#endif
    conf->buildInfo.buildDate = UA_DateTime_now();

    UA_ApplicationDescription_clear(&conf->applicationDescription);
    conf->applicationDescription.applicationUri = UA_STRING_ALLOC(APPLICATION_URI_SERVER);
    conf->applicationDescription.productUri = UA_STRING_ALLOC(PRODUCT_URI);
    conf->applicationDescription.applicationName =
        UA_LOCALIZEDTEXT_ALLOC("en", APPLICATION_NAME);
    conf->applicationDescription.applicationType = UA_APPLICATIONTYPE_SERVER;
    /* conf->applicationDescription.gatewayServerUri = UA_STRING_NULL; */
    /* conf->applicationDescription.discoveryProfileUri = UA_STRING_NULL; */
    /* conf->applicationDescription.discoveryUrlsSize = 0; */
    /* conf->applicationDescription.discoveryUrls = NULL; */

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
    UA_MdnsDiscoveryConfiguration_clear(&conf->mdnsConfig);
    conf->mdnsInterfaceIP = UA_STRING_NULL;
# if !defined(UA_HAS_GETIFADDR)
    conf->mdnsIpAddressList = NULL;
    conf->mdnsIpAddressListSize = 0;
# endif
#endif

    /* Custom DataTypes */
    /* conf->customDataTypesSize = 0; */
    /* conf->customDataTypes = NULL; */

    /* Networking */
    /* Set up the local ServerUrls. They are used during startup to initialize
     * the server sockets. */
    UA_String serverUrls[2];
    size_t serverUrlsSize = 0;
    char hostnamestr[256];
    char serverUrlBuffer[2][512];

    if(portNumber == 0) {
        UA_LOG_WARNING(&conf->logger, UA_LOGCATEGORY_USERLAND,
                       "Cannot set the ServerUrl with a zero port");
    } else {
        if(conf->serverUrlsSize > 0) {
            UA_LOG_WARNING(&conf->logger, UA_LOGCATEGORY_USERLAND,
                           "ServerUrls already set. Overriding.");
            UA_Array_delete(conf->serverUrls, conf->serverUrlsSize,
                            &UA_TYPES[UA_TYPES_STRING]);
            conf->serverUrls = NULL;
            conf->serverUrlsSize = 0;
        }

        /* 1) Listen on all interfaces (also external). This must be the first
         * entry if this is desired. Otherwise some interfaces may be blocked
         * (already in use) with a hostname that is only locally reachable.*/
        snprintf(serverUrlBuffer[0], sizeof(serverUrlBuffer[0]),
                 "opc.tcp://:%u", portNumber);
        serverUrls[serverUrlsSize] = UA_STRING(serverUrlBuffer[0]);
        serverUrlsSize++;

        /* 2) Use gethostname to get the local hostname. For that temporarily
         * initialize the Winsock API on Win32. */
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
        int err = gethostname(hostnamestr, sizeof(hostnamestr));
#ifdef _WIN32
        WSACleanup();
#endif

        if(err == 0) {
            snprintf(serverUrlBuffer[1], sizeof(serverUrlBuffer[1]),
                     "opc.tcp://%s:%u", hostnamestr, portNumber);
            serverUrls[serverUrlsSize] = UA_STRING(serverUrlBuffer[1]);
            serverUrlsSize++;
        }

        /* 3) Add to the config */
        UA_StatusCode retval =
            UA_Array_copy(serverUrls, serverUrlsSize,
                          (void**)&conf->serverUrls, &UA_TYPES[UA_TYPES_STRING]);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
        conf->serverUrlsSize = serverUrlsSize;
    }

    /* Endpoints */
    /* conf->endpoints = {0, NULL}; */

    if(!conf->certificateVerification.logging) {
        /* Set Logger for Certificate Verification */
        conf->certificateVerification.logging = &conf->logging;
   }

    /* Certificate Verification that accepts every certificate. Can be
     * overwritten when the policy is specialized. */
    UA_CertificateVerification_AcceptAll(&conf->certificateVerification);

    /* * Global Node Lifecycle * */
    /* conf->nodeLifecycle.constructor = NULL; */
    /* conf->nodeLifecycle.destructor = NULL; */
    /* conf->nodeLifecycle.createOptionalChild = NULL; */
    /* conf->nodeLifecycle.generateChildNodeId = NULL; */
    conf->modellingRulesOnInstances = true;

    /* Limits for SecureChannels */
    conf->maxSecureChannels = 40;
    conf->maxSecurityTokenLifetime = 10 * 60 * 1000; /* 10 minutes */

    /* Limits for Sessions */
    conf->maxSessions = 100;
    conf->maxSessionTimeout = 60.0 * 60.0 * 1000.0; /* 1h */

#ifdef UA_ENABLE_SUBSCRIPTIONS
    /* Limits for Subscriptions */
    conf->publishingIntervalLimits = UA_DURATIONRANGE(100.0, 3600.0 * 1000.0);
    conf->lifeTimeCountLimits = UA_UINT32RANGE(3, 15000);
    conf->keepAliveCountLimits = UA_UINT32RANGE(1, 100);
    conf->maxNotificationsPerPublish = 1000;
    conf->enableRetransmissionQueue = true;
    conf->maxRetransmissionQueueSize = 0; /* unlimited */
# ifdef UA_ENABLE_SUBSCRIPTIONS_EVENTS
    conf->maxEventsPerNode = 0; /* unlimited */
# endif

    /* Limits for MonitoredItems */
    conf->samplingIntervalLimits = UA_DURATIONRANGE(50.0, 24.0 * 3600.0 * 1000.0);
    conf->queueSizeLimits = UA_UINT32RANGE(1, 100);
#endif

#ifdef UA_ENABLE_DISCOVERY
    conf->discoveryCleanupTimeout = 60 * 60;
#endif

#ifdef UA_ENABLE_HISTORIZING
    /* conf->accessHistoryDataCapability = false; */
    /* conf->maxReturnDataValues = 0; */

    /* conf->accessHistoryEventsCapability = false; */
    /* conf->maxReturnEventValues = 0; */

    /* conf->insertDataCapability = false; */
    /* conf->insertEventCapability = false; */
    /* conf->insertAnnotationsCapability = false; */

    /* conf->replaceDataCapability = false; */
    /* conf->replaceEventCapability = false; */

    /* conf->updateDataCapability = false; */
    /* conf->updateEventCapability = false; */

    /* conf->deleteRawCapability = false; */
    /* conf->deleteEventCapability = false; */
    /* conf->deleteAtTimeDataCapability = false; */
#endif

#if UA_MULTITHREADING >= 100
    conf->maxAsyncOperationQueueSize = 0;
    conf->asyncOperationTimeout = 120000; /* Async Operation Timeout in ms (2 minutes) */
#endif

    /* --> Finish setting the default static config <-- */

    return UA_STATUSCODE_GOOD;
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_setBasics(UA_ServerConfig* conf) {
    return UA_ServerConfig_setBasics_withPort(conf, 4840);
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_setBasics_withPort(UA_ServerConfig* conf, UA_UInt16 portNumber) {
    UA_StatusCode res = setDefaultConfig(conf, portNumber);
    UA_LOG_WARNING(&conf->logger, UA_LOGCATEGORY_USERLAND,
                   "AcceptAll Certificate Verification. "
                   "Any remote certificate will be accepted.");
    return res;
}

#ifdef UA_ENABLE_WEBSOCKET_SERVER
UA_EXPORT UA_StatusCode
UA_ServerConfig_addNetworkLayerWS(UA_ServerConfig *conf, UA_UInt16 portNumber,
                                   UA_UInt32 sendBufferSize, UA_UInt32 recvBufferSize, const UA_ByteString* certificate, const UA_ByteString* privateKey) {
    /* Add a network layer */
    UA_ServerNetworkLayer *tmp = (UA_ServerNetworkLayer *)
        UA_realloc(conf->networkLayers,
                   sizeof(UA_ServerNetworkLayer) * (1 + conf->networkLayersSize));
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    conf->networkLayers = tmp;

    UA_ConnectionConfig config = UA_ConnectionConfig_default;
    if(sendBufferSize > 0)
        config.sendBufferSize = sendBufferSize;
    if(recvBufferSize > 0)
        config.recvBufferSize = recvBufferSize;

    conf->networkLayers[conf->networkLayersSize] =
        UA_ServerNetworkLayerWS(config, portNumber, certificate, privateKey);
    if(!conf->networkLayers[conf->networkLayersSize].handle)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    conf->networkLayersSize++;

    return UA_STATUSCODE_GOOD;
}
#endif

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyNone(UA_ServerConfig *config,
                                      const UA_ByteString *certificate) {
    /* Allocate the SecurityPolicies */
    UA_SecurityPolicy *tmp = (UA_SecurityPolicy *)
        UA_realloc(config->securityPolicies,
                   sizeof(UA_SecurityPolicy) * (1 + config->securityPoliciesSize));
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    config->securityPolicies = tmp;

    /* Populate the SecurityPolicies */
    UA_ByteString localCertificate = UA_BYTESTRING_NULL;
    if(certificate)
        localCertificate = *certificate;
    UA_StatusCode retval =
        UA_SecurityPolicy_None(&config->securityPolicies[config->securityPoliciesSize],
                               localCertificate, &config->logger);
    if(retval != UA_STATUSCODE_GOOD) {
        if(config->securityPoliciesSize == 0) {
            UA_free(config->securityPolicies);
            config->securityPolicies = NULL;
        }
        return retval;
    }

    config->securityPoliciesSize++;
    return UA_STATUSCODE_GOOD;
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_addEndpoint(UA_ServerConfig *config, const UA_String securityPolicyUri,
                            UA_MessageSecurityMode securityMode) {
    /* Lookup the security policy */
    const UA_SecurityPolicy *policy = NULL;
    for (size_t i = 0; i < config->securityPoliciesSize; ++i) {
        if (UA_String_equal(&securityPolicyUri, &config->securityPolicies[i].policyUri)) {
            policy = &config->securityPolicies[i];
            break;
        }
    }
    if(!policy)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* Populate the endpoint */
    return addEndpoint(config, policy, securityMode);
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_addAllEndpoints(UA_ServerConfig *config) {
    /* Populate the endpoints */
    for(size_t i = 0; i < config->securityPoliciesSize; ++i) {
        if(UA_String_equal(&UA_SECURITY_POLICY_NONE_URI, &config->securityPolicies[i].policyUri)) {
            UA_StatusCode retval =
                addEndpoint(config, &config->securityPolicies[i], UA_MESSAGESECURITYMODE_NONE);
            if(retval != UA_STATUSCODE_GOOD)
                return retval;
        } else {
            UA_StatusCode retval =
                addEndpoint(config, &config->securityPolicies[i], UA_MESSAGESECURITYMODE_SIGN);
            if(retval != UA_STATUSCODE_GOOD)
                return retval;
            retval = addEndpoint(config, &config->securityPolicies[i],
                                 UA_MESSAGESECURITYMODE_SIGNANDENCRYPT);
            if(retval != UA_STATUSCODE_GOOD)
                return retval;
        }
    }

    return UA_STATUSCODE_GOOD;
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_setMinimalCustomBuffer(UA_ServerConfig *config, UA_UInt16 portNumber,
                                       const UA_ByteString *certificate,
                                       UA_UInt32 sendBufferSize,
                                       UA_UInt32 recvBufferSize) {
    if(!config)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_StatusCode retval = setDefaultConfig(config, portNumber);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clean(config);
        return retval;
    }

    /* Set the TCP settings */
    config->tcpBufSize = recvBufferSize;

    /* Allocate the SecurityPolicies */
    retval = UA_ServerConfig_addSecurityPolicyNone(config, certificate);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clean(config);
        return retval;
    }

    /* Initialize the Access Control plugin */
    retval = UA_AccessControl_default(config, true, NULL,
                                      &config->securityPolicies[config->securityPoliciesSize-1].policyUri,
                                      usernamePasswordsSize, usernamePasswords);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clean(config);
        return retval;
    }

    /* Allocate the endpoint */
    retval = UA_ServerConfig_addEndpoint(config, UA_SECURITY_POLICY_NONE_URI,
                                         UA_MESSAGESECURITYMODE_NONE);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clean(config);
        return retval;
    }

    UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                   "AcceptAll Certificate Verification. "
                   "Any remote certificate will be accepted.");

    return UA_STATUSCODE_GOOD;
}

#ifdef UA_ENABLE_ENCRYPTION

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyBasic128Rsa15(UA_ServerConfig *config,
                                               const UA_ByteString *certificate,
                                               const UA_ByteString *privateKey) {
    /* Allocate the SecurityPolicies */
    UA_SecurityPolicy *tmp = (UA_SecurityPolicy *)
        UA_realloc(config->securityPolicies,
                   sizeof(UA_SecurityPolicy) * (1 + config->securityPoliciesSize));
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    config->securityPolicies = tmp;

    /* Populate the SecurityPolicies */
    UA_ByteString localCertificate = UA_BYTESTRING_NULL;
    UA_ByteString localPrivateKey  = UA_BYTESTRING_NULL;
    if(certificate)
        localCertificate = *certificate;
    if(privateKey)
       localPrivateKey = *privateKey;
    UA_StatusCode retval =
        UA_SecurityPolicy_Basic128Rsa15(&config->securityPolicies[config->securityPoliciesSize],
                                        localCertificate, localPrivateKey, &config->logger);
    if(retval != UA_STATUSCODE_GOOD) {
        if(config->securityPoliciesSize == 0) {
            UA_free(config->securityPolicies);
            config->securityPolicies = NULL;
        }
        return retval;
    }

    config->securityPoliciesSize++;
    return UA_STATUSCODE_GOOD;
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyBasic256(UA_ServerConfig *config,
                                          const UA_ByteString *certificate,
                                          const UA_ByteString *privateKey) {
    /* Allocate the SecurityPolicies */
    UA_SecurityPolicy *tmp = (UA_SecurityPolicy *)
        UA_realloc(config->securityPolicies,
                   sizeof(UA_SecurityPolicy) * (1 + config->securityPoliciesSize));
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    config->securityPolicies = tmp;

    /* Populate the SecurityPolicies */
    UA_ByteString localCertificate = UA_BYTESTRING_NULL;
    UA_ByteString localPrivateKey  = UA_BYTESTRING_NULL;
    if(certificate)
        localCertificate = *certificate;
    if(privateKey)
       localPrivateKey = *privateKey;
    UA_StatusCode retval =
        UA_SecurityPolicy_Basic256(&config->securityPolicies[config->securityPoliciesSize],
                                   localCertificate, localPrivateKey, &config->logger);
    if(retval != UA_STATUSCODE_GOOD) {
        if(config->securityPoliciesSize == 0) {
            UA_free(config->securityPolicies);
            config->securityPolicies = NULL;
        }
        return retval;
    }

    config->securityPoliciesSize++;
    return UA_STATUSCODE_GOOD;
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyBasic256Sha256(UA_ServerConfig *config,
                                                const UA_ByteString *certificate,
                                                const UA_ByteString *privateKey) {
    /* Allocate the SecurityPolicies */
    UA_SecurityPolicy *tmp = (UA_SecurityPolicy *)
        UA_realloc(config->securityPolicies,
                   sizeof(UA_SecurityPolicy) * (1 + config->securityPoliciesSize));
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    config->securityPolicies = tmp;

    /* Populate the SecurityPolicies */
    UA_ByteString localCertificate = UA_BYTESTRING_NULL;
    UA_ByteString localPrivateKey  = UA_BYTESTRING_NULL;
    if(certificate)
        localCertificate = *certificate;
    if(privateKey)
       localPrivateKey = *privateKey;
    UA_StatusCode retval =
        UA_SecurityPolicy_Basic256Sha256(&config->securityPolicies[config->securityPoliciesSize],
                                         localCertificate, localPrivateKey, &config->logger);
    if(retval != UA_STATUSCODE_GOOD) {
        if(config->securityPoliciesSize == 0) {
            UA_free(config->securityPolicies);
            config->securityPolicies = NULL;
        }
        return retval;
    }

    config->securityPoliciesSize++;
    return UA_STATUSCODE_GOOD;
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_addSecurityPolicyAes128Sha256RsaOaep(UA_ServerConfig *config,
                                                const UA_ByteString *certificate,
                                                const UA_ByteString *privateKey) {
    /* Allocate the SecurityPolicies */
    UA_SecurityPolicy *tmp = (UA_SecurityPolicy *)
        UA_realloc(config->securityPolicies,
                   sizeof(UA_SecurityPolicy) * (1 + config->securityPoliciesSize));
    if(!tmp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    config->securityPolicies = tmp;

    /* Populate the SecurityPolicies */
    UA_ByteString localCertificate = UA_BYTESTRING_NULL;
    UA_ByteString localPrivateKey  = UA_BYTESTRING_NULL;
    if(certificate)
        localCertificate = *certificate;
    if(privateKey)
       localPrivateKey = *privateKey;
    UA_StatusCode retval =
        UA_SecurityPolicy_Aes128Sha256RsaOaep(&config->securityPolicies[config->securityPoliciesSize],
                                              localCertificate, localPrivateKey, &config->logger);
    if(retval != UA_STATUSCODE_GOOD) {
        if(config->securityPoliciesSize == 0) {
            UA_free(config->securityPolicies);
            config->securityPolicies = NULL;
        }
        return retval;
    }

    config->securityPoliciesSize++;
    return UA_STATUSCODE_GOOD;
}

/* Always returns UA_STATUSCODE_GOOD. Logs a warning if policies could not be added. */
UA_EXPORT UA_StatusCode
UA_ServerConfig_addAllSecurityPolicies(UA_ServerConfig *config,
                                       const UA_ByteString *certificate,
                                       const UA_ByteString *privateKey) {
    /* Populate the SecurityPolicies */
    UA_ByteString localCertificate = UA_BYTESTRING_NULL;
    UA_ByteString localPrivateKey  = UA_BYTESTRING_NULL;
    if(certificate)
        localCertificate = *certificate;
    if(privateKey)
       localPrivateKey = *privateKey;

    UA_StatusCode retval = UA_ServerConfig_addSecurityPolicyNone(config, &localCertificate);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#None with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_ServerConfig_addSecurityPolicyBasic128Rsa15(config, &localCertificate, &localPrivateKey);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic128Rsa15 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_ServerConfig_addSecurityPolicyBasic256(config, &localCertificate, &localPrivateKey);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic256 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_ServerConfig_addSecurityPolicyBasic256Sha256(config, &localCertificate, &localPrivateKey);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic256Sha256 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_ServerConfig_addSecurityPolicyAes128Sha256RsaOaep(config, &localCertificate, &localPrivateKey);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Aes128Sha256RsaOaep with error code %s",
                       UA_StatusCode_name(retval));
    }

    return UA_STATUSCODE_GOOD;
}

UA_EXPORT UA_StatusCode
UA_ServerConfig_setDefaultWithSecurityPolicies(UA_ServerConfig *conf,
                                               UA_UInt16 portNumber,
                                               const UA_ByteString *certificate,
                                               const UA_ByteString *privateKey,
                                               const UA_ByteString *trustList,
                                               size_t trustListSize,
                                               const UA_ByteString *issuerList,
                                               size_t issuerListSize,
                                               const UA_ByteString *revocationList,
                                               size_t revocationListSize) {
    UA_StatusCode retval = setDefaultConfig(conf, portNumber);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clean(conf);
        return retval;
    }

    retval = UA_CertificateVerification_Trustlist(&conf->certificateVerification,
                                                  trustList, trustListSize,
                                                  issuerList, issuerListSize,
                                                  revocationList, revocationListSize);
    if (retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_ServerConfig_addAllSecurityPolicies(conf, certificate, privateKey);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clean(conf);
        return retval;
    }

    UA_CertificateVerification accessControlVerification;
    memset(&accessControlVerification, 0, sizeof(accessControlVerification));
    accessControlVerification.logging = &conf->logging;
    retval = UA_CertificateVerification_Trustlist(&accessControlVerification,
                                                  trustList, trustListSize,
                                                  issuerList, issuerListSize,
                                                  revocationList, revocationListSize);
    if(retval == UA_STATUSCODE_GOOD) {
        retval = UA_AccessControl_default(conf, true, &accessControlVerification,
                    &conf->securityPolicies[conf->securityPoliciesSize-1].policyUri,
                    usernamePasswordsSize, usernamePasswords);
    }
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clean(conf);
        return retval;
    }

    retval = UA_ServerConfig_addAllEndpoints(conf);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ServerConfig_clean(conf);
        return retval;
    }

    return UA_STATUSCODE_GOOD;
}

#endif

/***************************/
/* Default Client Settings */
/***************************/

UA_Client * UA_Client_new(void) {
    UA_ClientConfig config;
    memset(&config, 0, sizeof(UA_ClientConfig));
    /* Set up basic usable config including logger and event loop */
    UA_StatusCode res = UA_ClientConfig_setDefault(&config);
    if(res != UA_STATUSCODE_GOOD)
        return NULL;
    return UA_Client_newWithConfig(&config);
}

UA_StatusCode
UA_ClientConfig_setDefault(UA_ClientConfig *config) {
    /* The following fields are untouched and OK to leave as NULL or 0:
     *  clientContext
     *  userIdentityToken
     *  securityMode
     *  securityPolicyUri
     *  endpoint
     *  userTokenPolicy
     *  customDataTypes
     *  connectivityCheckInterval
     *  stateCallback
     *  inactivityCallback
     *  outStandingPublishRequests
     *  subscriptionInactivityCallback
     *  sessionLocaleIds
     *  sessionLocaleIdsSize */

    if(config->timeout == 0)
        config->timeout = 5 * 1000; /* 5 seconds */
    if(config->secureChannelLifeTime == 0)
        config->secureChannelLifeTime = 10 * 60 * 1000; /* 10 minutes */

    if(!config->logger.log) {
        config->logger = UA_Log_Stdout_withLevel(UA_LOGLEVEL_INFO);
    }
    if(config->logging == NULL)
        config->logging = &config->logger;

    /* EventLoop */
    if(config->eventLoop == NULL) {
        config->eventLoop = UA_EventLoop_new_POSIX(&config->logger);
        config->externalEventLoop = false;

        /* Add the TCP connection manager */
        UA_ConnectionManager *tcpCM =
            UA_ConnectionManager_new_POSIX_TCP(UA_STRING("tcp connection manager"));
        config->eventLoop->registerEventSource(config->eventLoop, (UA_EventSource *)tcpCM);

        /* Add the UDP connection manager */
        UA_ConnectionManager *udpCM =
            UA_ConnectionManager_new_POSIX_UDP(UA_STRING("udp connection manager"));
        config->eventLoop->registerEventSource(config->eventLoop, (UA_EventSource *)udpCM);
    }

    if(config->localConnectionConfig.recvBufferSize == 0)
        config->localConnectionConfig = UA_ConnectionConfig_default;

    if(!config->certificateVerification.logging) {
        /* Set Logger for Certificate Verification */
        config->certificateVerification.logging = &config->logging;
    }

    if(!config->certificateVerification.verifyCertificate) {
        /* Certificate Verification that accepts every certificate. Can be
         * overwritten when the policy is specialized. */
        UA_CertificateVerification_AcceptAll(&config->certificateVerification);
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "AcceptAll Certificate Verification. "
                       "Any remote certificate will be accepted.");
    }

    /* With encryption enabled, the applicationUri needs to match the URI from
     * the certificate */
    if(!config->clientDescription.applicationUri.data)
        config->clientDescription.applicationUri = UA_STRING_ALLOC(APPLICATION_URI);
    if(config->clientDescription.applicationType == 0)
        config->clientDescription.applicationType = UA_APPLICATIONTYPE_CLIENT;

    if(config->securityPoliciesSize == 0) {
        config->securityPolicies = (UA_SecurityPolicy*)UA_malloc(sizeof(UA_SecurityPolicy));
        if(!config->securityPolicies)
            return UA_STATUSCODE_BADOUTOFMEMORY;
        UA_StatusCode retval = UA_SecurityPolicy_None(config->securityPolicies,
                                                      UA_BYTESTRING_NULL, &config->logger);
        if(retval != UA_STATUSCODE_GOOD) {
            UA_free(config->securityPolicies);
            config->securityPolicies = NULL;
            return retval;
        }
        config->securityPoliciesSize = 1;
    }

    if(config->requestedSessionTimeout == 0)
        config->requestedSessionTimeout = 1200000;

#ifdef UA_ENABLE_SUBSCRIPTIONS
    if(config->outStandingPublishRequests == 0)
        config->outStandingPublishRequests = 10;
#endif

    return UA_STATUSCODE_GOOD;
}

#ifdef UA_ENABLE_ENCRYPTION
UA_StatusCode
UA_ClientConfig_setDefaultEncryption(UA_ClientConfig *config,
                                     UA_ByteString localCertificate, UA_ByteString privateKey,
                                     const UA_ByteString *trustList, size_t trustListSize,
                                     const UA_ByteString *revocationList, size_t revocationListSize) {
    UA_StatusCode retval = UA_ClientConfig_setDefault(config);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_CertificateVerification_Trustlist(&config->certificateVerification,
                                                  trustList, trustListSize,
                                                  NULL, 0,
                                                  revocationList, revocationListSize);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Populate SecurityPolicies */
    UA_SecurityPolicy *sp = (UA_SecurityPolicy*)
        UA_realloc(config->securityPolicies, sizeof(UA_SecurityPolicy) * 5);
    if(!sp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    config->securityPolicies = sp;

    retval = UA_SecurityPolicy_Basic128Rsa15(&config->securityPolicies[config->securityPoliciesSize],
                                             localCertificate, privateKey, &config->logger);
    if(retval == UA_STATUSCODE_GOOD) {
        ++config->securityPoliciesSize;
    } else {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic128Rsa15 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_SecurityPolicy_Basic256(&config->securityPolicies[config->securityPoliciesSize],
                                        localCertificate, privateKey, &config->logger);
    if(retval == UA_STATUSCODE_GOOD) {
        ++config->securityPoliciesSize;
    } else {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic256 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_SecurityPolicy_Basic256Sha256(&config->securityPolicies[config->securityPoliciesSize],
                                              localCertificate, privateKey, &config->logger);
    if(retval == UA_STATUSCODE_GOOD) {
        ++config->securityPoliciesSize;
    } else {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic256Sha256 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_SecurityPolicy_Aes128Sha256RsaOaep(&config->securityPolicies[config->securityPoliciesSize],
                                                   localCertificate, privateKey, &config->logger);
    if(retval == UA_STATUSCODE_GOOD) {
        ++config->securityPoliciesSize;
    } else {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Aes128Sha256RsaOaep with error code %s",
                       UA_StatusCode_name(retval));
    }

    if(config->securityPoliciesSize == 0) {
        UA_free(config->securityPolicies);
        config->securityPolicies = NULL;
    }

    return UA_STATUSCODE_GOOD;
}
#endif

#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) || defined(UA_ENABLE_ENCRYPTION_MBEDTLS)
UA_StatusCode
UA_ClientConfig_setAuthenticationCert(UA_ClientConfig *config,
                                   UA_ByteString certificateAuth, UA_ByteString privateKeyAuth) {
#ifdef UA_ENABLE_ENCRYPTION_LIBRESSL
    UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                   "Certificate authentication with LibreSSL as crypto backend is not supported.");
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
#endif
    /* Create UserIdentityToken */
    UA_X509IdentityToken* identityToken = UA_X509IdentityToken_new();
    if(!identityToken)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    identityToken->policyId = UA_STRING_ALLOC("open62541-certificate-policy");
    UA_StatusCode retval = UA_ByteString_copy(&certificateAuth, &identityToken->certificateData);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    UA_ExtensionObject_clear(&config->userIdentityToken);
    config->userIdentityToken.encoding = UA_EXTENSIONOBJECT_DECODED;
    config->userIdentityToken.content.decoded.type = &UA_TYPES[UA_TYPES_X509IDENTITYTOKEN];
    config->userIdentityToken.content.decoded.data = identityToken;

    /* Populate SecurityPolicies */
    UA_SecurityPolicy *sp = (UA_SecurityPolicy*)
        UA_realloc(config->authSecurityPolicies, sizeof(UA_SecurityPolicy) * 5);
    if(!sp)
        return UA_STATUSCODE_BADOUTOFMEMORY;
    config->authSecurityPolicies = sp;

    retval = UA_SecurityPolicy_Basic128Rsa15(&config->authSecurityPolicies[config->authSecurityPoliciesSize],
                                                           certificateAuth, privateKeyAuth, &config->logger);
    if(retval == UA_STATUSCODE_GOOD) {
        ++config->authSecurityPoliciesSize;
    } else {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic128Rsa15 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_SecurityPolicy_Basic256(&config->authSecurityPolicies[config->authSecurityPoliciesSize],
                                        certificateAuth, privateKeyAuth, &config->logger);
    if(retval == UA_STATUSCODE_GOOD) {
        ++config->authSecurityPoliciesSize;
    } else {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic256 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_SecurityPolicy_Basic256Sha256(&config->authSecurityPolicies[config->authSecurityPoliciesSize],
                                              certificateAuth, privateKeyAuth, &config->logger);
    if(retval == UA_STATUSCODE_GOOD) {
        ++config->authSecurityPoliciesSize;
    } else {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Basic256Sha256 with error code %s",
                       UA_StatusCode_name(retval));
    }

    retval = UA_SecurityPolicy_Aes128Sha256RsaOaep(&config->authSecurityPolicies[config->authSecurityPoliciesSize],
                                                   certificateAuth, privateKeyAuth, &config->logger);
    if(retval == UA_STATUSCODE_GOOD) {
        ++config->authSecurityPoliciesSize;
    } else {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_USERLAND,
                       "Could not add SecurityPolicy#Aes128Sha256RsaOaep with error code %s",
                       UA_StatusCode_name(retval));
    }

    if(config->authSecurityPoliciesSize == 0) {
        UA_free(config->authSecurityPolicies);
        config->authSecurityPolicies = NULL;
    }
    return UA_STATUSCODE_GOOD;
}
#endif
