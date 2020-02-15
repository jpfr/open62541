/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 * Copyright 2020 (c) Kalycito Infotech Private Limited
 *
 */

#include <open62541/plugin/log_stdout.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>
#include <open62541/plugin/nodestore_default.h>

#include <signal.h>
#include <stdlib.h>

static void usage(void) {
    printf("Usage: server [-lookupTable <lookup table file>] \n"
           "              [-encodedBin <encoded binary file>] \n"
           "              [-dump] \n");
}

static volatile UA_Boolean running = true;
static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "received ctrl-c");
    running = false;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    char *lookupTablePath = NULL;
    char *enocdedBinPath = NULL;
    bool dump = false;

    /* Parse the arguments */
    for(int argpos = 1; argpos < argc; argpos++) {
        if(strcmp(argv[argpos], "--help") == 0 ||
           strcmp(argv[argpos], "-h") == 0) {
            usage();
            return EXIT_SUCCESS;
        }

        if(strcmp(argv[argpos], "-lookupTable") == 0) {
            argpos++;
            lookupTablePath = argv[argpos];
            continue;
        }

        if(strcmp(argv[argpos], "-encodedBin") == 0) {
            argpos++;
            enocdedBinPath = argv[argpos];
            continue;
        }

        if(strcmp(argv[argpos], "-dump") == 0) {
            dump = true;
            continue;
        }

        usage();
        return EXIT_FAILURE;
    }

    UA_ServerConfig config;
    memset(&config, 0, sizeof(UA_ServerConfig));
    if(!dump && lookupTablePath && enocdedBinPath)
        UA_Nodestore_BinaryEncoded(&config.nodestore, lookupTablePath, enocdedBinPath);
    UA_ServerConfig_setDefault(&config);
    config.initNS0 = dump; /* only initialize if dumping the nodeset */

    UA_Server *server = NULL;
    server = UA_Server_newWithConfig(&config);
    if(!server) {
        UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                       "Could not create the server");
        return EXIT_FAILURE;
    }

    UA_StatusCode retval;

    if(dump) {
        running = false;
        retval = UA_Server_run(server, &running);
        void *dumpCtx = UA_Nodestore_dumpFileContext_open(lookupTablePath, enocdedBinPath);
        if(dumpCtx) {
            UA_ServerConfig *cc = UA_Server_getConfig(server);
            cc->nodestore.iterate(cc->nodestore.context, UA_Nodestore_dumpNodeCallback, dumpCtx);
            UA_Nodestore_dumpFileContext_close(dumpCtx);
        } else {
            UA_LOG_WARNING(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                           "Could not write the nodestore to files");
            retval |= UA_STATUSCODE_BADINTERNALERROR;
        }
    } else {
        retval = UA_Server_run(server, &running);
    }

    UA_Server_delete(server);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
