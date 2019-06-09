/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information. */

/* A simple example to showcase parsing of the server config from a file */

#include <open62541/server.h>
#include <open62541/server_config_parse.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static volatile UA_Boolean running = true;
static void stopHandler(int sig) {
    printf("received ctrl-c\n");
    running = false;
}

int main(int argc, char **argv) {
    signal(SIGINT, stopHandler);
    signal(SIGTERM, stopHandler);

    if(argc != 2) {
        printf("Usage: server_config_parse <config-file.toml>\n");
        return EXIT_FAILURE;
    }

    /* Open the file */
    FILE *fp = fopen(argv[1], "r");
    if(!fp) {
        printf("Usage: server_config_parse <config-file.toml>\n");
        return EXIT_FAILURE;
    }

    /* Get the file length, allocate the data and read */
    fseek(fp, 0, SEEK_END);
    size_t config_size = (size_t)ftell(fp);
    char *config_data = (char*)UA_malloc(config_size);
    if(!config_data) {
        fclose(fp);
        return EXIT_FAILURE;
    }
    fseek(fp, 0, SEEK_SET);
    size_t read = fread(config_data, sizeof(UA_Byte), config_size, fp);
    fclose(fp);
    if(read != config_size) {
        free(config_data);
        return EXIT_FAILURE;
    }

    /* Create the server */
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_Server *server = UA_Server_new();
    if(!server) {
        retval = UA_STATUSCODE_BADOUTOFMEMORY;
        goto exit;
    }

    /* Parse the config */
    retval = UA_ServerConfig_parse(UA_Server_getConfig(server), config_data);
    if(retval != UA_STATUSCODE_GOOD)
        goto exit;

    /* Run the server */
    retval = UA_Server_run(server, &running);

    /* Cleanup */
 exit:
    if(server)
        UA_Server_delete(server);
    free(config_data);
    return retval == UA_STATUSCODE_GOOD ? EXIT_SUCCESS : EXIT_FAILURE;
}
