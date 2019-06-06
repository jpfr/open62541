/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2019 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 */

#ifndef UA_SERVER_CONFIG_DEFAULT_H_
#define UA_SERVER_CONFIG_DEFAULT_H_

#include <open62541/server_config.h>

_UA_BEGIN_DECLS

#ifdef UA_ENABLE_CONFIG_PARSER

/**
 * Parse Server Config
 * ------------------- */

/* Parses the server config from TOML definitions. See
 * https://github.com/toml-lang/toml for the format definition and
 * /examples/server/server_config.toml for the recognized configuration options.
 *
 * If the logger of the server configuration is used initially, then this logger
 * is used to report errors of the parser until it is replaced with a new logger
 * definition from the config.
 *
 * @param config The server configuration to which the configuration is written
 * @param toml The null-terminated content of a TOML configuration file
 * @return Returns the success of the parsing operation
 */
UA_EXPORT UA_StatusCode
UA_ServerConfig_parse(UA_ServerConfig *config, const char *toml);

#endif

_UA_END_DECLS

#endif /* UA_SERVER_CONFIG_DEFAULT_H_ */
