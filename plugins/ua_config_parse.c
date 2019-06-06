/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2019 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 */

#include <open62541/server_config_parse.h>
#include "toml.h"

/* Parse Builtin Types */

static UA_StatusCode
parseString(const char *raw, UA_String *target) {
    UA_String_clear(target);
    if(!raw)
        return UA_STATUSCODE_GOOD;
    char *str = NULL;
    if(toml_rtos(raw, &str) == -1)
        return UA_STATUSCODE_BADINTERNALERROR;
    *target = UA_STRING(str);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
parseStringArray(toml_table_t *arr, size_t *arrSize, UA_String **arrData) {
    if(toml_array_kind(arr) != 'v')
        return UA_STATUSCODE_BADINTERNALERROR;
    if(toml_array_type(arr) != 's')
        return UA_STATUSCODE_BADINTERNALERROR;
    int isize = toml_array_nelem(arr);
    if(isize < 0)
        return UA_STATUSCODE_BADINTERNALERROR;
    size_t size = (size_t)isize;
    *arrData = UA_Array_new(size, UA_TYPES[UA_TYPES_STRING]);
    if(!(*arrData))
        return UA_STATUSCODE_BADOUTOFMEMORY;
    *arrSize = size;
    for(int i = 0; i < isize; i++)
        parseString(toml_raw_at(arr, i), &(*arrData)[i]);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
parseLocalizedText(toml_table_t *tt, UA_LocalizedText *target) {
    if(!tt) {
        UA_LocalizedText_clear(target);
        return UA_STATUSCODE_GOOD;
    }
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval |= parseString(toml_raw_in(tt, "Locale"), &target->locale);
    retval |= parseString(toml_raw_in(tt, "Text"), &target->locale);
    return retval;
}

static void
parseApplicationDescription(toml_table_t *tt, UA_ApplicationDescription *ad) {
    UA_ApplicationDescription_clear(ad);

    parseString(toml_raw_in(tt, "ApplicationUri"), &ad->applicationUri);
    parseString(toml_raw_in(tt, "ProductUri"), &ad->productUri);
    parseLocalizedText(toml_table_in(tt, "ApplicationName"), &ad->applicationName);
    // UA_ApplicationType applicationType;
    parseString(toml_raw_in(tt, "GatewayServerUri"), &ad->gatewayServerUri);
    UA_String discoveryProfileUri;
    size_t discoveryUrlsSize;
}

static char errbuf[200];

UA_StatusCode
UA_ServerConfig_parse(UA_ServerConfig *config, const char *toml) {
    toml_table_t* main_table = toml_parse(toml, errbuf, sizeof(errbuf));
    if(!main_table)
        return UA_STATUSCODE_BADINTERNALERROR;

    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Locate the [ApplicationDescription] table */
    toml_table_t *app_descr = toml_table_in(conf, "ApplicationDescription");
    if(app_descr)
        parseApplicationDescription(&config->applicationDescription, app_descr);
    
    toml_free(main_table);
    return UA_STATUSCODE_GOOD;
}
