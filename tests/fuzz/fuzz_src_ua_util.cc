/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <open62541/util.h>
#include "custom_memory_manager.h"


static int tortureParseEndpointUrl(const uint8_t *data, size_t size) {
    const UA_String endpointUrl = {
        size, (UA_Byte* )(void*)data
    };

    UA_String hostname;
    UA_UInt16 port;
    UA_String path;
    UA_parseEndpointUrl(&endpointUrl, &hostname, &port, &path);
    return 0;
}

static int tortureParseEndpointUrlEthernet(const uint8_t *data, size_t size) {
    const UA_String endpointUrl = {
        size, (UA_Byte* )(void*)data
    };

    UA_String target;
    UA_UInt16 vid;
    UA_Byte prid;
    UA_parseEndpointUrlEthernet(&endpointUrl, &target, &vid, &prid);
    return 0;
}

/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if(size <= 4)
        return 0;

    UA_memoryManager_activate();

    if(!UA_memoryManager_setLimitFromLast4Bytes(data, size)) {
        UA_memoryManager_deactivate();
        return 0;
    }
    size -= 4;

    if(size == 0) {
        UA_memoryManager_deactivate();
        return 0;
    }

    // use first byte to decide which function should be fuzzed

    const uint8_t select = data[0];

    const uint8_t *newData = &data[1];
    size_t  newSize = size-1;

    int retval = 0;
    switch(select) {
        case 0:
            retval = tortureParseEndpointUrl(newData, newSize);
            break;
        case 1:
            retval = tortureParseEndpointUrlEthernet(newData, newSize);
            break;
        default:
            break;
    }

    UA_memoryManager_deactivate();
    return retval;
}
