/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef UA_NODESTORE_DEFAULTH_
#define UA_NODESTORE_DEFAULTH_

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_plugin_nodestore.h"

/* Initializes the nodestore, sets the context and function pointers */
UA_StatusCode UA_Nodestore_default_new(UA_Nodestore *ns);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* UA_NODESTORE_DEFAULT_H_ */
