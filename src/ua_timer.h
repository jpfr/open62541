/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef UA_TIMER_H_
#define UA_TIMER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_util.h"

/* Three pointers are passed into callbacks:
 * - application (server / client)
 * - context (connection, session, ...)
 * - data (anything else) */
typedef struct {
    void (*callback)(void *application, void *context, void *data);
    void *context;
    void *data;
} UA_Callback;

typedef void
(*UA_RepeatedCallbacksListProcessCallback)(void *application, UA_Callback *callback);

struct UA_RepeatedCallback;
typedef struct UA_RepeatedCallback UA_RepeatedCallback;

typedef struct {
    /* The linked list of callbacks is sorted according to the execution timestamp. */
    SLIST_HEAD(RepeatedCallbacksSList, UA_RepeatedCallback) repeatedCallbacks;

    /* Changes to the repeated callbacks in a multi-producer single-consumer queue */
    UA_RepeatedCallback * volatile changes_head;
    UA_RepeatedCallback *changes_tail;
    UA_RepeatedCallback *changes_stub;

    UA_UInt64 identiferCounter;
} UA_RepeatedCallbacksList;

/* Initialize the RepeatedCallbacksSList. Not thread-safe. */
void UA_RepeatedCallbacksList_init(UA_RepeatedCallbacksList *rcl);

/* Add a repated callback. Thread-safe, can be used in parallel and in parallel
 * with UA_RepeatedCallbacksList_process. */
UA_StatusCode
UA_RepeatedCallbacksList_addRepeatedCallback(UA_RepeatedCallbacksList *rcl,
                                             const UA_Callback callback,
                                             const UA_UInt32 interval,
                                             UA_UInt64 *callbackId);

/* Remove a repated callback. Thread-safe, can be used in parallel and in
 * parallel with UA_RepeatedCallbacksList_process. */
UA_StatusCode
UA_RepeatedCallbacksList_removeRepeatedCallback(UA_RepeatedCallbacksList *rcl,
                                                const UA_UInt64 callbackId);

/* Process the repeated callbacks that have timed out. Returns the timestamp of
 * the next scheduled repeated callback. Not thread-safe. Application is a
 * pointer to the client / server environment for the callback. Dispatched is
 * set to true when at least one callback was run / dispatched. */
UA_DateTime
UA_RepeatedCallbacksList_process(UA_RepeatedCallbacksList *rcl, UA_DateTime nowMonotonic,
                                 void *application, UA_Boolean *dispatched);

/* Remove all repeated callbacks. Not thread-safe. */
void UA_RepeatedCallbacksList_deleteMembers(UA_RepeatedCallbacksList *rcl);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* UA_TIMER_H_ */
