/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef UA_TIMER_H_
#define UA_TIMER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "ua_util.h"

/* Three pointers are passed into jobs:
 * - application (server / client)
 * - context (connection, session, ...)
 * - data (userdefined) */
typedef struct {
    void (*callback)(void *application, void *context, void *data);
    void *context;
    void *data;
} UA_Job;

typedef void
(*UA_RepeatedJobsListProcessCallback)(void *application, UA_Job *job);

struct UA_RepeatedJob;
typedef struct UA_RepeatedJob UA_RepeatedJob;

typedef struct {
    /* The linked list of jobs is sorted according to the execution timestamp. */
    SLIST_HEAD(RepeatedJobsSList, UA_RepeatedJob) repeatedJobs;

    /* Changes to the repeated jobs in a multi-producer single-consumer queue */
    UA_RepeatedJob * volatile changes_head;
    UA_RepeatedJob *changes_tail;
    UA_RepeatedJob *changes_stub;
} UA_RepeatedJobsList;

/* Initialize the RepeatedJobsSList. Not thread-safe. */
void
UA_RepeatedJobsList_init(UA_RepeatedJobsList *rjl);

/* Add a repated job. Thread-safe, can be used in parallel and in parallel with
 * UA_RepeatedJobsList_process. */
UA_StatusCode
UA_RepeatedJobsList_addRepeatedJob(UA_RepeatedJobsList *rjl, const UA_Job job,
                                   const UA_UInt32 interval, UA_Guid *jobId);

/* Remove a repated job. Thread-safe, can be used in parallel and in parallel
 * with UA_RepeatedJobsList_process. */
UA_StatusCode
UA_RepeatedJobsList_removeRepeatedJob(UA_RepeatedJobsList *rjl, const UA_Guid jobId);

/* Process the repeated jobs that have timed out. Returns the timestamp of the
 * next scheduled repeated job. Not thread-safe.

 * application is a pointer to the client / server environment for the callback.
 * dispatched is set to true when at least one job was run / dispatched. */
UA_DateTime
UA_RepeatedJobsList_process(UA_RepeatedJobsList *rjl, UA_DateTime nowMonotonic,
                            void *application, UA_Boolean *dispatched);

/* Remove all repeated jobs. Not thread-safe. */
void
UA_RepeatedJobsList_deleteMembers(UA_RepeatedJobsList *rjl);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* UA_TIMER_H_ */
