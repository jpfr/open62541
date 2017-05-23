/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ua_util.h"
#include "ua_timer.h"

/* Only one thread operates on the repeated jobs. This is usually the "main"
 * thread with the event loop. All other threads may add changes to the repeated
 * jobs to a multi-producer single-consumer queue. The queue is based on a
 * design by Dmitry Vyukov.
 * http://www.1024cores.net/home/lock-free-algorithms/queues/intrusive-mpsc-node-based-queue */

struct UA_RepeatedCallback {
    SLIST_ENTRY(UA_RepeatedCallback) next; /* Next element in the list */
    UA_DateTime nextTime;                  /* The next time when the callbacks are to be executed */
    UA_UInt64 interval;                    /* Interval in 100ns resolution */
    UA_UInt64 id;                          /* Id of the repeated callback */
    UA_Callback callback;                  /* The callback description itself */
};

void
UA_RepeatedCallbacksList_init(UA_RepeatedCallbacksList *rcl) {
    SLIST_INIT(&rcl->repeatedCallbacks);
    rcl->changes_head = (UA_RepeatedCallback*)&rcl->changes_stub;
    rcl->changes_tail = (UA_RepeatedCallback*)&rcl->changes_stub;
    rcl->changes_stub = NULL;
    rcl->identiferCounter = 0;
}

static void
enqueueChange(UA_RepeatedCallbacksList *rcl, UA_RepeatedCallback *rc) {
    rc->next.sle_next = NULL;
    UA_RepeatedCallback *prev = (UA_RepeatedCallback*)UA_atomic_xchg((void * volatile *)&rcl->changes_head, rc);
    /* Nothing can be dequeued while the producer is blocked here */
    prev->next.sle_next = rc; /* Once this change is visible in the consumer,
                               * the node is dequeued in the following
                               * iteration */
}

static UA_RepeatedCallback *
dequeueChange(UA_RepeatedCallbacksList *rcl) {
    UA_RepeatedCallback *tail = rcl->changes_tail;
    UA_RepeatedCallback *next = tail->next.sle_next;
    if(tail == (UA_RepeatedCallback*)&rcl->changes_stub) {
        if(!next)
            return NULL;
        rcl->changes_tail = next;
        tail = next;
        next = next->next.sle_next;
    }
    if(next) {
        rcl->changes_tail = next;
        return tail;
    }
    UA_RepeatedCallback* head = rcl->changes_head;
    if(tail != head)
        return NULL;
    enqueueChange(rcl, (UA_RepeatedCallback*)&rcl->changes_stub);
    next = tail->next.sle_next;
    if(next) {
        rcl->changes_tail = next;
        return tail;
    }
    return NULL;
}

/* Adding repeated callbacks: Add an entry with the "nextTime" timestamp in the
 * future. This will be picked up in the next iteration and inserted at the
 * correct place. So that the next execution takes place ät "nextTime". */
UA_StatusCode
UA_RepeatedCallbacksList_addRepeatedCallback(UA_RepeatedCallbacksList *rcl,
                                             const UA_Callback callback,
                                             const UA_UInt32 interval,
                                             UA_UInt64 *callbackId) {
    /* The interval needs to be at least 5ms */
    if(interval < 5)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Allocate the repeated callback structure */
    UA_RepeatedCallback *rc = (UA_RepeatedCallback*)UA_malloc(sizeof(UA_RepeatedCallback));
    if(!rc)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    /* Set the repeated callback */
    rc->interval = (UA_UInt64)interval * (UA_UInt64)UA_MSEC_TO_DATETIME;
    rc->id = ++rcl->identiferCounter;
    rc->callback = callback;
    rc->nextTime = UA_DateTime_nowMonotonic() + (UA_DateTime)rc->interval;

    /* Set the output identifier */
    if(callbackId)
        *callbackId = rc->id;

    /* Enqueue the changes in the MPSC queue */
    enqueueChange(rcl, rc);
    return UA_STATUSCODE_GOOD;
}

static void
addRepeatedCallback(UA_RepeatedCallbacksList *rcl,
                    UA_RepeatedCallback * UA_RESTRICT rc,
                    UA_DateTime nowMonotonic) {
    /* The latest time for the first execution */
    rc->nextTime = nowMonotonic + (UA_Int64)rc->interval;

    /* Find the last entry before this callback */
    UA_RepeatedCallback *tmpRc, *afterRc = NULL;
    SLIST_FOREACH(tmpRc, &rcl->repeatedCallbacks, next) {
        if(tmpRc->nextTime >= rc->nextTime)
            break;
        afterRc = tmpRc;

        /* The goal is to have many repeated callbacks with the same repetition
         * interval in a "block" in order to reduce linear search for re-entry
         * to the sorted list after processing. Allow the first execution to lie
         * between "nextTime - 1s" and "nextTime" if this adjustment groups callbacks
         * with the same repetition interval. */
        if(tmpRc->interval == rc->interval &&
           tmpRc->nextTime > (rc->nextTime - UA_SEC_TO_DATETIME))
            rc->nextTime = tmpRc->nextTime;
    }

    /* Add the repeated callback */
    if(afterRc)
        SLIST_INSERT_AFTER(afterRc, rc, next);
    else
        SLIST_INSERT_HEAD(&rcl->repeatedCallbacks, rc, next);
}

/* Removing a repeated callback: Add an entry with the "nextTime" timestamp set to
 * UA_INT64_MAX. The next iteration picks this up and removes the repated callback
 * from the linked list. */
UA_StatusCode
UA_RepeatedCallbacksList_removeRepeatedCallback(UA_RepeatedCallbacksList *rcl,
                                                const UA_UInt64 callbackId) {
    /* Allocate the repeated callback structure */
    UA_RepeatedCallback *rc = (UA_RepeatedCallback*)UA_malloc(sizeof(UA_RepeatedCallback));
    if(!rc)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    /* Set the repeated callback with the sentinel nextTime */
    rc->id = callbackId;
    rc->nextTime = UA_INT64_MAX;

    /* Enqueue the changes in the MPSC queue */
    enqueueChange(rcl, rc);
    return UA_STATUSCODE_GOOD;
}

static void
removeRepeatedCallback(UA_RepeatedCallbacksList *rcl,
                       const UA_UInt64 *callbackId) {
    UA_RepeatedCallback *rc, *prev = NULL;
    SLIST_FOREACH(rc, &rcl->repeatedCallbacks, next) {
        if(callbackId == &rc->id) {
            if(prev)
                SLIST_REMOVE_AFTER(prev, next);
            else
                SLIST_REMOVE_HEAD(&rcl->repeatedCallbacks, next);
            UA_free(rc);
            break;
        }
        prev = rc;
    }
}

static void
processChanges(UA_RepeatedCallbacksList *rcl, UA_DateTime nowMonotonic) {
    UA_RepeatedCallback *change;
    while((change = dequeueChange(rcl))) {
        if(change->nextTime < UA_INT64_MAX) {
            addRepeatedCallback(rcl, change, nowMonotonic);
        } else {
            removeRepeatedCallback(rcl, &change->id);
            UA_free(change);
        }
    }
}

UA_DateTime
UA_RepeatedCallbacksList_process(UA_RepeatedCallbacksList *rcl,
                                 UA_DateTime nowMonotonic,
                                 void *application,
                                 UA_Boolean *dispatched) {
    /* Insert and remove callbacks */
    processChanges(rcl, nowMonotonic);

    /* Find the last callback to be executed now */
    UA_RepeatedCallback *firstAfter, *lastNow = NULL;
    SLIST_FOREACH(firstAfter, &rcl->repeatedCallbacks, next) {
        if(firstAfter->nextTime > nowMonotonic)
            break;
        lastNow = firstAfter;
    }

    /* Nothing to do */
    if(!lastNow) {
        if(firstAfter)
            return firstAfter->nextTime;
        return UA_INT64_MAX;
    }

    /* Put the callbacks that are executed now in a separate list */
    struct memberstruct(UA_RepeatedCallbacksList,RepeatedCallbacksSList) executedNowList;
    executedNowList.slh_first = SLIST_FIRST(&rcl->repeatedCallbacks);
    lastNow->next.sle_next = NULL;

    /* Fake entry to represent the first element in the newly-sorted list */
    UA_RepeatedCallback tmp_first;
    tmp_first.nextTime = nowMonotonic - 1; /* never matches for last_dispatched */
    tmp_first.next.sle_next = firstAfter;
    UA_RepeatedCallback *last_dispatched = &tmp_first;

    /* Iterate over the list of callbacks to process now */
    UA_RepeatedCallback *rc;
    while((rc = SLIST_FIRST(&executedNowList))) {
        /* Remove from the list */
        SLIST_REMOVE_HEAD(&executedNowList, next);

        /* Dispatch/process callback */
        rc->callback.callback(application, rc->callback.context, &rc->callback.data);
        *dispatched = true;

        /* Set the time for the next execution. Prevent an infinite loop by
         * forcing the next processing into the next iteration. */
        rc->nextTime += (UA_Int64)rc->interval;
        if(rc->nextTime < nowMonotonic)
            rc->nextTime = nowMonotonic + 1;

        /* Find the new position for rc to keep the list sorted */
        UA_RepeatedCallback *prev_rc;
        if(last_dispatched->nextTime == rc->nextTime) {
            /* We "batch" repeatedCallbacks with the same interval in
             * addRepeatedCallbacks. So this might occur quite often. */
            UA_assert(last_dispatched != &tmp_first);
            prev_rc = last_dispatched;
        } else {
            /* Find the position for the next execution by a linear search
             * starting at the first possible callback */
            prev_rc = &tmp_first;
            while(true) {
                UA_RepeatedCallback *n = SLIST_NEXT(prev_rc, next);
                if(!n || n->nextTime >= rc->nextTime)
                    break;
                prev_rc = n;
            }

            /* Update last_dispatched */
            last_dispatched = rc;
        }

        /* Add entry to the new position in the sorted list */
        SLIST_INSERT_AFTER(prev_rc, rc, next);
    }

    /* Set the entry-point for the newly sorted list */
    rcl->repeatedCallbacks.slh_first = tmp_first.next.sle_next;

    /* Re-repeat processAddRemoved since one of the callbacks might have removed or
     * added a callback. So we get the returned timeout right. */
    processChanges(rcl, nowMonotonic);

    /* Return timestamp of next repetition */
    return SLIST_FIRST(&rcl->repeatedCallbacks)->nextTime;
}

void
UA_RepeatedCallbacksList_deleteMembers(UA_RepeatedCallbacksList *rcl) {
    /* Process changes to empty the queue */
    processChanges(rcl, 0);

    /* Remove repeated callbacks */
    UA_RepeatedCallback *current;
    while((current = SLIST_FIRST(&rcl->repeatedCallbacks))) {
        SLIST_REMOVE_HEAD(&rcl->repeatedCallbacks, next);
        UA_free(current);
    }
}
