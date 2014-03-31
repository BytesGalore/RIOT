/*
 * Copyright (C) 2014 Hamburg University of Applied Sciences (HAW)
 *
 * This file subject to the terms and conditions of the GNU Lesser General
 * Public License. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @defgroup
 * @brief
 * @ingroup     sys
 * @{
 *
 * @file        condition_variable.h
 * @brief       RIOT POSIX condition variable API
 *
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef _CONDITION_VARIABLE_H
#define _CONDITION_VARIABLE_H

#include <time.h>
#include "mutex.h"

typedef struct pthread_condattr_t {
    int __dummy;
} pthread_condattr_t;

/* // real definition
typedef struct {
    struct _pthread_fastlock __c_lock;
    _pthread_descr __c_waiting;
    char __padding[48 - sizeof(struct _pthread_fastlock) -
           sizeof(_pthread_descr) -
           sizeof(__pthread_cond_align_t)];
    __pthread_cond_align_t __align;
} pthread_cond_t;
*/

typedef struct pthread_cond_t {
    /* fields are managed by cv functions, don't touch */
    queue_node_t queue; /**< Threads currently waiting to be signaled. */
} pthread_cond_t;

/**
 * @brief Initializes a condition attribute variable object using default values
 * @param attr pre-allocated condition attribute variable structure.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_cond_condattr_destroy(struct pthread_condattr_t *attr);

/**
 * @brief Uninitializes a condition attribute variable object
 * @param attr pre-allocated condition attribute variable structure.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_cond_condattr_init(struct pthread_condattr_t *attr);

/**
 * @brief Get the process-shared attribute in an initialised attributes object referenced by attr
 * @param attr pre-allocated condition attribute variable structure.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared);

/**
 * @brief Set the process-shared attribute in an initialised attributes object referenced by attr
 * @param attr pre-allocated condition attribute variable structure.
 * @param pshared
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared);

/**
 * @brief Get the clock selected for the conditon variable attribute attr.
 * @param attr pre-allocated condition attribute variable structure.
 * @param clock_id the clock ID that is used to measure the timeout service
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_condattr_getclock(const pthread_condattr_t *attr, clockid_t *clock_id);

/**
 * @brief Set the clock selected for the conditon variable attribute ATTR.
 * @param attr pre-allocated condition attribute variable structure.
 * @param clock_id the clock ID that shall be used to measure the timeout service
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id);

/**
 * @brief Initializes a condition variable object
 * @param cond pre-allocated condition variable structure.
 * @param attr pre-allocated condition attribute variable structure.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_cond_init(struct pthread_cond_t *cond, struct pthread_condattr_t *attr);

/**
 * @brief Destroy the condition variable cond
 * @param cond pre-allocated condition variable structure.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_cond_destroy(struct pthread_cond_t *cond);

/**
 * @brief blocks the calling thread until the specified condition cond is signalled
 * @param cond pre-allocated condition variable structure.
 * @param mutex pre-allocated mutex variable structure.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_cond_wait(struct pthread_cond_t *cond, struct mutex_t *mutex);

/**
 * @brief blocks the calling thread until the specified condition cond is signalled
 * @param cond pre-allocated condition variable structure.
 * @param mutex pre-allocated mutex variable structure.
 * @param abstime pre-allocated timeout.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_cond_timedwait(struct pthread_cond_t *cond, struct mutex_t *mutex, const struct timespec *abstime);

/**
 * @brief unblock at least one of the threads that are blocked on the specified condition variable cond
 * @param cond pre-allocated condition variable structure.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_cond_signal(struct pthread_cond_t *cond);

/**
 * @brief unblock all threads that are currently blocked on the specified condition variable cond
 * @param cond pre-allocated condition variable structure.
 * @return returns 0 on success, an errorcode otherwise.
 */
int pthread_cond_broadcast(struct pthread_cond_t *cond);

/** @} */
#endif /* _CONDITION_VARIABLE_H */
