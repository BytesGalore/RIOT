/*
 * Copyright (C) 2013 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser General
 * Public License. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @defgroup pthread POSIX threads
 * POSIX conforming multi-threading features.
 * @ingroup posix
 * @{
 * @file
 * @brief   Thread creation features.
 * @see     [The Open Group Base Specifications Issue 7: pthread.h - threads](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/pthread.h.html)
 * @author  Christian Mehlis <mehlis@inf.fu-berlin.de>
 * @author  René Kijewski <kijewski@inf.fu-berlin.de>
 * @}
 */

#include <malloc.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "cpu-conf.h"
#include "irq.h"
#include "kernel_internal.h"
#include "msg.h"
#include "mutex.h"
#include "queue.h"
#include "thread.h"
#include "sched.h"

#include "pthread.h"

#define ENABLE_DEBUG (0)

#if ENABLE_DEBUG
#   define PTHREAD_REAPER_STACKSIZE KERNEL_CONF_STACKSIZE_MAIN
#   define PTHREAD_STACKSIZE KERNEL_CONF_STACKSIZE_MAIN
#else
#   define PTHREAD_REAPER_STACKSIZE KERNEL_CONF_STACKSIZE_DEFAULT
#   define PTHREAD_STACKSIZE KERNEL_CONF_STACKSIZE_DEFAULT
#endif

#include "debug.h"

enum pthread_thread_status {
    PTS_RUNNING,
    PTS_DETACHED,
    PTS_ZOMBIE,
};

typedef struct tls_data {
    pthread_key_t key;
    struct tls_data *next;
    void *value;
} tls_data_t;

typedef struct pthread_thread {
    int thread_pid;

    enum pthread_thread_status status;
    int joining_thread;
    void *returnval;
    bool should_cancel;

    void *(*start_routine)(void *);
    void *arg;

    struct tls_data *tls;

    char *stack;

    __pthread_cleanup_datum_t *cleanup_top;
} pthread_thread_t;

static pthread_thread_t *volatile pthread_sched_threads[MAXTHREADS];
static struct mutex_t pthread_mutex;

static volatile int pthread_reaper_pid = -1;

static char pthread_reaper_stack[PTHREAD_REAPER_STACKSIZE];

struct __pthread_key {
    void (*destructor)(void *);
};

static void pthread_keys_exit(pthread_thread_t *pt);

static void pthread_start_routine(void)
{
    pthread_t self = pthread_self();

    pthread_thread_t *pt = pthread_sched_threads[self - 1];

    void *retval = pt->start_routine(pt->arg);
    pthread_exit(retval);
}

static int insert(pthread_thread_t *pt)
{
    int result = -1;
    mutex_lock(&pthread_mutex);

    for (int i = 0; i < MAXTHREADS; i++){
        if (!pthread_sched_threads[i]) {
            pthread_sched_threads[i] = pt;
            result = i+1;
            break;
        }
    }

    mutex_unlock(&pthread_mutex);
    return result;
}

static void pthread_reaper(void)
{
    while (1) {
        msg_t m;
        msg_receive(&m);
        DEBUG("pthread_reaper(): free(%p)\n", m.content.ptr);
        free(m.content.ptr);
    }
}

int pthread_create(pthread_t *newthread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)
{
    pthread_thread_t *pt = calloc(1, sizeof(pthread_thread_t));

    int pthread_pid = insert(pt);
    if (pthread_pid < 0) {
        free(pt);
        return -1;
    }
    *newthread = pthread_pid;

    pt->status = attr && attr->detached ? PTS_DETACHED : PTS_RUNNING;
    pt->start_routine = start_routine;
    pt->arg = arg;

    bool autofree = attr == NULL || attr->ss_sp == NULL || attr->ss_size == 0;
    size_t stack_size = attr && attr->ss_size > 0 ? attr->ss_size : PTHREAD_STACKSIZE;
    void *stack = autofree ? malloc(stack_size) : attr->ss_sp;
    pt->stack = autofree ? stack : NULL;

    if (autofree && pthread_reaper_pid < 0) {
        mutex_lock(&pthread_mutex);
        if (pthread_reaper_pid < 0) {
            /* volatile pid to overcome problems with double checking */
            volatile int pid = thread_create(pthread_reaper_stack,
                                             PTHREAD_REAPER_STACKSIZE,
                                             0,
                                             CREATE_STACKTEST,
                                             pthread_reaper,
                                             "pthread-reaper");
            pthread_reaper_pid = pid;
        }
        mutex_unlock(&pthread_mutex);
    }

    pt->thread_pid = thread_create(stack,
                                   stack_size,
                                   PRIORITY_MAIN,
                                   CREATE_WOUT_YIELD | CREATE_STACKTEST,
                                   pthread_start_routine,
                                   "pthread");
    if (pt->thread_pid < 0) {
        free(pt->stack);
        free(pt);
        pthread_sched_threads[pthread_pid-1] = NULL;
        return -1;
    }

    sched_switch(sched_active_thread->priority, PRIORITY_MAIN);

    return 0;
}

void pthread_exit(void *retval)
{
    pthread_t self_id = pthread_self();

    if (self_id == 0) {
        DEBUG("ERROR called pthread_self() returned 0 in \"%s\"!\n", __func__);
    }
    else {
        pthread_thread_t *self = pthread_sched_threads[self_id-1];

        while (self->cleanup_top) {
            __pthread_cleanup_datum_t *ct = self->cleanup_top;
            self->cleanup_top = ct->__next;

            ct->__routine(ct->__arg);
        }

        pthread_keys_exit(self);

        self->thread_pid = -1;
        DEBUG("pthread_exit(%p), self == %p\n", retval, (void *) self);
        if (self->status != PTS_DETACHED) {
            self->returnval = retval;
            self->status = PTS_ZOMBIE;

            if (self->joining_thread) {
                /* our thread got an other thread waiting for us */
                thread_wakeup(self->joining_thread);
            }
        }

        dINT();
        if (self->stack) {
            msg_t m;
            m.content.ptr = self->stack;
            msg_send_int(&m, pthread_reaper_pid);
        }
    }

    sched_task_exit();
}

int pthread_join(pthread_t th, void **thread_return)
{
    if (th < 1 || th > MAXTHREADS) {
        DEBUG("passed pthread_t th (%d) exceeds bounds of pthread_sched_threads[] in \"%s\"!\n", th, __func__);
        return -3;
    }

    pthread_thread_t *other = pthread_sched_threads[th-1];
    if (!other) {
        return -1;
    }

    switch (other->status) {
        case (PTS_RUNNING):
            other->joining_thread = sched_active_pid;
            /* go blocked, I'm waking up if other thread exits */
            thread_sleep();
            /* no break */
        case (PTS_ZOMBIE):
            if (thread_return) {
                *thread_return = other->returnval;
            }
            free(other);
            /* we only need to free the pthread layer struct,
            native thread stack is freed by other */
            pthread_sched_threads[th-1] = NULL;
            return 0;
        case (PTS_DETACHED):
            return -1;
    }

    return -2;
}

int pthread_detach(pthread_t th)
{
    if (th < 1 || th > MAXTHREADS) {
        DEBUG("passed pthread_t th (%d) exceeds bounds of pthread_sched_threads[] in \"%s\"!\n", th, __func__);
        return -2;
    }

    pthread_thread_t *other = pthread_sched_threads[th-1];
    if (!other) {
        return -1;
    }

    if (other->status == PTS_ZOMBIE) {
        free(other);
        /* we only need to free the pthread layer struct,
        native thread stack is freed by other */
        pthread_sched_threads[th-1] = NULL;
    } else {
        other->status = PTS_DETACHED;
    }

    return 0;
}

pthread_t pthread_self(void)
{
    pthread_t result = 0;
    mutex_lock(&pthread_mutex);
    int pid = sched_active_pid; /* sched_active_pid is volatile */
    for (int i = 0; i < MAXTHREADS; i++) {
        if (pthread_sched_threads[i] && pthread_sched_threads[i]->thread_pid == pid) {
            result = i+1;
            break;
        }
    }
    mutex_unlock(&pthread_mutex);
    return result;
}

int pthread_cancel(pthread_t th)
{
    pthread_thread_t *other = pthread_sched_threads[th-1];
    if (!other) {
        return -1;
    }

    other->should_cancel = 1;

    return 0;
}

int pthread_setcancelstate(int state, int *oldstate)
{
    (void) state;
    (void) oldstate;
    return -1;
}

int pthread_setcanceltype(int type, int *oldtype)
{
    (void) type;
    (void) oldtype;
    return -1;
}

void pthread_testcancel(void)
{
    pthread_t self = pthread_self();

    if (self == 0) {
        DEBUG("ERROR called pthread_self() returned 0 in \"%s\"!\n", __func__);
        return;
    }

    if (pthread_sched_threads[self-1]->should_cancel) {
        pthread_exit(PTHREAD_CANCELED);
    }
}

void __pthread_cleanup_push(__pthread_cleanup_datum_t *datum)
{
    pthread_t self_id = pthread_self();

    if (self_id == 0) {
        DEBUG("ERROR called pthread_self() returned 0 in \"%s\"!\n", __func__);
        return;
    }

    pthread_thread_t *self = pthread_sched_threads[self_id-1];
    datum->__next = self->cleanup_top;
    self->cleanup_top = datum;
}

void __pthread_cleanup_pop(__pthread_cleanup_datum_t *datum, int execute)
{
    pthread_t self_id = pthread_self();

    if (self_id == 0) {
        DEBUG("ERROR called pthread_self() returned 0 in \"%s\"!\n", __func__);
        return;
    }

    pthread_thread_t *self = pthread_sched_threads[self_id-1];
    self->cleanup_top = datum->__next;

    if (execute != 0) {
        /* "The pthread_cleanup_pop() function shall remove the routine at the
         *  top of the calling thread's cancellation cleanup stack and optionally
         *  invoke it (if execute is non-zero)." */
        datum->__routine(datum->__arg);
    }
}

/**
 * @brief   Used while manipulating the TLS of a pthread.
 */
static struct mutex_t tls_mutex;

/**
 * @brief        Find a thread-specific datum.
 * @param[in]    pt     The calling pthread.
 * @param[in]    key    The key to look up.
 * @param[out]   prev   The datum before the result. `NULL` if the result is the first key. Spurious if the key was not found.
 * @returns      The datum or `NULL`.
 */
static tls_data_t *find_specific(pthread_thread_t *pt, pthread_key_t key, tls_data_t **prev)
{
    tls_data_t *specific = pt->tls;
    *prev = NULL;

    while (specific) {
        if (specific->key == key) {
            return specific;
        }

        *prev = specific;
        specific = specific->next;
    }

    return 0;
}

/**
 * @brief       Find or allocate a thread specific datum.
 * @details     The `key` must be initialized.
 *              The result will be the head of the thread-specific datums afterwards.
 * @param[in]   key   The key to lookup.
 * @returns     The datum. `NULL` on ENOMEM or if the caller is not a pthread.
 */
static tls_data_t *get_specific(pthread_key_t key)
{
    pthread_t self = pthread_self();
    if (self == 0) {
        DEBUG("ERROR called pthread_self() returned 0 in \"%s\"!\n", __func__);
        return NULL;
    }

    pthread_thread_t *pt = pthread_sched_threads[self - 1];
    tls_data_t *prev, *specific = find_specific(pt, key, &prev);

    /* Did the datum already exist? */
    if (specific) {
        if (prev) {
            /* Move the datum to the front for a faster next lookup. */
            /* Let's pretend that we have a totally degenerated splay tree. ;-) */
            prev->next = specific->next;
            specific->next = pt->tls;
            pt->tls = specific;
        }
        return specific;
    }

    /* Allocate new datum. */
    specific = malloc(sizeof (*specific));
    if (specific) {
        specific->key = key;
        specific->next = pt->tls;
        specific->value = NULL;
        pt->tls = specific;
    }
    else {
        DEBUG("ERROR out of memory in %s!\n", __func__);
    }
    return specific;
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *))
{
    *key = malloc(sizeof (**key));
    if (!*key) {
        return ENOMEM;
    }

    (*key)->destructor = destructor;
    return 0;
}

int pthread_key_delete(pthread_key_t key)
{
    if (!key) {
        return EINVAL;
    }

    mutex_lock(&tls_mutex);
    for (unsigned i = 0; i < sizeof (pthread_sched_threads) / sizeof (*pthread_sched_threads); ++i) {
        pthread_thread_t *pt = pthread_sched_threads[i];
        if (!pt) {
            continue;
        }

        tls_data_t *prev, *specific = find_specific(pt, key, &prev);
        if (specific) {
            if (prev) {
                prev->next = specific->next;
            }
            else {
                pt->tls = specific->next;
            }
            free(specific);
        }
    }
    mutex_unlock(&tls_mutex);

    return 0;
}

void *pthread_getspecific(pthread_key_t key)
{
    if (!key) {
        return NULL;
    }

    mutex_lock(&tls_mutex);
    tls_data_t *specific = get_specific(key);
    void *result = specific ? specific->value : NULL;
    mutex_unlock(&tls_mutex);

    return result;
}

int pthread_setspecific(pthread_key_t key, const void *value)
{
    if (!key) {
        return EINVAL;
    }

    mutex_lock(&tls_mutex);
    tls_data_t *specific = get_specific(key);
    if (specific) {
        specific->value = (void *) value;
    }
    mutex_unlock(&tls_mutex);

    return specific ? 0 : ENOMEM;
}

static void pthread_keys_exit(pthread_thread_t *pt)
{
    /* Calling the dtor could cause another pthread_exit(), so we dehead and free defore calling it. */
    mutex_lock(&tls_mutex);
    for (tls_data_t *specific; (specific = pt->tls); ) {
        pt->tls = specific->next;
        void *value = specific->value;
        void (*destructor)(void *) = specific->key->destructor;
        free(specific);

        if (value && destructor) {
            mutex_unlock(&tls_mutex);
            destructor(value);
            mutex_lock(&tls_mutex);
        }
    }
    mutex_unlock(&tls_mutex);
}
