/*
 * Copyright (C) 2014 Hamburg University of Applied Sciences (HAW)
 *
 * This file subject to the terms and conditions of the GNU Lesser General
 * Public License. See the file LICENSE in the top level directory for more
 * details.
 */

/**
 * @ingroup pthread
 * @{
 * @file
 * @brief       RIOT POSIX thread local storage
 * @author      Martin Landsmann <martin.landsmann@haw-hamburg.de>
 */

#ifndef __SYS__POSIX__PTHREAD_TLS__H
#define __SYS__POSIX__PTHREAD_TLS__H

/**
 * @brief   Internal representation of a thread-specific key.
 * @internal
 */
struct __pthread_key;

/**
 * @brief   A thread-specific key.
 */
typedef struct __pthread_key *pthread_key_t;

/**
 * @brief returns the requested tls
 * @param[in] key the identifier for the requested tls
 * @return returns pointer to the storage on success, a 0 value otherwise
 */
void *pthread_getspecific(pthread_key_t key);

/**
 * @brief set and binds a specific tls to a key
 * @param[in] key the identifier for the tls
 * @param[in] value pointer to the location of the tls
 * @return returns 0 on success, an errorcode otherwise
 */
int pthread_setspecific(pthread_key_t key, const void *value);

/**
 * @brief crates a new key to be used to identify a specific tls
 * @param[out] key the created key is scribed to the given pointer
 * @param[in] destructor function pointer called when non NULL just befor the pthread exits
 * @return returns 0 on success, an errorcode otherwise
 */
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));

/**
 * @brief deletes a pthread_key_t that was previously created with pthread_key_create.
 * @details does not call the destructor of the key
 * @param[in] key the identifier of the key to be deleted
 * @return returns 0 on success, an errorcode otherwise
 */
int pthread_key_delete(pthread_key_t key);

#endif /* __SYS__POSIX__PTHREAD_TLS__H */
/** @} */
