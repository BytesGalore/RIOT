/*
 * Copyright (C) 2017
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 *
 * @author  martin.landsmann@haw-hamburg.de
 */

#include "net/gnrc/rpl/watchdog/rpl_wd_protector_base.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static stProtector_t* protectors[RPL_WD_MAX_PROTECTORS_COUNT];

int add_protector(stProtector_t* protector)
{
    for (int i = 0; i < RPL_WD_MAX_PROTECTORS_COUNT; i++)
    {
        if(protectors[i] == NULL)
        {
            protectors[i] = protector;
            return 0;
        }
    }
    return -1;
}

int del_protector(stProtector_t* protector)
{
    for (int i = 0; i < RPL_WD_MAX_PROTECTORS_COUNT; i++)
    {
        if(protectors[i] == protector)
        {
            protectors[i] = NULL;
        }
    }
    return -1;
}

stProtector_t* get_next_protector(stProtector_t* protector)
{
    bool found = (protector == NULL) ? true : false;
    for (int i = 0; i < (RPL_WD_MAX_PROTECTORS_COUNT); i++)
    {
        if (!found && (protector == protectors[i]))
        {
            found = true;
            continue;
        }

        if (found && protectors[i] && (protectors[i]->is_matching()))
        {
            return protectors[i];
        }
    }

    return NULL;
}

void init_protectors(void)
{
    memset(&protectors[0], 0, RPL_WD_MAX_PROTECTORS_COUNT*(sizeof(stProtector_t)));
}
