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

#include "net/gnrc/rpl/watchdog/rpl_wd_parser_base.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"


static stRule* rules[RPL_WD_MAX_RULES_COUNT];

int add_rule(stRule* rule)
{
    for (int i = 0; i < RPL_WD_MAX_RULES_COUNT; i++)
    {
        if(rules[i] == NULL)
        {
            rules[i] = rule;
            return 0;
        }
    }
    return -1;
}

int del_rule(stRule* rule)
{
    for (int i = 0; i < RPL_WD_MAX_RULES_COUNT; i++)
    {
        if(rules[i] == rule)
        {
            rules[i]->code = 0;
            rules[i] = NULL;
        }
    }
    return -1;
}

stRule* get_next_typed_rule(uint16_t type, stRule* rule)
{
    bool found = (rule == NULL) ? true : false;
    for (int i = 0; i < (RPL_WD_MAX_RULES_COUNT); i++)
    {
        if (!found && (rule == rules[i]))
        {
            found = true;
            continue;
        }

        if (found && rules[i] && (type == rules[i]->code))
        {
            return rules[i];
        }
    }

    return NULL;
}

stRule* get_next_rule(stRule* rule)
{
    if (rule == NULL)
    {
        return rules[0];
    }

    for (int i = 0; i < (RPL_WD_MAX_RULES_COUNT-1); i++)
    {
        if (rule == rules[i])
        {
            return rules[i+1];
        }
    }
    return NULL;
}



void init_rules(void)
{
    //printf("RPL_WD_MAX_RULES_COUNT*(sizeof(stRule): %d\n", RPL_WD_MAX_RULES_COUNT*(sizeof(stRule)));
    memset(&rules[0], 0, RPL_WD_MAX_RULES_COUNT*(sizeof(stRule)));
}
