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

#include "net/gnrc/rpl/watchdog/rpl_wd_protectors.h"
#include "net/gnrc/rpl/watchdog/rpl_wd_protector_base.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static void gethandled(uint8_t* handled)
{
    setbit(eDIOpkt, handled);
    setbit(eParentAdd, handled);
    setbit(eParentSetPrune, handled);
    setbit(eDISpkt, handled);
    setbit(eDISUnicast, handled);
}

static int init(void)
{
    puts("init");
    return 0;
}

static bool is_matching(void)
{
    if (getIdentificationBit(eDISUnicast) || getIdentificationBit(eDISpkt))
    {
        puts("matches");
        return true;
    }
    return false;
}

static int apply(uint8_t* result)
{
    puts("apply");

    clearbit(eDIOpkt, result);
    
    clearbit(eParentAdd, result);
    clearbit(eParentSetPrune, result);
    clearbit(eDISpkt, result);
    clearbit(eDISUnicast, result);
    return 0;
}

stProtector_t testProtector = {init, gethandled, is_matching, apply};

void register_protectors(void)
{
    add_protector(&testProtector);
}
