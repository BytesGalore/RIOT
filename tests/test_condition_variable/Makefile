export PROJECT = test_condition_variable
include ../Makefile.tests_common

USEMODULE += posix
USEMODULE += pthread
USEMODULE += vtimer

ifeq ($(BOARD),native)
    CFLAGS += -isystem $(RIOTBASE)/sys/posix/pthread/include
else
    export INCLUDES += -I$(RIOTBASE)/sys/posix/pthread/include \
                       -I$(RIOTBASE)/sys/posix/include
endif

include $(RIOTBASE)/Makefile.include
