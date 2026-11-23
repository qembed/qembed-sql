EXTENSION = qembed_context_verify
MODULE_big = qembed_context_verify
OBJS = qembed_context_verify.o
DATA = qembed_context_verify--1.0.sql

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
PG_CPPFLAGS += $(shell pkg-config --cflags libsodium)
SHLIB_LINK += $(shell pkg-config --libs libsodium)

include $(PGXS)
