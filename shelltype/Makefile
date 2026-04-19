# Makefile for shelltype (Command Policy Learner)

CC      ?= gcc
CFLAGS  := -Wall -Wextra -Werror -pedantic -std=c11 -O2 -g
LDFLAGS :=

INCLUDES := -Iinclude

SRCDIR  := src
TOOLDIR := tools
TESTDIR := tests
OBJDIR  := obj

# Library sources
LIB_SRCS := $(SRCDIR)/normalize.c $(SRCDIR)/trie.c $(SRCDIR)/policy.c $(SRCDIR)/policy_ctx.c $(SRCDIR)/vacuum_filter.c $(SRCDIR)/filter_hash.c
LIB_SRCS_ALL := $(LIB_SRCS)
LIB_OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(LIB_SRCS_ALL))

# Library
LIB_NAME := libshelltype.a
LIB      := $(OBJDIR)/$(LIB_NAME)

# CLI tool
TOOL_SRC := $(TOOLDIR)/shelltype-tool.c
TOOL_BIN := shelltype-tool

# Tests
TEST_SRC := $(TESTDIR)/test_shelltype.c
TEST_BIN := $(TESTDIR)/test_shelltype

TEST_POLICY_SRC := $(TESTDIR)/test_policy.c
TEST_POLICY_BIN := $(TESTDIR)/test_policy

TEST_VERIFY_SRC := $(TESTDIR)/test_verify.c
TEST_VERIFY_BIN := $(TESTDIR)/test_verify

TEST_TOKEN_TYPES_SRC := $(TESTDIR)/test_token_types.c
TEST_TOKEN_TYPES_BIN := $(TESTDIR)/test_token_types

# Integration tests
INTEGRATION_SRC := $(TESTDIR)/test_shelltype_integration.c
INTEGRATION_BIN := $(TESTDIR)/test_shelltype_integration

# Compact policy tests
COMPACT_POLICY_SRC := $(TESTDIR)/test_policy_compact.c
COMPACT_POLICY_BIN := $(TESTDIR)/test_policy_compact

# Filter tests (Bloom, Cuckoo, Vacuum)
FILTER_TEST_SRC := $(TESTDIR)/test_filters.c
FILTER_TEST_BIN := $(TESTDIR)/test_filters

# Default target
.PHONY: all clean test

all: $(LIB) $(TOOL_BIN)

# Object directory
$(OBJDIR):
	mkdir -p $(OBJDIR)

# Library objects
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Vacuum filter object (compiled without -Werror)
$(OBJDIR)/vacuum_filter.o: $(SRCDIR)/vacuum_filter.c | $(OBJDIR)
	$(CC) $(CFLAGS) -Wno-error $(INCLUDES) -c $< -o $@

# Static library
$(LIB): $(LIB_OBJS)
	ar rcs $@ $^

# CLI tool
$(TOOL_BIN): $(TOOL_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(OBJDIR) -lshelltype -lm -o $@

# Unit tests
$(TEST_BIN): $(TEST_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(OBJDIR) -lshelltype -lm -o $@

$(TEST_POLICY_BIN): $(TEST_POLICY_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(OBJDIR) -lshelltype -lm -o $@

$(TEST_VERIFY_BIN): $(TEST_VERIFY_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(OBJDIR) -lshelltype -lm -o $@

$(TEST_TOKEN_TYPES_BIN): $(TEST_TOKEN_TYPES_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(OBJDIR) -lshelltype -lm -o $@

# Integration tests
$(INTEGRATION_BIN): $(INTEGRATION_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(OBJDIR) -lshelltype -lm -o $@

$(COMPACT_POLICY_BIN): $(COMPACT_POLICY_SRC) $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L$(OBJDIR) -lshelltype -lm -o $@

# Filter tests need bloom and cuckoo objects in addition to the library
FILTER_TEST_OBJS := $(OBJDIR)/bloom_filter.o $(OBJDIR)/cuckoo_filter.o
$(OBJDIR)/bloom_filter.o: $(SRCDIR)/bloom_filter.c | $(OBJDIR)
	$(CC) $(CFLAGS) -Wno-error $(INCLUDES) -c $< -o $@

$(OBJDIR)/cuckoo_filter.o: $(SRCDIR)/cuckoo_filter.c | $(OBJDIR)
	$(CC) $(CFLAGS) -Wno-error $(INCLUDES) -c $< -o $@

$(FILTER_TEST_BIN): $(FILTER_TEST_SRC) $(LIB) $(FILTER_TEST_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $< $(FILTER_TEST_OBJS) -L$(OBJDIR) -lshelltype -lm -o $@

# Run tests
test: $(TEST_TOKEN_TYPES_BIN) $(TEST_BIN) $(TEST_POLICY_BIN) $(TEST_VERIFY_BIN) $(INTEGRATION_BIN) $(COMPACT_POLICY_BIN) $(FILTER_TEST_BIN)
	@echo "=== Running token type tests ==="
	@$(TEST_TOKEN_TYPES_BIN)
	@echo ""
	@echo "=== Running shelltype unit tests ==="
	@$(TEST_BIN)
	@echo ""
	@echo "=== Running policy unit tests ==="
	@$(TEST_POLICY_BIN)
	@echo ""
	@echo "=== Running verify unit tests ==="
	@$(TEST_VERIFY_BIN)
	@echo ""
	@echo "=== Running integration tests ==="
	@$(INTEGRATION_BIN)
	@echo ""
	@echo "=== Running compact policy tests ==="
	@$(COMPACT_POLICY_BIN)
	@echo ""
	@echo "=== Running filter tests ==="
	@$(FILTER_TEST_BIN)
	@echo ""
	@echo "=== All tests passed ==="

clean:
	rm -rf $(OBJDIR) $(TOOL_BIN) $(TEST_BIN) $(TEST_POLICY_BIN) $(TEST_VERIFY_BIN) $(TEST_TOKEN_TYPES_BIN) $(INTEGRATION_BIN) $(COMPACT_POLICY_BIN) $(FILTER_TEST_BIN)
	rm -f $(TESTDIR)/test_output.txt $(TESTDIR)/test_*.tmp
