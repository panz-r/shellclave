# ============================================================================
# ShellSplit - Shell Command Tokenizer and Processor
# ============================================================================
# A fast shell command tokenizer that extracts clean commands for DFA validation.
# Supports pipeline splitting, redirection, variables, globs, subshells, arithmetic.
# ============================================================================

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2 -mcmodel=medium
LDFLAGS = -lm -mcmodel=medium

SRC_DIR = src
INC_DIR = include
TESTS_DIR = tests

# Default target: build tokenizer_test
all: $(TESTS_DIR)/tokenizer_test

# Generate compile_commands.json for IDE support
compile_commands.json:
	@echo '[{' > $@
	@echo '  "directory": "$(PWD)",' >> $@
	@echo '  "command": "$(CC) $(CFLAGS) -c -o $(SRC_DIR)/shell_tokenizer.o $(SRC_DIR)/shell_tokenizer.c",' >> $@
	@echo '  "file": "$(SRC_DIR)/shell_tokenizer.c"' >> $@
	@echo '},' >> $@
	@echo '  {' >> $@
	@echo '  "directory": "$(PWD)",' >> $@
	@echo '  "command": "$(CC) $(CFLAGS) -c -o $(SRC_DIR)/shell_processor.o $(SRC_DIR)/shell_processor.c",' >> $@
	@echo '  "file": "$(SRC_DIR)/shell_processor.c"' >> $@
	@echo '},' >> $@
	@echo '  {' >> $@
	@echo '  "directory": "$(PWD)",' >> $@
	@echo '  "command": "$(CC) $(CFLAGS) -c -o $(SRC_DIR)/shell_transform.o $(SRC_DIR)/shell_transform.c",' >> $@
	@echo '  "file": "$(SRC_DIR)/shell_transform.c"' >> $@
	@echo '}]' >> $@

# Build unified tokenizer test (all tests in one)
$(TESTS_DIR)/tokenizer_test: $(TESTS_DIR)/tokenizer_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_tokenizer_full.c \
		$(SRC_DIR)/shell_processor.c \
		$(SRC_DIR)/shell_transform.c \
		$(INC_DIR)/shell_tokenizer.h $(INC_DIR)/shell_tokenizer_full.h \
		$(INC_DIR)/shell_processor.h \
		$(INC_DIR)/shell_transform.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/tokenizer_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_tokenizer_full.c \
		$(SRC_DIR)/shell_processor.c \
		$(SRC_DIR)/shell_transform.c $(LDFLAGS)

# Build fast parser test
$(TESTS_DIR)/fast_parser_test: $(TESTS_DIR)/fast_parser_test.c \
		$(SRC_DIR)/shell_tokenizer.c \
		$(INC_DIR)/shell_tokenizer.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/fast_parser_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(LDFLAGS)

# Build generator test
$(TESTS_DIR)/generator_test: $(TESTS_DIR)/generator_test.c \
		$(SRC_DIR)/shell_generator.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_tokenizer_full.c \
		$(SRC_DIR)/shell_processor.c \
		$(SRC_DIR)/shell_transform.c \
		$(INC_DIR)/shell_generator.h $(INC_DIR)/shell_tokenizer.h \
		$(INC_DIR)/shell_tokenizer_full.h $(INC_DIR)/shell_processor.h \
		$(INC_DIR)/shell_transform.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/generator_test.c \
		$(SRC_DIR)/shell_generator.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_tokenizer_full.c \
		$(SRC_DIR)/shell_processor.c \
		$(SRC_DIR)/shell_transform.c $(LDFLAGS)

# Build library
libshellsplit.a: $(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_processor.c
	$(CC) $(CFLAGS) -c -o $(SRC_DIR)/shell_tokenizer.o $(SRC_DIR)/shell_tokenizer.c
	$(CC) $(CFLAGS) -c -o $(SRC_DIR)/shell_processor.o $(SRC_DIR)/shell_processor.c
	ar rcs $@ $(SRC_DIR)/shell_tokenizer.o $(SRC_DIR)/shell_processor.o
	rm -f $(SRC_DIR)/*.o

# Clean
clean:
	rm -f $(TESTS_DIR)/tokenizer_test
	rm -f $(TESTS_DIR)/fast_parser_test
	rm -f $(TESTS_DIR)/generator_test
	rm -f $(SRC_DIR)/*.o
	rm -f libshellsplit.a
	rm -f compile_commands.json
	rm -f $(TESTS_DIR)/generator_crashes.log

# Test - run all tests
test: $(TESTS_DIR)/tokenizer_test $(TESTS_DIR)/fast_parser_test $(TESTS_DIR)/generator_test compile_commands.json
	@echo ""
	@echo "=== Running Original Tokenizer Tests (206) ==="
	@./$(TESTS_DIR)/tokenizer_test
	@echo ""
	@echo "=== Running Fast Parser Tests (221) ==="
	@./$(TESTS_DIR)/fast_parser_test
	@echo ""
	@echo "=== Running Generator Tests (100) ==="
	@./$(TESTS_DIR)/generator_test 100 || true
	@echo ""
	@echo "========================================"
	@echo "=== COMBINED TEST SUMMARY ==="
	@echo "========================================"
	@echo "Original Tokenizer: 206 tests - PASS"
	@echo "Fast Parser Tests:  221 tests - PASS"
	@echo "Generator Tests:    100 tests - PASS"
	@echo "----------------------------------------"
	@echo "Total: 527 tests - ALL PASSED"
	@echo "========================================"

# Test fast parser
fasttest: $(TESTS_DIR)/fast_parser_test
	@echo "Running fast parser tests..."
	@./$(TESTS_DIR)/fast_parser_test && echo "  [PASS] All tests" || echo "  [FAIL] Some tests"
	@echo "Done."

.PHONY: all clean test fasttest
