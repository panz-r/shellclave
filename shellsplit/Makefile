# ============================================================================
# ShellSplit - Shell Command Tokenizer and Processor
# ============================================================================
# A fast shell command tokenizer that extracts clean commands for DFA validation.
# Supports pipeline splitting, redirection, variables, and shell features.
# ============================================================================

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude -O2 -mcmodel=medium
LDFLAGS = -lm -mcmodel=medium

SRC_DIR = src
INC_DIR = include
TESTS_DIR = tests

# Default target: build tokenizer_test (basic)
all: $(TESTS_DIR)/tokenizer_test

# Build tokenizer test (basic tokenizer)
$(TESTS_DIR)/tokenizer_test: $(TESTS_DIR)/tokenizer_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_processor.c \
		$(INC_DIR)/shell_tokenizer.h $(INC_DIR)/shell_processor.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/tokenizer_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_processor.c $(LDFLAGS)

# Build extended tokenizer test
$(TESTS_DIR)/tokenizer_ext_test: $(TESTS_DIR)/tokenizer_ext_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_tokenizer_ext.c \
		$(INC_DIR)/shell_tokenizer.h $(INC_DIR)/shell_tokenizer_ext.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/tokenizer_ext_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_tokenizer_ext.c $(LDFLAGS)

# Build transform test
$(TESTS_DIR)/transform_test: $(TESTS_DIR)/transform_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_tokenizer_ext.c \
		$(SRC_DIR)/shell_transform.c \
		$(INC_DIR)/shell_tokenizer.h $(INC_DIR)/shell_tokenizer_ext.h \
		$(INC_DIR)/shell_transform.h
	$(CC) $(CFLAGS) -o $@ $(TESTS_DIR)/transform_test.c \
		$(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_tokenizer_ext.c \
		$(SRC_DIR)/shell_transform.c $(LDFLAGS)

# Build library
libshellsplit.a: $(SRC_DIR)/shell_tokenizer.c $(SRC_DIR)/shell_processor.c
	$(CC) $(CFLAGS) -c -o $(SRC_DIR)/shell_tokenizer.o $(SRC_DIR)/shell_tokenizer.c
	$(CC) $(CFLAGS) -c -o $(SRC_DIR)/shell_processor.o $(SRC_DIR)/shell_processor.c
	ar rcs $@ $(SRC_DIR)/shell_tokenizer.o $(SRC_DIR)/shell_processor.o
	rm -f $(SRC_DIR)/*.o

# Clean
clean:
	rm -f $(TESTS_DIR)/tokenizer_test $(TESTS_DIR)/tokenizer_ext_test $(TESTS_DIR)/transform_test
	rm -f $(SRC_DIR)/*.o
	rm -f libshellsplit.a

# Test
test: $(TESTS_DIR)/tokenizer_test $(TESTS_DIR)/transform_test
	@echo "Running shell tokenizer tests..."
	@./$(TESTS_DIR)/tokenizer_test "cat xx | less -G > rsr" > /dev/null 2>&1 && echo "  [PASS] Basic tokenization" || echo "  [FAIL] Basic tokenization"
	@./$(TESTS_DIR)/tokenizer_test "cat file.txt | grep pattern | sort | uniq" > /dev/null 2>&1 && echo "  [PASS] Pipeline splitting" || echo "  [FAIL] Pipeline splitting"
	@./$(TESTS_DIR)/tokenizer_test "grep \$$PATTERN *.log" > /dev/null 2>&1 && echo "  [PASS] Variable handling" || echo "  [FAIL] Variable handling"
	@echo ""
	@echo "Running transform tests..."
	@./$(TESTS_DIR)/transform_test > /dev/null 2>&1 && echo "  [PASS] Transform pass" || echo "  [FAIL] Transform pass"
	@echo "Done."

.PHONY: all clean test
