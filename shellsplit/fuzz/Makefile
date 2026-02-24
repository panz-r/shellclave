# LibFuzzer harness Makefile for shellsplit
# Requires: libfuzzer-21-dev (clang with fuzzing support)

CXX = clang++
CC = clang

# Sanitizer flags - use fuzzer only for long runs (no ASan to avoid stopping on bugs)
# For bug-finding, use: make fuzzer-asan
CXXFLAGS = -fsanitize=fuzzer -I../include -g -O1 -fno-omit-frame-pointer -std=c++11
CFLAGS = -fsanitize=fuzzer -I../include -g -O1 -fno-omit-frame-pointer

# Library sources - all shellsplit modules
LIB_SRC = ../src/shell_tokenizer.c ../src/shell_tokenizer_full.c ../src/shell_transform.c ../src/shell_processor.c
LIB_OBJS = ../src/shell_tokenizer.o ../src/shell_tokenizer_full.o ../src/shell_transform.o ../src/shell_processor.o

FUZZERS = tokenizer_fuzzer

# Default target
all: setup-dirs $(FUZZERS)

# Set up required directories
setup-dirs:
	@mkdir -p crashes corpus/interesting

# Build tokenizer fuzzer
tokenizer_fuzzer: tokenizer_fuzzer.cpp $(LIB_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIB_OBJS) -lm

# Build library objects
../src/shell_tokenizer.o: ../src/shell_tokenizer.c ../include/shell_tokenizer.h
	$(CC) $(CFLAGS) -c $< -o $@

../src/shell_tokenizer_full.o: ../src/shell_tokenizer_full.c ../include/shell_tokenizer_full.h
	$(CC) $(CFLAGS) -c $< -o $@

../src/shell_transform.o: ../src/shell_transform.c ../include/shell_transform.h
	$(CC) $(CFLAGS) -c $< -o $@

../src/shell_processor.o: ../src/shell_processor.c ../include/shell_processor.h
	$(CC) $(CFLAGS) -c $< -o $@

# Run fuzzing with corpus
run: tokenizer_fuzzer
	./tokenizer_fuzzer corpus/seed -merge=corpus/interesting -artifact_prefix=crashes/ -max_len=8192 -jobs=4 -workers=4

# Run with dictionary
run-dict: tokenizer_fuzzer
	./tokenizer_fuzzer corpus/seed -merge=corpus/interesting -artifact_prefix=crashes/ -dict=cmd_dict.txt -max_len=8192 -jobs=4 -workers=4

# Run with timeout
run-10m: tokenizer_fuzzer
	timeout 600 ./tokenizer_fuzzer corpus/seed -merge=corpus/interesting -artifact_prefix=crashes/ -max_len=8192 -jobs=4 -workers=4

# Run with timeout (4 hours)
run-4h: tokenizer_fuzzer
	timeout 14400 ./tokenizer_fuzzer corpus/seed -merge=corpus/interesting -artifact_prefix=crashes/ -max_len=8192 -jobs=4 -workers=4

# Minimize corpus
minimize: tokenizer_fuzzer
	./tokenizer_fuzzer corpus/interesting -merge=1 -reduce_inputs_to=1000 corpus/minimized

# Clean generated files
clean:
	rm -f $(FUZZERS) $(LIB_OBJS)

# Clear crash artifacts
clean-crashes:
	rm -rf crashes/*

# Replay crashes - useful for regression testing
# Usage: make replay-crashes CRASHES="crashes/tokenizer_abc123"
replay-crashes: tokenizer_fuzzer
	@if [ -z "$(CRASHES)" ]; then \
		echo "Error: Please specify CRASHES='file1 file2 ...'"; \
		echo "Example: make replay-crashes CRASHES='crashes/tokenizer_*'"; \
		exit 1; \
	fi
	@for crash in $(CRASHES); do \
		echo "=== Replaying $$crash ==="; \
		./tokenizer_fuzzer $$crash -runs=1; \
	done

# Replay all crashes found
replay-all-crashes: tokenizer_fuzzer
	@if ls crashes/tokenizer_* 1>/dev/null 2>&1; then \
		for crash in crashes/tokenizer_*; do \
			echo "=== Replaying $$crash ==="; \
			./tokenizer_fuzzer $$crash -runs=1; \
		done; \
	else \
		echo "No crashes found in crashes/"; \
	fi

# List crashes found
list-crashes:
	@echo "Crash files:"; ls -1 crashes/ 2>/dev/null | wc -l
	@find crashes -type f 2>/dev/null | wc -l

.PHONY: all clean run run-dict run-10m run-4h minimize replay-crashes replay-all-crashes list-crashes setup-dirs
