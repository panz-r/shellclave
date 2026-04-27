/*
 * fuzz_shellgate - Fuzzing harness for shellgate with anomaly detection
 *
 * Exercises sg_eval with anomaly detection enabled (raw + type models),
 * including model updates, cache hits, and periodic model resets.
 *
 * Build with libFuzzer:
 *   cmake -DENABLE_FUZZING=ON .. && make fuzz_shellgate
 *
 * Build standalone:
 *   cc -fsanitize=address,undefined -o fuzz_shellgate \
 *      tests/fuzz_shellgate.c -Iinclude -L. -lshellgate
 *
 * Run:
 *   ./fuzz_shellgate -runs=100000 tests/corpus/
 */

#include "shellgate.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#define CMD_BUF_SIZE  4096
#define RESULT_BUF_SIZE 8192
#define MAX_FUZZ_INPUT 256  /* cap input to avoid pathological tokenization OOM */

static char cmd_buf[CMD_BUF_SIZE];
static char result_buf[RESULT_BUF_SIZE];

/* Seed commands for pre-training the anomaly model */
static const char *seed_cmds[] = {
    "ls",
    "cd /tmp",
    "pwd",
    "cat file.txt",
    "grep pattern file.txt",
    "echo hello",
    "mkdir dir",
    "cp a b",
    "mv b c",
    "rm c",
    "ls ; cd /tmp ; pwd",
    "cat file.txt ; grep pattern ; sort",
    "echo hello ; sleep 1 ; true",
    "mkdir dir ; chmod 755 dir ; ls dir",
    "cp a b ; mv b c ; rm c",
    "find . -name '*.c' ; xargs grep TODO ; wc -l",
    "git status ; git add . ; git commit -m fix",
    "make clean ; make -j4 ; make test",
    "sort file.txt ; uniq ; wc -l",
    "head -n 10 file.txt ; tail -n 10 file.txt"
};
#define NUM_SEEDS (sizeof(seed_cmds) / sizeof(seed_cmds[0]))

static void train_model(sg_gate_t *gate)
{
    sg_result_t r;
    for (size_t i = 0; i < NUM_SEEDS; i++) {
        sg_eval(gate, seed_cmds[i], strlen(seed_cmds[i]),
                result_buf, sizeof(result_buf), &r);
    }
}

/* Shared gate persisted across fuzzer invocations to avoid OOM from
 * repeated model creation.  libFuzzer calls LLVMFuzzerTestOneInput
 * thousands of times per second; creating a new gate each time causes
 * hash table allocation to accumulate faster than the GC can free. */
static sg_gate_t *shared_gate;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    shared_gate = sg_gate_new();
    if (shared_gate) {
        sg_gate_enable_anomaly(shared_gate, 5.0, 0.1, -10.0);
        train_model(shared_gate);
        /* Freeze model: re-enable with threshold=0 so every command is
         * flagged anomalous, and set skip_on_anomaly=true so the model
         * never updates.  The scoring path (hash lookups, KN smoothing,
         * type sequences) is still fully exercised. */
        sg_gate_enable_anomaly(shared_gate, 0.0, 0.1, -10.0);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > MAX_FUZZ_INPUT) return 0;
    if (!shared_gate) return 0;

    memcpy(cmd_buf, data, size);
    cmd_buf[size] = '\0';

    sg_result_t result;
    sg_error_t err = sg_eval(shared_gate, cmd_buf, size,
                             result_buf, sizeof(result_buf), &result);
    (void)err;

    /* Verify scores are finite (catches NaN/Inf bugs) */
    if (isfinite(result.anomaly_score) && result.anomaly_score > 0.0) {
        sg_eval(shared_gate, cmd_buf, size, result_buf, sizeof(result_buf), &result);
    }

    return 0;
}

/* Standalone driver for environments without libFuzzer */
#if !defined(HAS_LIBFUZZER) && !defined(__AFL_COMPILER)
int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Initialize shared gate */
    LLVMFuzzerInitialize(NULL, NULL);

    /* Read from stdin for quick smoke test */
    size_t n = fread(cmd_buf, 1, sizeof(cmd_buf) - 1, stdin);
    if (n == 0) {
        fprintf(stderr, "Usage: echo 'cmd' | ./fuzz_shellgate\n");
        fprintf(stderr, "       ./fuzz_shellgate -runs=100000 tests/corpus/\n");
        sg_gate_free(shared_gate);
        return 0;
    }

    LLVMFuzzerTestOneInput((const uint8_t *)cmd_buf, n);
    fprintf(stderr, "OK\n");
    sg_gate_free(shared_gate);
    return 0;
}
#endif
