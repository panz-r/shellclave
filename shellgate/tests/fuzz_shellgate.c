#include "shellgate.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static char cmd_buf[4096];
static char result_buf[8192];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size >= sizeof(cmd_buf)) {
        size = sizeof(cmd_buf) - 1;
    }
    memcpy(cmd_buf, data, size);
    cmd_buf[size] = '\0';

    sg_gate_t *gate = sg_gate_new();
    if (!gate) return 0;

    sg_result_t result;
    sg_error_t err = sg_eval(gate, cmd_buf, size, result_buf, sizeof(result_buf), &result);
    (void)err;
    (void)result;

    sg_gate_free(gate);
    return 0;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    fprintf(stderr, "Standalone fuzz driver - use libFuzzer for actual fuzzing\n");
    fprintf(stderr, "Usage: ./fuzz_shellgate -runs=<N> [corpus_dir]\n");
    return 0;
}