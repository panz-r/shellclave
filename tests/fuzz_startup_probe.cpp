/* Only the watchdog regression runs this executable. It hangs before
 * libFuzzer has installed its per-input timeout, never calling a library API.
 */
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  const char *ready = std::getenv("SHELLCLAVE_STARTUP_PROBE_READY");
  if (!ready)
    return 1;
  FILE *stream = std::fopen(ready, "w");
  if (!stream)
    return 1;
  if (std::fputs("ready", stream) < 0) {
    std::fclose(stream);
    return 1;
  }
  if (std::fclose(stream) != 0)
    return 1;
  for (;;)
    pause();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *, size_t) { return 0; }
