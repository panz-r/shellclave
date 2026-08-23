#include "crc32.h"

uint32_t st_crc32_update(const void *data, size_t length, uint32_t previous) {
  uint32_t crc = previous ^ UINT32_C(0xffffffff);
  const unsigned char *bytes = data;
  for (size_t i = 0; i < length; i++) {
    crc ^= bytes[i];
    for (unsigned bit = 0; bit < 8; bit++)
      crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & (0u - (crc & 1u)));
  }
  return crc ^ UINT32_C(0xffffffff);
}
