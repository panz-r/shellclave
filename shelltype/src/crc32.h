#ifndef SHELLTYPE_CRC32_H
#define SHELLTYPE_CRC32_H

#include <stddef.h>
#include <stdint.h>

uint32_t st_crc32_update(const void *data, size_t length, uint32_t previous);

#endif
