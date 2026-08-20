#ifndef SHELLTYPE_METADATA_H
#define SHELLTYPE_METADATA_H

#include "shelltype.h"

#include <stddef.h>
#include <string.h>
#include <strings.h>

/* Closed metadata vocabulary for parametrized policy transitions. Metadata is
 * deliberately not part of st_token_type_t: joins and compatibility operate
 * on the base type only. Concrete token bytes are never stored as metadata. */
typedef enum {
  ST_META_NONE = 0,
  ST_META_SIZE_K,
  ST_META_SIZE_M,
  ST_META_SIZE_G,
  ST_META_SIZE_T,
  ST_META_SIZE_KI,
  ST_META_SIZE_MI,
  ST_META_SIZE_GI,
  ST_META_SIZE_TI,
  ST_META_SIZE_KB,
  ST_META_SIZE_MB,
  ST_META_SIZE_GB,
  ST_META_SIZE_TB,
  ST_META_SIZE_B,
  ST_META_SIZE_BYTES,
  ST_META_SIZE_KIB,
  ST_META_SIZE_MIB,
  ST_META_SIZE_GIB,
  ST_META_SIZE_TIB,
  ST_META_UUID_V4,
  ST_META_UUID_V5,
  ST_META_SEMVER_MAJOR,
  ST_META_SEMVER_MINOR,
  ST_META_SEMVER_PATCH,
  ST_META_SEMVER_ANY,
  ST_META_TIMESTAMP_DATE,
  ST_META_TIMESTAMP_TIME,
  ST_META_TIMESTAMP_DATETIME,
  ST_META_SHA_SHORT,
  ST_META_SHA_40,
  ST_META_SHA_64,
  ST_META_FINGERPRINT_SHA256,
  ST_META_FINGERPRINT_MD5,
  ST_META_DURATION_NS,
  ST_META_DURATION_US,
  ST_META_DURATION_MS,
  ST_META_DURATION_S,
  ST_META_DURATION_M,
  ST_META_DURATION_H,
  ST_META_DURATION_D,
  ST_META_DURATION_W,
  ST_META_RANGE_STEP,
  ST_META_PERM_BITS,
} st_metadata_id_t;

typedef struct {
  st_metadata_id_t id;
  st_token_type_t type;
  const char *name;
  const char *alias;
} st_metadata_entry_t;

static const st_metadata_entry_t st_metadata_entries[] = {
    {ST_META_SIZE_K, ST_TYPE_SIZE, "K", NULL},
    {ST_META_SIZE_M, ST_TYPE_SIZE, "M", NULL},
    {ST_META_SIZE_G, ST_TYPE_SIZE, "G", NULL},
    {ST_META_SIZE_T, ST_TYPE_SIZE, "T", NULL},
    {ST_META_SIZE_KI, ST_TYPE_SIZE, "Ki", NULL},
    {ST_META_SIZE_MI, ST_TYPE_SIZE, "Mi", NULL},
    {ST_META_SIZE_GI, ST_TYPE_SIZE, "Gi", NULL},
    {ST_META_SIZE_TI, ST_TYPE_SIZE, "Ti", NULL},
    {ST_META_SIZE_KB, ST_TYPE_SIZE, "KB", NULL},
    {ST_META_SIZE_MB, ST_TYPE_SIZE, "MB", NULL},
    {ST_META_SIZE_GB, ST_TYPE_SIZE, "GB", NULL},
    {ST_META_SIZE_TB, ST_TYPE_SIZE, "TB", NULL},
    {ST_META_SIZE_B, ST_TYPE_SIZE, "B", "b"},
    {ST_META_SIZE_BYTES, ST_TYPE_SIZE, "bytes", NULL},
    {ST_META_SIZE_KIB, ST_TYPE_SIZE, "KiB", NULL},
    {ST_META_SIZE_MIB, ST_TYPE_SIZE, "MiB", NULL},
    {ST_META_SIZE_GIB, ST_TYPE_SIZE, "GiB", NULL},
    {ST_META_SIZE_TIB, ST_TYPE_SIZE, "TiB", NULL},
    {ST_META_UUID_V4, ST_TYPE_UUID, "v4", "4"},
    {ST_META_UUID_V5, ST_TYPE_UUID, "v5", "5"},
    {ST_META_SEMVER_MAJOR, ST_TYPE_SEMVER, "major", NULL},
    {ST_META_SEMVER_MINOR, ST_TYPE_SEMVER, "minor", NULL},
    {ST_META_SEMVER_PATCH, ST_TYPE_SEMVER, "patch", NULL},
    {ST_META_SEMVER_ANY, ST_TYPE_SEMVER, "*", NULL},
    {ST_META_TIMESTAMP_DATE, ST_TYPE_TIMESTAMP, "date", NULL},
    {ST_META_TIMESTAMP_TIME, ST_TYPE_TIMESTAMP, "time", NULL},
    {ST_META_TIMESTAMP_DATETIME, ST_TYPE_TIMESTAMP, "datetime", NULL},
    {ST_META_SHA_SHORT, ST_TYPE_SHA, "short", NULL},
    {ST_META_SHA_40, ST_TYPE_SHA, "40", NULL},
    {ST_META_SHA_64, ST_TYPE_SHA, "64", NULL},
    {ST_META_FINGERPRINT_SHA256, ST_TYPE_FINGERPRINT, "sha256", NULL},
    {ST_META_FINGERPRINT_MD5, ST_TYPE_FINGERPRINT, "md5", NULL},
    {ST_META_DURATION_NS, ST_TYPE_DURATION, "ns", NULL},
    {ST_META_DURATION_US, ST_TYPE_DURATION, "us", NULL},
    {ST_META_DURATION_MS, ST_TYPE_DURATION, "ms", NULL},
    {ST_META_DURATION_S, ST_TYPE_DURATION, "s", NULL},
    {ST_META_DURATION_M, ST_TYPE_DURATION, "m", NULL},
    {ST_META_DURATION_H, ST_TYPE_DURATION, "h", NULL},
    {ST_META_DURATION_D, ST_TYPE_DURATION, "d", NULL},
    {ST_META_DURATION_W, ST_TYPE_DURATION, "w", NULL},
    {ST_META_RANGE_STEP, ST_TYPE_RANGE, "step", NULL},
    {ST_META_PERM_BITS, ST_TYPE_PERM_OCTAL, "bits", NULL},
};

static inline const st_metadata_entry_t *
st_metadata_lookup(st_token_type_t type, const char *name) {
  if (!name || *name == '\0')
    return NULL;
  for (size_t i = 0;
       i < sizeof(st_metadata_entries) / sizeof(st_metadata_entries[0]); i++) {
    const st_metadata_entry_t *entry = &st_metadata_entries[i];
    if (entry->type != type)
      continue;
    if (strcasecmp(name, entry->name) == 0 ||
        (entry->alias && strcasecmp(name, entry->alias) == 0))
      return entry;
  }
  return NULL;
}

static inline bool st_type_supports_metadata(st_token_type_t type) {
  for (size_t i = 0;
       i < sizeof(st_metadata_entries) / sizeof(st_metadata_entries[0]); i++)
    if (st_metadata_entries[i].type == type)
      return true;
  return false;
}

static inline const st_metadata_entry_t *
st_wildcard_metadata(const char *wild_text, st_token_type_t wild_type) {
  if (!wild_text || !st_type_supports_metadata(wild_type))
    return NULL;
  const char *symbol = st_type_symbol[wild_type];
  size_t symbol_len = strlen(symbol);
  if (strncmp(wild_text, symbol, symbol_len) != 0 ||
      wild_text[symbol_len] != '.')
    return NULL;
  return st_metadata_lookup(wild_type, wild_text + symbol_len + 1);
}

#endif
