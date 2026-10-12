#define _POSIX_C_SOURCE 200809L
#include "metadata.h"
#include "shell_netstring.h"
#include "shelltype.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"
#include "netpattern.h"

#ifdef SHELLTYPE_TEST_ALLOCATOR
static _Thread_local size_t cpl_parse_work;
size_t st_test_cpl_parse_work(void) { return cpl_parse_work; }

/* Include actual length-scan work, not just parser iterations: a suffix
 * strlen inside an escape/word loop must fail the linear-work regression. */
static SHELL_NONNULL(1) size_t cpl_test_strlen(const char *text) {
  size_t length = strlen(text);
  cpl_parse_work += length + 1;
  return length;
}
#define strlen cpl_test_strlen
#define CPL_PARSE_WORK(bytes) (cpl_parse_work += (bytes))
#else
#define CPL_PARSE_WORK(bytes) ((void)0)
#endif

typedef struct {
  char *text;
  size_t length;
  bool literal;
  /* A CPL compound contains one unquoted `{#type}` marker. `text` is the
   * flattened decoded spelling; the marker offsets preserve quoted literal
   * fragment boundaries until it is encoded as a canonical compound record. */
  bool compound;
  size_t capture_offset;
  size_t capture_length;
} cpl_word_t;

static void free_words(cpl_word_t *words, size_t count) {
  for (size_t i = 0; i < count; i++)
    free(words[i].text);
  free(words);
}

/* Scratch holds three independently bounded components, two structural braces
 * and a terminator. component_start <= *used and the active component has at
 * most ST_MAX_TOKEN_LEN - 1 decoded bytes. These helpers enforce that component
 * limit on untrusted CPL; parse_cpl alone advances structural boundaries. */
static SHELL_NONNULL(1, 2) bool append_cpl_byte(char *out, size_t *used,
                                                size_t component_start,
                                                unsigned char value) {
  if (*used - component_start == ST_MAX_TOKEN_LEN - 1)
    return false;
  out[(*used)++] = (char)value;
  return true;
}

static SHELL_NONNULL(1, 2) bool append_utf8(char *out, size_t *used,
                                            size_t component_start,
                                            uint32_t value) {
  if (value == 0 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
    return false;
  size_t width = value <= 0x7f     ? 1
                 : value <= 0x7ff  ? 2
                 : value <= 0xffff ? 3
                                   : 4;
  if (width > ST_MAX_TOKEN_LEN - 1 - (*used - component_start))
    return false;
  if (value <= 0x7f) {
    out[(*used)++] = (char)value;
  } else if (value <= 0x7ff) {
    out[(*used)++] = (char)(0xc0 | (value >> 6));
    out[(*used)++] = (char)(0x80 | (value & 0x3f));
  } else if (value <= 0xffff) {
    out[(*used)++] = (char)(0xe0 | (value >> 12));
    out[(*used)++] = (char)(0x80 | ((value >> 6) & 0x3f));
    out[(*used)++] = (char)(0x80 | (value & 0x3f));
  } else {
    out[(*used)++] = (char)(0xf0 | (value >> 18));
    out[(*used)++] = (char)(0x80 | ((value >> 12) & 0x3f));
    out[(*used)++] = (char)(0x80 | ((value >> 6) & 0x3f));
    out[(*used)++] = (char)(0x80 | (value & 0x3f));
  }
  return true;
}

/* text supplies four readable bytes; parse_cpl checks the source boundary. */
static SHELL_NONNULL(1, 2) bool hex4(const char *text, uint32_t *value) {
  uint32_t result = 0;
  for (size_t i = 0; i < 4; i++) {
    CPL_PARSE_WORK(1);
    unsigned char c = (unsigned char)text[i];
    unsigned digit;
    if (c >= '0' && c <= '9')
      digit = c - '0';
    else if (c >= 'a' && c <= 'f')
      digit = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
      digit = c - 'A' + 10;
    else
      return false;
    result = result * 16 + digit;
  }
  *value = result;
  return true;
}

static int hex_digit(unsigned char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static char *bytes_dup(const char *data, size_t length) {
  char *copy = malloc(length + 1);
  if (!copy)
    return NULL;
  if (length)
    memcpy(copy, data, length);
  copy[length] = '\0';
  return copy;
}

static size_t component_length(const char *text, size_t explicit_length) {
  if (!text)
    return 0;
  return explicit_length || text[0] == '\0' ? explicit_length : strlen(text);
}

/* cpl is a complete NUL-terminated string. This boundary validates CPL syntax
 * and resource limits; its outputs are unpublished until parsing succeeds.
 * Decode each word into bounded scratch, retaining only its exact spelling.
 * Geometric metadata growth keeps cumulative allocation/copy work linear. */
static SHELL_NONNULL(1, 2, 3) st_error_t
    parse_cpl(const char *cpl, cpl_word_t **out_words, size_t *out_count) {
#ifdef SHELLTYPE_TEST_ALLOCATOR
  cpl_parse_work = 0;
#endif
  *out_words = NULL;
  *out_count = 0;
  size_t length = strlen(cpl);
  if (length == 0 || length >= ST_MAX_CPL_LEN)
    return ST_ERR_INVALID;
  size_t offset = 0, count = 0, capacity = 0;
  cpl_word_t *words = NULL;
  char word[3 * (ST_MAX_TOKEN_LEN - 1) + 3];
  while (offset < length) {
    CPL_PARSE_WORK(1);
    while (offset < length && cpl[offset] == ' ') {
      CPL_PARSE_WORK(1);
      offset++;
    }
    if (offset == length)
      break;
    if (count == ST_MAX_CMD_TOKENS)
      goto invalid;
    bool saw_quoted = false;
    bool saw_unquoted = false;
    bool compound = false;
    bool open_capture = false;
    size_t capture_offset = 0;
    size_t capture_length = 0;
    size_t used = 0;
    size_t component_start = 0;
    while (offset < length && cpl[offset] != ' ') {
      CPL_PARSE_WORK(1);
      if (cpl[offset] != '"') {
        unsigned char c = (unsigned char)cpl[offset++];
        if (c < 0x20 || c == 0x7f || c == '\\')
          goto invalid;
        saw_unquoted = true;
        if (c == '{') {
          if (compound || open_capture)
            goto invalid;
          open_capture = true;
          word[used++] = '{';
          capture_offset = component_start = used;
          continue;
        } else if (c == '}') {
          if (!open_capture)
            goto invalid;
          open_capture = false;
          compound = true;
          capture_length = used - capture_offset;
          word[used++] = '}';
          component_start = used;
          continue;
        }
        if (!append_cpl_byte(word, &used, component_start, c))
          goto invalid;
        continue;
      }

      saw_quoted = true;
      offset++;
      bool closed = false;
      while (offset < length) {
        CPL_PARSE_WORK(1);
        unsigned char c = (unsigned char)cpl[offset++];
        if (c == '"') {
          closed = true;
          break;
        }
        if (c < 0x20)
          goto invalid;
        if (c != '\\') {
          if (!append_cpl_byte(word, &used, component_start, c))
            goto invalid;
          continue;
        }
        if (offset == length)
          goto invalid;
        char escape = cpl[offset++];
        switch (escape) {
        case '"':
          c = '"';
          break;
        case '\\':
          c = '\\';
          break;
        case 'b':
          c = '\b';
          break;
        case 'f':
          c = '\f';
          break;
        case 'n':
          c = '\n';
          break;
        case 'r':
          c = '\r';
          break;
        case 't':
          c = '\t';
          break;
        case 'x': {
          if (length - offset < 2)
            goto invalid;
          int high = hex_digit((unsigned char)cpl[offset]);
          int low = hex_digit((unsigned char)cpl[offset + 1]);
          if (high < 0 || low < 0)
            goto invalid;
          offset += 2;
          c = (unsigned char)((high << 4) | low);
          break;
        }
        case 'u': {
          uint32_t value;
          if (length - offset < 4 || !hex4(cpl + offset, &value))
            goto invalid;
          offset += 4;
          if (value >= 0xd800 && value <= 0xdbff) {
            uint32_t low;
            if (length - offset < 6 || cpl[offset] != '\\' ||
                cpl[offset + 1] != 'u' || !hex4(cpl + offset + 2, &low) ||
                low < 0xdc00 || low > 0xdfff)
              goto invalid;
            offset += 6;
            value = 0x10000 + ((value - 0xd800) << 10) + (low - 0xdc00);
          }
          if (!append_utf8(word, &used, component_start, value))
            goto invalid;
          continue;
        }
        default:
          goto invalid;
        }
        if (!append_cpl_byte(word, &used, component_start, c))
          goto invalid;
      }
      if (!closed)
        goto invalid;
    }
    if ((used == 0 && !saw_quoted) || open_capture ||
        (saw_quoted && saw_unquoted && !compound))
      goto invalid;
    word[used] = '\0';
    if (count == capacity) {
      /* The 128-word limit bounds these power-of-two capacities. */
      size_t next_capacity = capacity ? capacity * 2 : 4;
      cpl_word_t *grown = realloc(words, next_capacity * sizeof(*words));
      if (!grown)
        goto memory;
      words = grown;
      capacity = next_capacity;
    }
    char *owned_word = bytes_dup(word, used);
    if (!owned_word)
      goto memory;
    words[count++] = (cpl_word_t){.text = owned_word,
                                  .length = used,
                                  .literal = !saw_unquoted,
                                  .compound = compound,
                                  .capture_offset = capture_offset,
                                  .capture_length = capture_length};
  }
  if (count == 0)
    goto invalid;
  *out_words = words;
  *out_count = count;
  return ST_OK;
invalid:
  free_words(words, count);
  return ST_ERR_INVALID;
memory:
  free_words(words, count);
  return ST_ERR_MEMORY;
}

static st_token_type_t wildcard_type(const char *text) {
  if (strcmp(text, "*") == 0)
    return ST_TYPE_ANY;
  for (int value = 1; value < ST_TYPE_COUNT; value++) {
    st_token_type_t type = (st_token_type_t)value;
    const char *symbol = st_type_symbol[type];
    size_t length = strlen(symbol);
    if (strcmp(text, symbol) == 0)
      return type;
    if (symbol[0] == '#' && strncmp(text, symbol, length) == 0 &&
        text[length] == '.' && st_metadata_lookup(type, text + length + 1))
      return type;
  }
  return ST_TYPE_LITERAL;
}

static bool wildcard_spelling(const char *text) {
  return wildcard_type(text) != ST_TYPE_LITERAL;
}

static const char *canonical_wildcard(const char *text,
                                      st_token_type_t *out_type,
                                      char buffer[ST_MAX_TOKEN_LEN]) {
  st_token_type_t type = wildcard_type(text);
  if (type == ST_TYPE_LITERAL)
    return NULL;
  *out_type = type;
  const char *symbol = st_type_symbol[type];
  size_t symbol_length = strlen(symbol);
  if (text[symbol_length] != '.')
    return symbol;
  const st_metadata_entry_t *metadata =
      st_metadata_lookup(type, text + symbol_length + 1);
  if (!metadata)
    return NULL;
  int written =
      snprintf(buffer, ST_MAX_TOKEN_LEN, "%s.%s", symbol, metadata->name);
  return written > 0 && written < ST_MAX_TOKEN_LEN ? buffer : NULL;
}

/* Explicit-length token views are not required to carry a trailing NUL. Keep
 * the wildcard parser deliberately C-string based, but give it a bounded
 * local spelling rather than ever scanning caller-owned bytes. */
static const char *canonical_wildcard_view(const char *text, size_t length,
                                           st_token_type_t *out_type,
                                           char buffer[ST_MAX_TOKEN_LEN]) {
  if (!text || length >= ST_MAX_TOKEN_LEN || memchr(text, '\0', length))
    return NULL;
  char spelling[ST_MAX_TOKEN_LEN];
  if (length)
    memcpy(spelling, text, length);
  spelling[length] = '\0';
  return canonical_wildcard(spelling, out_type, buffer);
}

static st_error_t encode_tagged_record(char tag, const char *value,
                                       size_t value_length, char **out,
                                       size_t *out_length) {
  size_t tag_length = 0, value_record_length = 0;
  if (shell_netstring_encoded_length(1, &tag_length) != SHELL_NETSTRING_OK ||
      shell_netstring_encoded_length(value_length, &value_record_length) !=
          SHELL_NETSTRING_OK ||
      tag_length > SIZE_MAX - value_record_length)
    return ST_ERR_LIMIT;
  size_t payload_length = tag_length + value_record_length;
  size_t total = 0;
  if (shell_netstring_encoded_length(payload_length, &total) !=
      SHELL_NETSTRING_OK)
    return ST_ERR_LIMIT;
  char *record = malloc(total + 1);
  if (!record)
    return ST_ERR_MEMORY;
  size_t used = 0, written = 0;
  if (shell_netstring_write_prefix(record, total, payload_length, &used) !=
          SHELL_NETSTRING_OK ||
      shell_netstring_write(record + used, total - used, &tag, 1, &written) !=
          SHELL_NETSTRING_OK) {
    free(record);
    return ST_ERR_LIMIT;
  }
  used += written;
  if (shell_netstring_write(record + used, total - used, value, value_length,
                            &written) != SHELL_NETSTRING_OK) {
    free(record);
    return ST_ERR_LIMIT;
  }
  used += written;
  record[used++] = ',';
  record[used] = '\0';
  *out = record;
  *out_length = used;
  return ST_OK;
}

st_error_t st_netpattern_encode_owned(const st_token_t *tokens, size_t count,
                                      st_netpattern_t *out_netpattern) {
  *out_netpattern = (st_netpattern_t){0};
  if (!tokens || count == 0 || count > ST_MAX_CMD_TOKENS)
    return ST_ERR_INVALID;

  char *records[ST_MAX_CMD_TOKENS] = {0};
  size_t record_lengths[ST_MAX_CMD_TOKENS] = {0};
  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    st_error_t error = ST_OK;
    if (tokens[i].compound) {
      size_t prefix_length =
          component_length(tokens[i].prefix, tokens[i].prefix_length);
      size_t capture_length =
          component_length(tokens[i].capture, tokens[i].capture_length);
      size_t suffix_length =
          component_length(tokens[i].suffix, tokens[i].suffix_length);
      if (!tokens[i].prefix || !tokens[i].capture || !tokens[i].suffix ||
          tokens[i].capture_type <= ST_TYPE_LITERAL ||
          tokens[i].capture_type >= ST_TYPE_COUNT ||
          (prefix_length == 0 && suffix_length == 0)) {
        error = ST_ERR_INVALID;
      } else if (prefix_length >= ST_MAX_TOKEN_LEN ||
                 capture_length >= ST_MAX_TOKEN_LEN ||
                 suffix_length >= ST_MAX_TOKEN_LEN) {
        error = ST_ERR_LIMIT;
      } else {
        char canonical[ST_MAX_TOKEN_LEN];
        st_token_type_t type = ST_TYPE_LITERAL;
        const char *wild = canonical_wildcard_view(
            tokens[i].capture, capture_length, &type, canonical);
        if (!wild || type != tokens[i].capture_type)
          error = ST_ERR_FORMAT;
        char *parts[3] = {0};
        size_t part_lengths[3] = {0};
        size_t part_count = 0, nested_length = 0;
        if (error == ST_OK && prefix_length) {
          error = encode_tagged_record('L', tokens[i].prefix, prefix_length,
                                       &parts[part_count],
                                       &part_lengths[part_count]);
          if (error == ST_OK)
            part_count++;
        }
        if (error == ST_OK) {
          error =
              encode_tagged_record('T', wild, strlen(wild), &parts[part_count],
                                   &part_lengths[part_count]);
          if (error == ST_OK)
            part_count++;
        }
        if (error == ST_OK && suffix_length) {
          error = encode_tagged_record('L', tokens[i].suffix, suffix_length,
                                       &parts[part_count],
                                       &part_lengths[part_count]);
          if (error == ST_OK)
            part_count++;
        }
        for (size_t p = 0; p < part_count; p++) {
          if (nested_length > SIZE_MAX - part_lengths[p]) {
            error = ST_ERR_LIMIT;
            break;
          }
          nested_length += part_lengths[p];
        }
        if (nested_length == SIZE_MAX)
          error = ST_ERR_LIMIT;
        char *nested = error == ST_OK ? malloc(nested_length + 1) : NULL;
        if (error == ST_OK && !nested)
          error = ST_ERR_MEMORY;
        size_t used = 0;
        if (nested) {
          for (size_t p = 0; p < part_count; p++) {
            memcpy(nested + used, parts[p], part_lengths[p]);
            used += part_lengths[p];
          }
          nested[used] = '\0';
          error = encode_tagged_record('C', nested, nested_length, &records[i],
                                       &record_lengths[i]);
        }
        free(nested);
        for (size_t p = 0; p < part_count; p++)
          free(parts[p]);
      }
    } else {
      if (!tokens[i].text) {
        error = ST_ERR_INVALID;
      } else {
        size_t text_length = tokens[i].text_length;
        if (text_length == 0 && tokens[i].text[0] != '\0')
          text_length = strlen(tokens[i].text);
        if (text_length >= ST_MAX_TOKEN_LEN)
          error = ST_ERR_LIMIT;
        else {
          char canonical[ST_MAX_TOKEN_LEN];
          st_token_type_t type = ST_TYPE_LITERAL;
          const char *wild =
              tokens[i].type == ST_TYPE_LITERAL
                  ? NULL
                  : canonical_wildcard_view(tokens[i].text, text_length, &type,
                                            canonical);
          bool typed = tokens[i].type != ST_TYPE_LITERAL && wild != NULL;
          if (typed && type != tokens[i].type)
            error = ST_ERR_FORMAT;
          else
            error = encode_tagged_record(typed ? 'T' : 'L',
                                         typed ? wild : tokens[i].text,
                                         typed ? strlen(wild) : text_length,
                                         &records[i], &record_lengths[i]);
        }
      }
    }
    if (error != ST_OK) {
      for (size_t j = 0; j <= i; j++)
        free(records[j]);
      return error;
    }
    if (total > SIZE_MAX - record_lengths[i]) {
      for (size_t j = 0; j <= i; j++)
        free(records[j]);
      return ST_ERR_LIMIT;
    }
    total += record_lengths[i];
  }
  if (total >= ST_MAX_NETPATTERN_LEN) {
    for (size_t i = 0; i < count; i++)
      free(records[i]);
    return ST_ERR_LIMIT;
  }
  char *encoded = malloc(total + 1);
  if (!encoded) {
    for (size_t i = 0; i < count; i++)
      free(records[i]);
    return ST_ERR_MEMORY;
  }
  size_t used = 0;
  for (size_t i = 0; i < count; i++) {
    memcpy(encoded + used, records[i], record_lengths[i]);
    used += record_lengths[i];
    free(records[i]);
  }
  encoded[used] = '\0';
  *out_netpattern = (st_netpattern_t){.data = encoded, .length = used};
  return ST_OK;
}

void st_netpattern_free(st_netpattern_t *pattern) {
  if (!pattern)
    return;
  free(pattern->data);
  *pattern = (st_netpattern_t){0};
}

st_error_t st_netpattern_from_cpl_owned(const char *cpl,
                                        st_netpattern_t *out_netpattern) {
  cpl_word_t *words = NULL;
  size_t count = 0;
  st_error_t error = parse_cpl(cpl, &words, &count);
  if (error != ST_OK)
    return error;
  st_token_t tokens[ST_MAX_CMD_TOKENS];
  memset(tokens, 0, sizeof(tokens));
  for (size_t i = 0; i < count; i++) {
    if (words[i].compound) {
      size_t prefix_length = words[i].capture_offset - 1;
      size_t suffix_offset =
          words[i].capture_offset + words[i].capture_length + 1;
      size_t suffix_length = words[i].length - suffix_offset;
      char *capture = bytes_dup(words[i].text + words[i].capture_offset,
                                words[i].capture_length);
      if (!capture) {
        error = ST_ERR_MEMORY;
        goto cpl_done;
      }
      st_token_type_t capture_type = wildcard_type(capture);
      if (capture_type == ST_TYPE_LITERAL ||
          (prefix_length == 0 && suffix_length == 0)) {
        free(capture);
        error = ST_ERR_INVALID;
        goto cpl_done;
      }
      tokens[i].text = words[i].text;
      tokens[i].text_length = words[i].length;
      tokens[i].type = ST_TYPE_LITERAL;
      tokens[i].compound = true;
      tokens[i].prefix = bytes_dup(words[i].text, prefix_length);
      tokens[i].prefix_length = prefix_length;
      tokens[i].capture = capture;
      tokens[i].capture_length = words[i].capture_length;
      tokens[i].suffix =
          bytes_dup(words[i].text + suffix_offset, suffix_length);
      tokens[i].suffix_length = suffix_length;
      tokens[i].capture_type = capture_type;
      if (!tokens[i].prefix || !tokens[i].suffix) {
        error = ST_ERR_MEMORY;
        goto cpl_done;
      }
      continue;
    }
    bool typed = !words[i].literal && wildcard_spelling(words[i].text);
    if (!words[i].literal && words[i].text[0] == '#' && !typed) {
      error = ST_ERR_INVALID;
      goto cpl_done;
    }
    tokens[i] = (st_token_t){.text = words[i].text,
                             .type = typed ? wildcard_type(words[i].text)
                                           : ST_TYPE_LITERAL,
                             .text_length = words[i].length};
  }
  error = st_netpattern_encode_owned(tokens, count, out_netpattern);
cpl_done:
  for (size_t i = 0; i < count; i++) {
    free((void *)tokens[i].prefix);
    free((void *)tokens[i].capture);
    free((void *)tokens[i].suffix);
  }
  free_words(words, count);
  return error;
}

static bool literal_needs_quotes(const char *text, size_t length) {
  if (length == 0)
    return true;
  if (text[0] == '#' || (length == 1 && text[0] == '*'))
    return true;
  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)text[i];
    if (isspace(c) || c < 0x20 || c == 0x7f || c == '"' || c == '\\' ||
        c == '{' || c == '}')
      return true;
  }
  return false;
}

static size_t cpl_literal_length(const char *text, size_t length, bool quote) {
  if (!quote)
    return length;
  size_t result = 2;
  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)text[i];
    if (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' ||
        c == '\r' || c == '\t')
      result += 2;
    else if (c < 0x20 || c == 0x7f)
      result += 4;
    else
      result++;
  }
  return result;
}

static void append_cpl_literal(char *output, size_t *used, const char *text,
                               size_t length, bool quote) {
  if (quote)
    output[(*used)++] = '"';
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)text[i];
    if (!quote) {
      output[(*used)++] = (char)c;
    } else if (c == '"' || c == '\\') {
      output[(*used)++] = '\\';
      output[(*used)++] = (char)c;
    } else if (c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') {
      output[(*used)++] = '\\';
      output[(*used)++] = c == '\b'   ? 'b'
                          : c == '\f' ? 'f'
                          : c == '\n' ? 'n'
                          : c == '\r' ? 'r'
                                      : 't';
    } else if (c < 0x20 || c == 0x7f) {
      output[(*used)++] = '\\';
      output[(*used)++] = 'x';
      output[(*used)++] = hex[c >> 4];
      output[(*used)++] = hex[c & 15];
    } else {
      output[(*used)++] = (char)c;
    }
  }
  if (quote)
    output[(*used)++] = '"';
}

st_error_t st_netpattern_decode_view(st_netpattern_view_t netpattern,
                                     st_token_array_t *out_tokens) {

  out_tokens->tokens = NULL;
  out_tokens->count = 0;

  if (((!netpattern.data) && (netpattern.length != 0)))
    return ST_ERR_INVALID;
  const char *encoded = netpattern.data;
  size_t encoded_length = netpattern.length;
  if (encoded_length == 0 || encoded_length >= ST_MAX_NETPATTERN_LEN)
    return ST_ERR_FORMAT;
  size_t count = 0, capacity = 0;
  shell_netstring_iter_t outer;
  (void)shell_netstring_iter_init(&outer, encoded, encoded_length);
  st_token_t *tokens = NULL;
  while (outer.offset < outer.length) {
    if (count == ST_MAX_CMD_TOKENS)
      goto limit;
    shell_netstring_view_t record, tag_record, value_record;
    shell_netstring_status_t status =
        shell_netstring_iter_next(&outer, &record);
    if (status == SHELL_NETSTRING_EOVERFLOW)
      goto limit;
    if (status != SHELL_NETSTRING_OK)
      goto format;
    shell_netstring_iter_t inner;
    (void)shell_netstring_iter_init(&inner, record.payload,
                                    record.payload_length);
    if (shell_netstring_iter_next(&inner, &tag_record) != SHELL_NETSTRING_OK ||
        shell_netstring_iter_next(&inner, &value_record) !=
            SHELL_NETSTRING_OK ||
        inner.offset != inner.length || tag_record.payload_length != 1)
      goto format;
    const char *tag = (const char *)tag_record.payload;
    const char *value = (const char *)value_record.payload;
    size_t value_length = value_record.payload_length;
    if ((tag[0] != 'L' && tag[0] != 'T' && tag[0] != 'C') ||
        value_length >= ST_MAX_NETPATTERN_LEN)
      goto format;
    st_token_t token = {0};
    if (tag[0] == 'C') {
      const char *part_values[3] = {0};
      size_t part_lengths[3] = {0};
      char part_tags[3] = {0};
      size_t part_count = 0, typed_index = SIZE_MAX;
      shell_netstring_iter_t nested;
      (void)shell_netstring_iter_init(&nested, value, value_length);
      while (nested.offset < nested.length && part_count < 3) {
        shell_netstring_view_t part_record, part_tag_record, part_value_record;
        if (shell_netstring_iter_next(&nested, &part_record) !=
            SHELL_NETSTRING_OK)
          goto format;
        shell_netstring_iter_t part_inner;
        (void)shell_netstring_iter_init(&part_inner, part_record.payload,
                                        part_record.payload_length);
        if (shell_netstring_iter_next(&part_inner, &part_tag_record) !=
                SHELL_NETSTRING_OK ||
            shell_netstring_iter_next(&part_inner, &part_value_record) !=
                SHELL_NETSTRING_OK ||
            part_inner.offset != part_inner.length ||
            part_tag_record.payload_length != 1)
          goto format;
        const char *part_tag = (const char *)part_tag_record.payload;
        const char *part_value = (const char *)part_value_record.payload;
        size_t part_value_length = part_value_record.payload_length;
        if ((part_tag[0] != 'L' && part_tag[0] != 'T') ||
            part_value_length >= ST_MAX_TOKEN_LEN)
          goto format;
        part_tags[part_count] = part_tag[0];
        part_values[part_count] = part_value;
        part_lengths[part_count] = part_value_length;
        if (part_tag[0] == 'T') {
          if (typed_index != SIZE_MAX)
            goto format;
          typed_index = part_count;
        }
        part_count++;
      }
      bool canonical_parts =
          (part_count == 2 && ((part_tags[0] == 'L' && part_tags[1] == 'T') ||
                               (part_tags[0] == 'T' && part_tags[1] == 'L'))) ||
          (part_count == 3 && part_tags[0] == 'L' && part_tags[1] == 'T' &&
           part_tags[2] == 'L');
      if (nested.offset != nested.length || !canonical_parts ||
          typed_index == SIZE_MAX)
        goto format;
      const char *typed = part_values[typed_index];
      size_t typed_length = part_lengths[typed_index];
      char *typed_text = bytes_dup(typed, typed_length);
      if (!typed_text)
        goto memory;
      st_token_type_t capture_type = wildcard_type(typed_text);
      if (capture_type == ST_TYPE_LITERAL) {
        free(typed_text);
        goto format;
      }
      const char *prefix = typed_index ? part_values[0] : "";
      size_t prefix_length = typed_index ? part_lengths[0] : 0;
      const char *suffix =
          typed_index + 1 < part_count ? part_values[typed_index + 1] : "";
      size_t suffix_length =
          typed_index + 1 < part_count ? part_lengths[typed_index + 1] : 0;
      if (prefix_length == 0 && suffix_length == 0) {
        free(typed_text);
        goto format;
      }
      token.prefix = bytes_dup(prefix, prefix_length);
      token.capture = typed_text;
      token.suffix = bytes_dup(suffix, suffix_length);
      size_t display_length = prefix_length + typed_length + suffix_length + 2;
      char *display_text = malloc(display_length + 1);
      token.text = display_text;
      if (!token.prefix || !token.suffix || !token.text) {
        free((void *)token.prefix);
        free((void *)token.capture);
        free((void *)token.suffix);
        free((void *)token.text);
        goto memory;
      }
      size_t display_used = 0;
      memcpy(display_text + display_used, prefix, prefix_length);
      display_used += prefix_length;
      display_text[display_used++] = '{';
      memcpy(display_text + display_used, typed, typed_length);
      display_used += typed_length;
      display_text[display_used++] = '}';
      memcpy(display_text + display_used, suffix, suffix_length);
      display_used += suffix_length;
      display_text[display_used] = '\0';
      token.type = ST_TYPE_LITERAL;
      token.text_length = display_used;
      token.prefix_length = prefix_length;
      token.capture_length = typed_length;
      token.suffix_length = suffix_length;
      token.compound = true;
      token.capture_type = capture_type;
    } else {
      if (value_length >= ST_MAX_TOKEN_LEN)
        goto format;
      token.text = bytes_dup(value, value_length);
      if (!token.text)
        goto memory;
      token.type = ST_TYPE_LITERAL;
      token.text_length = value_length;
      if (tag[0] == 'T') {
        if (!wildcard_spelling(token.text)) {
          free((void *)token.text);
          goto format;
        }
        token.type = wildcard_type(token.text);
        if (token.type == ST_TYPE_LITERAL) {
          free((void *)token.text);
          goto format;
        }
      }
    }
    if (count == capacity) {
      /* The token-count limit bounds these power-of-two capacities. Grow
       * geometrically so cumulative allocation and token-copy work is linear.
       */
      size_t next_capacity = capacity ? capacity * 2 : 4;
      st_token_t *grown = realloc(tokens, next_capacity * sizeof(*tokens));
      if (!grown) {
        free((void *)token.text);
        free((void *)token.prefix);
        free((void *)token.capture);
        free((void *)token.suffix);
        goto memory;
      }
      tokens = grown;
      capacity = next_capacity;
    }
    tokens[count++] = token;
  }
  if (count == 0)
    goto format;
  st_netpattern_t canonical = {0};
  st_error_t canonical_error =
      st_netpattern_encode_owned(tokens, count, &canonical);
  if (canonical_error != ST_OK) {
    if (canonical_error == ST_ERR_MEMORY)
      goto memory;
    if (canonical_error == ST_ERR_LIMIT)
      goto limit;
    goto format;
  }
  bool is_canonical = canonical.length == encoded_length &&
                      memcmp(canonical.data, encoded, encoded_length) == 0;
  st_netpattern_free(&canonical);
  if (!is_canonical)
    goto format;
  out_tokens->tokens = tokens;
  out_tokens->count = count;
  return ST_OK;
format:
  for (size_t i = 0; i < count; i++) {
    free((void *)tokens[i].text);
    free((void *)tokens[i].prefix);
    free((void *)tokens[i].capture);
    free((void *)tokens[i].suffix);
  }
  free(tokens);
  return ST_ERR_FORMAT;
limit:
  for (size_t i = 0; i < count; i++) {
    free((void *)tokens[i].text);
    free((void *)tokens[i].prefix);
    free((void *)tokens[i].capture);
    free((void *)tokens[i].suffix);
  }
  free(tokens);
  return ST_ERR_LIMIT;
memory:
  for (size_t i = 0; i < count; i++) {
    free((void *)tokens[i].text);
    free((void *)tokens[i].prefix);
    free((void *)tokens[i].capture);
    free((void *)tokens[i].suffix);
  }
  free(tokens);
  return ST_ERR_MEMORY;
}

st_error_t st_netpattern_to_cpl_view(st_netpattern_view_t netpattern,
                                     char **out_cpl) {
  *out_cpl = NULL;
  if (((!netpattern.data) && (netpattern.length != 0)))
    return ST_ERR_INVALID;
  st_token_array_t decoded = {0};
  st_error_t decode_error = st_netpattern_decode_view(netpattern, &decoded);
  if (decode_error != ST_OK)
    return decode_error;
  size_t required = decoded.count ? decoded.count - 1 : 0;
  for (size_t i = 0; i < decoded.count; i++) {
    if (decoded.tokens[i].compound) {
      size_t prefix_length = component_length(decoded.tokens[i].prefix,
                                              decoded.tokens[i].prefix_length);
      size_t capture_length = component_length(
          decoded.tokens[i].capture, decoded.tokens[i].capture_length);
      size_t suffix_length = component_length(decoded.tokens[i].suffix,
                                              decoded.tokens[i].suffix_length);
      bool quote_prefix =
          prefix_length &&
          literal_needs_quotes(decoded.tokens[i].prefix, prefix_length);
      bool quote_suffix =
          suffix_length &&
          literal_needs_quotes(decoded.tokens[i].suffix, suffix_length);
      size_t prefix_rendered = cpl_literal_length(decoded.tokens[i].prefix,
                                                  prefix_length, quote_prefix);
      size_t suffix_rendered = cpl_literal_length(decoded.tokens[i].suffix,
                                                  suffix_length, quote_suffix);
      if (prefix_rendered > SIZE_MAX - capture_length - 2 ||
          suffix_rendered > SIZE_MAX - prefix_rendered - capture_length - 2) {
        st_token_array_free(&decoded);
        return ST_ERR_LIMIT;
      }
      size_t addition = prefix_rendered + capture_length + suffix_rendered + 2;
      if (addition > SIZE_MAX - required ||
          required + addition >= ST_MAX_CPL_LEN) {
        st_token_array_free(&decoded);
        return ST_ERR_LIMIT;
      }
      required += addition;
      continue;
    }
    size_t value_length = decoded.tokens[i].text_length;
    size_t addition =
        decoded.tokens[i].type == ST_TYPE_LITERAL
            ? cpl_literal_length(
                  decoded.tokens[i].text, value_length,
                  literal_needs_quotes(decoded.tokens[i].text, value_length))
            : value_length;
    if (addition > SIZE_MAX - required ||
        required + addition >= ST_MAX_CPL_LEN) {
      st_token_array_free(&decoded);
      return ST_ERR_LIMIT;
    }
    required += addition;
  }
  char *cpl = malloc(required + 1);
  if (!cpl) {
    st_token_array_free(&decoded);
    return ST_ERR_MEMORY;
  }
  size_t used = 0;
  for (size_t i = 0; i < decoded.count; i++) {
    const char *value = decoded.tokens[i].text;
    size_t value_length = decoded.tokens[i].text_length;
    if (used)
      cpl[used++] = ' ';
    if (decoded.tokens[i].compound) {
      size_t prefix_length = component_length(decoded.tokens[i].prefix,
                                              decoded.tokens[i].prefix_length);
      size_t capture_length = component_length(
          decoded.tokens[i].capture, decoded.tokens[i].capture_length);
      size_t suffix_length = component_length(decoded.tokens[i].suffix,
                                              decoded.tokens[i].suffix_length);
      if (prefix_length)
        append_cpl_literal(
            cpl, &used, decoded.tokens[i].prefix, prefix_length,
            literal_needs_quotes(decoded.tokens[i].prefix, prefix_length));
      cpl[used++] = '{';
      memcpy(cpl + used, decoded.tokens[i].capture, capture_length);
      used += capture_length;
      cpl[used++] = '}';
      if (suffix_length)
        append_cpl_literal(
            cpl, &used, decoded.tokens[i].suffix, suffix_length,
            literal_needs_quotes(decoded.tokens[i].suffix, suffix_length));
      continue;
    }
    if (decoded.tokens[i].type != ST_TYPE_LITERAL) {
      memcpy(cpl + used, value, value_length);
      used += value_length;
    } else
      append_cpl_literal(cpl, &used, value, value_length,
                         literal_needs_quotes(value, value_length));
  }
  cpl[used] = '\0';
  *out_cpl = cpl;
  st_token_array_free(&decoded);
  return ST_OK;
}

static int compare_bytes(const char *left, size_t left_length,
                         const char *right, size_t right_length) {
  size_t common = left_length < right_length ? left_length : right_length;
  int order = common ? memcmp(left, right, common) : 0;
  return order                        ? order
         : left_length > right_length ? 1
         : left_length < right_length ? -1
                                      : 0;
}

int st_netpattern_compare_view(st_netpattern_view_t left,
                               st_netpattern_view_t right) {
  if (!left.data || !right.data)
    return left.data ? 1 : right.data ? -1 : 0;
  size_t left_length = left.length, right_length = right.length;
  shell_netstring_iter_t lo, ro;
  (void)shell_netstring_iter_init(&lo, left.data, left_length);
  (void)shell_netstring_iter_init(&ro, right.data, right_length);
  while (lo.offset < lo.length && ro.offset < ro.length) {
    shell_netstring_view_t lr, rr, lt, lv, rt, rv;
    if (shell_netstring_iter_next(&lo, &lr) != SHELL_NETSTRING_OK ||
        shell_netstring_iter_next(&ro, &rr) != SHELL_NETSTRING_OK)
      return compare_bytes(left.data, left_length, right.data, right_length);
    shell_netstring_iter_t li, ri;
    (void)shell_netstring_iter_init(&li, lr.payload, lr.payload_length);
    (void)shell_netstring_iter_init(&ri, rr.payload, rr.payload_length);
    if (shell_netstring_iter_next(&li, &lt) != SHELL_NETSTRING_OK ||
        shell_netstring_iter_next(&li, &lv) != SHELL_NETSTRING_OK ||
        li.offset != li.length ||
        shell_netstring_iter_next(&ri, &rt) != SHELL_NETSTRING_OK ||
        shell_netstring_iter_next(&ri, &rv) != SHELL_NETSTRING_OK ||
        ri.offset != ri.length || lt.payload_length != 1 ||
        rt.payload_length != 1)
      return compare_bytes(left.data, left_length, right.data, right_length);
    size_t common = lv.payload_length < rv.payload_length ? lv.payload_length
                                                          : rv.payload_length;
    int value_order = memcmp(lv.payload, rv.payload, common);
    if (value_order != 0)
      return value_order;
    if (lv.payload_length != rv.payload_length)
      return lv.payload_length < rv.payload_length ? -1 : 1;
    if (lt.payload[0] != rt.payload[0])
      return lt.payload[0] < rt.payload[0] ? -1 : 1;
  }
  if (lo.offset == lo.length && ro.offset == ro.length)
    return 0;
  return lo.offset == lo.length ? -1 : 1;
}
