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

typedef struct {
  char *text;
  size_t length;
  bool literal;
} cpl_word_t;

static void free_words(cpl_word_t *words, size_t count) {
  for (size_t i = 0; i < count; i++)
    free(words[i].text);
  free(words);
}

static bool append_utf8(char *out, size_t *used, uint32_t value) {
  if (value == 0 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
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

static bool hex4(const char *text, uint32_t *value) {
  uint32_t result = 0;
  for (size_t i = 0; i < 4; i++) {
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

static st_error_t parse_cpl(const char *cpl, cpl_word_t **out_words,
                            size_t *out_count) {
  *out_words = NULL;
  *out_count = 0;
  if (!cpl || !cpl[0] || strlen(cpl) >= ST_MAX_CPL_LEN)
    return ST_ERR_INVALID;
  size_t offset = 0, count = 0;
  cpl_word_t *words = NULL;
  while (cpl[offset]) {
    while (cpl[offset] == ' ')
      offset++;
    if (!cpl[offset])
      break;
    if (count == ST_MAX_CMD_TOKENS)
      goto invalid;
    bool quoted = cpl[offset] == '"';
    size_t capacity = strlen(cpl + offset) * 3 + 1;
    char *word = malloc(capacity);
    if (!word)
      goto memory;
    size_t used = 0;
    if (quoted) {
      offset++;
      bool closed = false;
      while (cpl[offset]) {
        unsigned char c = (unsigned char)cpl[offset++];
        if (c == '"') {
          closed = true;
          break;
        }
        if (c < 0x20)
          goto word_invalid;
        if (c != '\\') {
          word[used++] = (char)c;
          continue;
        }
        char escape = cpl[offset++];
        if (!escape)
          goto word_invalid;
        switch (escape) {
        case '"':
          word[used++] = '"';
          break;
        case '\\':
          word[used++] = '\\';
          break;
        case 'b':
          word[used++] = '\b';
          break;
        case 'f':
          word[used++] = '\f';
          break;
        case 'n':
          word[used++] = '\n';
          break;
        case 'r':
          word[used++] = '\r';
          break;
        case 't':
          word[used++] = '\t';
          break;
        case 'u': {
          uint32_t value;
          if (strlen(cpl + offset) < 4 || !hex4(cpl + offset, &value))
            goto word_invalid;
          offset += 4;
          if (value >= 0xd800 && value <= 0xdbff) {
            uint32_t low;
            if (cpl[offset] != '\\' || cpl[offset + 1] != 'u' ||
                strlen(cpl + offset + 2) < 4 || !hex4(cpl + offset + 2, &low) ||
                low < 0xdc00 || low > 0xdfff)
              goto word_invalid;
            offset += 6;
            value = 0x10000 + ((value - 0xd800) << 10) + (low - 0xdc00);
          }
          if (!append_utf8(word, &used, value))
            goto word_invalid;
          break;
        }
        default:
          goto word_invalid;
        }
      }
      if (!closed || (cpl[offset] && cpl[offset] != ' '))
        goto word_invalid;
    } else {
      while (cpl[offset] && cpl[offset] != ' ') {
        unsigned char c = (unsigned char)cpl[offset++];
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\\')
          goto word_invalid;
        word[used++] = (char)c;
      }
      if (used == 0)
        goto word_invalid;
    }
    if (used >= ST_MAX_TOKEN_LEN) {
    word_invalid:
      free(word);
      goto invalid;
    }
    word[used] = '\0';
    cpl_word_t *grown = realloc(words, (count + 1) * sizeof(*words));
    if (!grown) {
      free(word);
      goto memory;
    }
    words = grown;
    words[count++] = (cpl_word_t){word, used, quoted};
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

st_error_t st_netpattern_encode(const st_token_t *tokens, size_t count,
                                char **out_netpattern) {
  if (out_netpattern)
    *out_netpattern = NULL;
  if (!tokens || count == 0 || count > ST_MAX_CMD_TOKENS || !out_netpattern)
    return ST_ERR_INVALID;

  char *records[ST_MAX_CMD_TOKENS] = {0};
  size_t record_lengths[ST_MAX_CMD_TOKENS] = {0};
  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    st_error_t error = ST_OK;
    if (tokens[i].compound) {
      if (!tokens[i].prefix || !tokens[i].capture || !tokens[i].suffix ||
          tokens[i].capture_type <= ST_TYPE_LITERAL ||
          tokens[i].capture_type >= ST_TYPE_COUNT ||
          (tokens[i].prefix[0] == '\0' && tokens[i].suffix[0] == '\0')) {
        error = ST_ERR_INVALID;
      } else {
        char canonical[ST_MAX_TOKEN_LEN];
        st_token_type_t type = ST_TYPE_LITERAL;
        const char *wild =
            canonical_wildcard(tokens[i].capture, &type, canonical);
        if (!wild || type != tokens[i].capture_type)
          error = ST_ERR_FORMAT;
        char *parts[3] = {0};
        size_t part_lengths[3] = {0};
        size_t part_count = 0, nested_length = 0;
        if (error == ST_OK && tokens[i].prefix[0]) {
          error = encode_tagged_record(
              'L', tokens[i].prefix, strlen(tokens[i].prefix),
              &parts[part_count], &part_lengths[part_count]);
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
        if (error == ST_OK && tokens[i].suffix[0]) {
          error = encode_tagged_record(
              'L', tokens[i].suffix, strlen(tokens[i].suffix),
              &parts[part_count], &part_lengths[part_count]);
          if (error == ST_OK)
            part_count++;
        }
        for (size_t p = 0; p < part_count; p++)
          nested_length += part_lengths[p];
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
      if (!tokens[i].text)
        error = ST_ERR_INVALID;
      else if (strlen(tokens[i].text) >= ST_MAX_TOKEN_LEN)
        error = ST_ERR_LIMIT;
      else {
        char canonical[ST_MAX_TOKEN_LEN];
        st_token_type_t type = ST_TYPE_LITERAL;
        const char *wild = canonical_wildcard(tokens[i].text, &type, canonical);
        bool typed = tokens[i].type != ST_TYPE_LITERAL && wild != NULL;
        if (typed && type != tokens[i].type)
          error = ST_ERR_FORMAT;
        else
          error = encode_tagged_record(typed ? 'T' : 'L',
                                       typed ? wild : tokens[i].text,
                                       strlen(typed ? wild : tokens[i].text),
                                       &records[i], &record_lengths[i]);
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
  *out_netpattern = encoded;
  return ST_OK;
}

st_error_t st_netpattern_from_cpl(const char *cpl, char **out_netpattern) {
  if (out_netpattern)
    *out_netpattern = NULL;
  if (!out_netpattern)
    return ST_ERR_INVALID;
  cpl_word_t *words = NULL;
  size_t count = 0;
  st_error_t error = parse_cpl(cpl, &words, &count);
  if (error != ST_OK)
    return error;
  st_token_t tokens[ST_MAX_CMD_TOKENS];
  memset(tokens, 0, sizeof(tokens));
  for (size_t i = 0; i < count; i++) {
    if (!words[i].literal) {
      char *open = strchr(words[i].text, '{');
      char *close = open ? strchr(open + 1, '}') : NULL;
      if (open || close) {
        if (!open || !close || strchr(open + 1, '{') ||
            strchr(close + 1, '}') || close[1] == '{') {
          error = ST_ERR_INVALID;
          goto cpl_done;
        }
        size_t capture_length = (size_t)(close - open - 1);
        char *capture = strndup(open + 1, capture_length);
        if (!capture) {
          error = ST_ERR_MEMORY;
          goto cpl_done;
        }
        st_token_type_t capture_type = wildcard_type(capture);
        if (capture_type == ST_TYPE_LITERAL ||
            (open == words[i].text && close[1] == '\0')) {
          free(capture);
          error = ST_ERR_INVALID;
          goto cpl_done;
        }
        tokens[i].text = words[i].text;
        tokens[i].type = ST_TYPE_LITERAL;
        tokens[i].compound = true;
        tokens[i].prefix =
            strndup(words[i].text, (size_t)(open - words[i].text));
        tokens[i].capture = capture;
        tokens[i].suffix = strdup(close + 1);
        tokens[i].capture_type = capture_type;
        if (!tokens[i].prefix || !tokens[i].suffix) {
          error = ST_ERR_MEMORY;
          goto cpl_done;
        }
        continue;
      }
    }
    bool typed = !words[i].literal && wildcard_spelling(words[i].text);
    if (!words[i].literal && words[i].text[0] == '#' && !typed) {
      error = ST_ERR_INVALID;
      goto cpl_done;
    }
    tokens[i] = (st_token_t){.text = words[i].text,
                             .type = typed ? wildcard_type(words[i].text)
                                           : ST_TYPE_LITERAL};
  }
  error = st_netpattern_encode(tokens, count, out_netpattern);
cpl_done:
  for (size_t i = 0; i < count; i++) {
    free((void *)tokens[i].prefix);
    free((void *)tokens[i].capture);
    free((void *)tokens[i].suffix);
  }
  free_words(words, count);
  return error;
}

static st_error_t read_netstring(const char *encoded, size_t encoded_length,
                                 size_t *offset, const char **payload,
                                 size_t *payload_length) {
  if (!encoded || !offset || !payload || !payload_length ||
      *offset > encoded_length)
    return ST_ERR_FORMAT;
  shell_netstring_iter_t iter;
  shell_netstring_status_t status = shell_netstring_iter_init(
      &iter, encoded + *offset, encoded_length - *offset);
  if (status != SHELL_NETSTRING_OK)
    return ST_ERR_FORMAT;
  shell_netstring_view_t view;
  status = shell_netstring_iter_next(&iter, &view);
  if (status == SHELL_NETSTRING_EOVERFLOW)
    return ST_ERR_LIMIT;
  if (status != SHELL_NETSTRING_OK)
    return ST_ERR_FORMAT;
  *payload = (const char *)view.payload;
  *payload_length = view.payload_length;
  *offset += view.record_length;
  return ST_OK;
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
      result += 6;
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
      output[(*used)++] = 'u';
      output[(*used)++] = '0';
      output[(*used)++] = '0';
      output[(*used)++] = hex[c >> 4];
      output[(*used)++] = hex[c & 15];
    } else {
      output[(*used)++] = (char)c;
    }
  }
  if (quote)
    output[(*used)++] = '"';
}

st_error_t st_netpattern_decode(const char *netpattern,
                                st_token_array_t *out_tokens) {
  if (out_tokens) {
    out_tokens->tokens = NULL;
    out_tokens->count = 0;
  }
  if (!netpattern || !out_tokens)
    return ST_ERR_INVALID;
  size_t encoded_length = strlen(netpattern);
  if (encoded_length == 0 || encoded_length >= ST_MAX_NETPATTERN_LEN)
    return ST_ERR_FORMAT;
  size_t outer = 0, count = 0;
  st_token_t *tokens = NULL;
  while (outer < encoded_length) {
    if (count == ST_MAX_CMD_TOKENS)
      goto limit;
    const char *record, *tag, *value;
    size_t record_length, tag_length, value_length, inner = 0;
    st_error_t error = read_netstring(netpattern, encoded_length, &outer,
                                      &record, &record_length);
    if (error == ST_ERR_LIMIT)
      goto limit;
    if (error != ST_OK ||
        read_netstring(record, record_length, &inner, &tag, &tag_length) !=
            ST_OK ||
        read_netstring(record, record_length, &inner, &value, &value_length) !=
            ST_OK ||
        inner != record_length || tag_length != 1 ||
        (tag[0] != 'L' && tag[0] != 'T' && tag[0] != 'C') ||
        value_length >= ST_MAX_NETPATTERN_LEN)
      goto format;
    st_token_t token = {0};
    if (tag[0] == 'C') {
      const char *part_values[3] = {0};
      size_t part_lengths[3] = {0};
      char part_tags[3] = {0};
      size_t nested = 0, part_count = 0, typed_index = SIZE_MAX;
      while (nested < value_length && part_count < 3) {
        const char *part_record, *part_tag, *part_value;
        size_t part_record_length, part_tag_length, part_value_length;
        size_t part_inner = 0;
        if (read_netstring(value, value_length, &nested, &part_record,
                           &part_record_length) != ST_OK ||
            read_netstring(part_record, part_record_length, &part_inner,
                           &part_tag, &part_tag_length) != ST_OK ||
            read_netstring(part_record, part_record_length, &part_inner,
                           &part_value, &part_value_length) != ST_OK ||
            part_inner != part_record_length || part_tag_length != 1 ||
            (part_tag[0] != 'L' && part_tag[0] != 'T') ||
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
      if (nested != value_length || !canonical_parts || typed_index == SIZE_MAX)
        goto format;
      const char *typed = part_values[typed_index];
      size_t typed_length = part_lengths[typed_index];
      char *typed_text = strndup(typed, typed_length);
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
      token.prefix = strndup(prefix, prefix_length);
      token.capture = typed_text;
      token.suffix = strndup(suffix, suffix_length);
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
      token.compound = true;
      token.capture_type = capture_type;
    } else {
      if (value_length >= ST_MAX_TOKEN_LEN)
        goto format;
      token.text = strndup(value, value_length);
      if (!token.text)
        goto memory;
      token.type = ST_TYPE_LITERAL;
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
    st_token_t *grown = realloc(tokens, (count + 1) * sizeof(*tokens));
    if (!grown) {
      free((void *)token.text);
      free((void *)token.prefix);
      free((void *)token.capture);
      free((void *)token.suffix);
      goto memory;
    }
    tokens = grown;
    tokens[count++] = token;
  }
  if (count == 0)
    goto format;
  char *canonical = NULL;
  st_error_t canonical_error = st_netpattern_encode(tokens, count, &canonical);
  if (canonical_error != ST_OK) {
    if (canonical_error == ST_ERR_MEMORY)
      goto memory;
    if (canonical_error == ST_ERR_LIMIT)
      goto limit;
    goto format;
  }
  bool is_canonical = strcmp(canonical, netpattern) == 0;
  free(canonical);
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

st_error_t st_netpattern_to_cpl(const char *netpattern, char **out_cpl) {
  if (out_cpl)
    *out_cpl = NULL;
  if (!netpattern || !out_cpl)
    return ST_ERR_INVALID;
  st_token_array_t decoded = {0};
  st_error_t decode_error = st_netpattern_decode(netpattern, &decoded);
  if (decode_error != ST_OK)
    return decode_error;
  size_t required = decoded.count ? decoded.count - 1 : 0;
  for (size_t i = 0; i < decoded.count; i++) {
    if (decoded.tokens[i].compound) {
      size_t prefix_length = strlen(decoded.tokens[i].prefix);
      size_t capture_length = strlen(decoded.tokens[i].capture);
      size_t suffix_length = strlen(decoded.tokens[i].suffix);
      if (literal_needs_quotes(decoded.tokens[i].prefix, prefix_length) ||
          (suffix_length &&
           literal_needs_quotes(decoded.tokens[i].suffix, suffix_length))) {
        st_token_array_free(&decoded);
        return ST_ERR_INVALID;
      }
      size_t addition = prefix_length + capture_length + suffix_length + 2;
      if (addition > SIZE_MAX - required ||
          required + addition >= ST_MAX_CPL_LEN) {
        st_token_array_free(&decoded);
        return ST_ERR_LIMIT;
      }
      required += addition;
      continue;
    }
    size_t value_length = strlen(decoded.tokens[i].text);
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
    size_t value_length = strlen(value);
    if (used)
      cpl[used++] = ' ';
    if (decoded.tokens[i].compound) {
      size_t prefix_length = strlen(decoded.tokens[i].prefix);
      size_t capture_length = strlen(decoded.tokens[i].capture);
      size_t suffix_length = strlen(decoded.tokens[i].suffix);
      memcpy(cpl + used, decoded.tokens[i].prefix, prefix_length);
      used += prefix_length;
      cpl[used++] = '{';
      memcpy(cpl + used, decoded.tokens[i].capture, capture_length);
      used += capture_length;
      cpl[used++] = '}';
      memcpy(cpl + used, decoded.tokens[i].suffix, suffix_length);
      used += suffix_length;
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

int st_netpattern_compare(const char *left, const char *right) {
  if (!left || !right)
    return left ? 1 : right ? -1 : 0;
  size_t left_length = strlen(left), right_length = strlen(right);
  size_t lo = 0, ro = 0;
  while (lo < left_length && ro < right_length) {
    const char *lr = NULL, *rr = NULL;
    size_t ll = 0, rl = 0, li = 0, ri = 0;
    if (read_netstring(left, left_length, &lo, &lr, &ll) != ST_OK ||
        read_netstring(right, right_length, &ro, &rr, &rl) != ST_OK)
      return strcmp(left, right);
    const char *lt = NULL, *lv = NULL, *rt = NULL, *rv = NULL;
    size_t ltl = 0, lvl = 0, rtl = 0, rvl = 0;
    if (read_netstring(lr, ll, &li, &lt, &ltl) != ST_OK ||
        read_netstring(lr, ll, &li, &lv, &lvl) != ST_OK || li != ll ||
        read_netstring(rr, rl, &ri, &rt, &rtl) != ST_OK ||
        read_netstring(rr, rl, &ri, &rv, &rvl) != ST_OK || ri != rl ||
        ltl != 1 || rtl != 1)
      return strcmp(left, right);
    size_t common = lvl < rvl ? lvl : rvl;
    int value_order = memcmp(lv, rv, common);
    if (value_order != 0)
      return value_order;
    if (lvl != rvl)
      return lvl < rvl ? -1 : 1;
    if (lt[0] != rt[0])
      return lt[0] < rt[0] ? -1 : 1;
  }
  if (lo == left_length && ro == right_length)
    return 0;
  return lo == left_length ? -1 : 1;
}
