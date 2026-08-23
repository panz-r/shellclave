#define _POSIX_C_SOURCE 200809L
#include "metadata.h"
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

static size_t digits(size_t value) {
  size_t result = 1;
  while (value >= 10) {
    value /= 10;
    result++;
  }
  return result;
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

st_error_t st_netpattern_encode(const st_token_t *tokens, size_t count,
                                char **out_netpattern) {
  if (out_netpattern)
    *out_netpattern = NULL;
  if (!tokens || count == 0 || count > ST_MAX_CMD_TOKENS || !out_netpattern)
    return ST_ERR_INVALID;

  const char *values[ST_MAX_CMD_TOKENS];
  char canonical[ST_MAX_CMD_TOKENS][ST_MAX_TOKEN_LEN];
  char tags[ST_MAX_CMD_TOKENS];
  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    if (!tokens[i].text)
      return ST_ERR_INVALID;
    size_t length = strlen(tokens[i].text);
    if (length >= ST_MAX_TOKEN_LEN)
      return ST_ERR_LIMIT;
    st_token_type_t type = ST_TYPE_LITERAL;
    const char *wild = canonical_wildcard(tokens[i].text, &type, canonical[i]);
    bool typed = tokens[i].type != ST_TYPE_LITERAL && wild != NULL;
    if (typed && type != tokens[i].type)
      return ST_ERR_FORMAT;
    tags[i] = typed ? 'T' : 'L';
    values[i] = typed ? wild : tokens[i].text;
    length = strlen(values[i]);
    size_t record = 4 + digits(length) + 2 + length;
    if (record > SIZE_MAX - digits(record) - 2 ||
        total > SIZE_MAX - record - digits(record) - 2)
      return ST_ERR_LIMIT;
    total += digits(record) + 2 + record;
  }
  if (total >= ST_MAX_NETPATTERN_LEN)
    return ST_ERR_LIMIT;
  char *encoded = malloc(total + 1);
  if (!encoded)
    return ST_ERR_MEMORY;
  size_t used = 0;
  for (size_t i = 0; i < count; i++) {
    size_t length = strlen(values[i]);
    size_t record = 4 + digits(length) + 2 + length;
    used += (size_t)sprintf(encoded + used, "%zu:1:%c,%zu:", record, tags[i],
                            length);
    memcpy(encoded + used, values[i], length);
    used += length;
    encoded[used++] = ',';
    encoded[used++] = ',';
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
  for (size_t i = 0; i < count; i++) {
    bool typed = !words[i].literal && wildcard_spelling(words[i].text);
    if (!words[i].literal && words[i].text[0] == '#' && !typed) {
      error = ST_ERR_INVALID;
      free_words(words, count);
      return error;
    }
    tokens[i] = (st_token_t){.text = words[i].text,
                             .type = typed ? wildcard_type(words[i].text)
                                           : ST_TYPE_LITERAL};
  }
  error = st_netpattern_encode(tokens, count, out_netpattern);
  free_words(words, count);
  return error;
}

static st_error_t read_netstring(const char *encoded, size_t encoded_length,
                                 size_t *offset, const char **payload,
                                 size_t *payload_length) {
  if (*offset >= encoded_length || !isdigit((unsigned char)encoded[*offset]))
    return ST_ERR_FORMAT;
  size_t length = 0;
  if (encoded[*offset] == '0' && *offset + 1 < encoded_length &&
      isdigit((unsigned char)encoded[*offset + 1]))
    return ST_ERR_FORMAT;
  do {
    unsigned digit = (unsigned)(encoded[*offset] - '0');
    if (length > (SIZE_MAX - digit) / 10)
      return ST_ERR_LIMIT;
    length = length * 10 + digit;
    (*offset)++;
  } while (*offset < encoded_length &&
           isdigit((unsigned char)encoded[*offset]));
  if (*offset >= encoded_length || encoded[(*offset)++] != ':' ||
      length >= encoded_length - *offset || encoded[*offset + length] != ',')
    return ST_ERR_FORMAT;
  *payload = encoded + *offset;
  *payload_length = length;
  *offset += length + 1;
  return ST_OK;
}

static bool literal_needs_quotes(const char *text, size_t length) {
  if (length == 0)
    return true;
  if (text[0] == '#' || (length == 1 && text[0] == '*'))
    return true;
  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)text[i];
    if (isspace(c) || c < 0x20 || c == 0x7f || c == '"' || c == '\\')
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
        (tag[0] != 'L' && tag[0] != 'T') || value_length >= ST_MAX_TOKEN_LEN)
      goto format;
    char *text = strndup(value, value_length);
    if (!text)
      goto memory;
    st_token_type_t type = ST_TYPE_LITERAL;
    if (tag[0] == 'T') {
      if (!wildcard_spelling(text)) {
        free(text);
        goto format;
      }
      type = wildcard_type(text);
      if (type == ST_TYPE_LITERAL) {
        free(text);
        goto format;
      }
    }
    st_token_t *grown = realloc(tokens, (count + 1) * sizeof(*tokens));
    if (!grown) {
      free(text);
      goto memory;
    }
    tokens = grown;
    tokens[count++] = (st_token_t){.text = text, .type = type};
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
  for (size_t i = 0; i < count; i++)
    free(tokens[i].text);
  free(tokens);
  return ST_ERR_FORMAT;
limit:
  for (size_t i = 0; i < count; i++)
    free(tokens[i].text);
  free(tokens);
  return ST_ERR_LIMIT;
memory:
  for (size_t i = 0; i < count; i++)
    free(tokens[i].text);
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
    size_t value_length = strlen(decoded.tokens[i].text);
    size_t addition =
        decoded.tokens[i].type == ST_TYPE_LITERAL
            ? cpl_literal_length(
                  decoded.tokens[i].text, value_length,
                  literal_needs_quotes(decoded.tokens[i].text, value_length))
            : value_length;
    if (addition > SIZE_MAX - required ||
        required + addition >= ST_MAX_CPL_LEN) {
      st_free_token_array(&decoded);
      return ST_ERR_LIMIT;
    }
    required += addition;
  }
  char *cpl = malloc(required + 1);
  if (!cpl) {
    st_free_token_array(&decoded);
    return ST_ERR_MEMORY;
  }
  size_t used = 0;
  for (size_t i = 0; i < decoded.count; i++) {
    const char *value = decoded.tokens[i].text;
    size_t value_length = strlen(value);
    if (used)
      cpl[used++] = ' ';
    if (decoded.tokens[i].type != ST_TYPE_LITERAL) {
      memcpy(cpl + used, value, value_length);
      used += value_length;
    } else
      append_cpl_literal(cpl, &used, value, value_length,
                         literal_needs_quotes(value, value_length));
  }
  cpl[used] = '\0';
  *out_cpl = cpl;
  st_free_token_array(&decoded);
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
