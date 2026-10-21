#ifndef SHELLSPLIT_WORD_BYTE_CASES_H
#define SHELLSPLIT_WORD_BYTE_CASES_H

/* Complete ordinary shell words and their exact decoded bytes. No payload
 * contains NUL: malformed UTF-8 is data, not an encoding error. */
static const struct {
  const char *word, *value;
} shellsplit_test_word_bytes[] = {
    {"日本", "日本"},
    {"résumé.txt", "résumé.txt"},
    {"pre日'本'\".txt\"", "pre日本.txt"},
    {"\x80\xff\xc0\xaf", "\x80\xff\xc0\xaf"},
    {"\\日本", "日本"},
    {"日\\\n本", "日本"},
    {"日本\\ word", "日本 word"},
    {"$日本", "$日本"},
    {"日本=value", "日本=value"},
    {"if日本", "if日本"},
    {"日本if", "日本if"},
    {"time日本", "time日本"},
    {"日本#tail", "日本#tail"},
    {"日本.if", "日本.if"},
    {"日本''if", "日本if"},
    {"日本-while", "日本-while"},
    {"日本/in", "日本/in"},
    {"x.if", "x.if"},
    {"x''while", "xwhile"},
    {"日本$'ascii'case", "日本asciicase"},
    {"'日本'", "日本"},
    {"\"日本\"", "日本"},
    {"pre'日本'\".txt\"", "pre日本.txt"},
    {"'\x80\xff\xc0\xaf'", "\x80\xff\xc0\xaf"},
    {"\"\x80\xff\xc0\xaf\"", "\x80\xff\xc0\xaf"},
    {"'é'\"\\$\"'文'", "é$文"},
    {"\"a\\\n日本\"", "a日本"},
    {"''\"\xe6\"''", "\xe6"},
    {"\"'日本'\"", "'日本'"},
    {"'日本\"$`\\*?'", "日本\"$`\\*?"},
    {"'\xe2\x80\xa8'", "\xe2\x80\xa8"},
    {"'é'", "é"},
    {"'é'", "é"},
    {"\"日本\"suffix", "日本suffix"},
    {"'é\\'", "é\\"},
    {"'\x80\xff\\'", "\x80\xff\\"},
    {"pre'é\\'\".txt\"", "preé\\.txt"},
    {"\"é\\q\"", "é\\q"},
    {"\"é\\\\\"", "é\\"},
    {"\"é\\\"q\"", "é\"q"},
    {"\"é\\`q\"", "é`q"},
};

#endif
