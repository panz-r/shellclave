#ifndef SHELLSPLIT_TEST_ANSI_NUL_CASES_H
#define SHELLSPLIT_TEST_ANSI_NUL_CASES_H

/* Effective ordinary shell-word values. Binary word decoders deliberately
 * retain the NUL and discarded bytes instead; these fixtures describe argv. */
static const struct {
  const char *word, *value;
} shellsplit_test_ansi_nul_words[] = {
    {"$'before\\0after'", "before"},
    {"pre$'before\\0after'post", "prebeforepost"},
    {"$'\\0'", ""},
    {"$'\\0ignored'after", "after"},
    {"$'a\\000b'", "a"},
    {"$'a\\400b'", "a"},
    {"$'a\\x00b'", "a"},
    {"$'a\\c@b'", "a"},
    {"$'a\\u0000b'", "a"},
    {"$'a\\U00000000b'", "a"},
    {"$'a\\0b'$'c\\0d'e", "ace"},
    {"$\\\n'a\\0b'c", "ac"},
    {"$'日本\\0ignored'語", "日本語"},
    {"$'a\\0\\u65e5'", "a"},
    {"$'a\\0\\U000065e5'", "a"},
    {"$'a\\0\\c\\'discarded'X", "aX"},
    {"$'a\\0$(printf phantom)`printf phantom`*?{a,b}'", "a"},
    {"$'a\\0]'[", "a["},
};

/* These have complete raw grammar. Nested defaults/alternates retain their
 * enclosing double quote even through an ordinary-quoting pattern operand;
 * NUL translation there is unsupported by complete-command semantic APIs. */
#define SHELLSPLIT_TEST_NESTED_ANSI_NUL(prefix, suffix)                        \
  prefix "${u:-$'a\\0b'}" suffix, prefix "${u-$'a\\0b'}" suffix,               \
      prefix "${u:+$'a\\0b'}" suffix, prefix "${u+$'a\\0b'}" suffix
static const char *const shellsplit_test_nested_ansi_nul[] = {
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v#", "}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v##", "}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v%", "}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v%%", "}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v/", "/x}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v/x/", "}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v^", "}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v^^", "}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v,", "}\""),
    SHELLSPLIT_TEST_NESTED_ANSI_NUL("printf %s \"${v,,", "}\""),
    "printf %s \"${v#${u:-$'a\\x00b'}}\"",
    "printf %s \"${v#${u:-${w%${t:+$'a\\0b'}}}}\"",
    "printf %s ${v#\"${u:-$'a\\0b'}\"}",
};
#undef SHELLSPLIT_TEST_NESTED_ANSI_NUL

#endif
