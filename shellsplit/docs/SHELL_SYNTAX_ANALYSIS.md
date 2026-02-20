# Shell Scripting Syntax Support Analysis

> This document analyzes the shell syntax support in the **ShellSplit** library.

## Performance vs. Functionality Trade-offs

### Performance Requirements
- **Current tokenizer**: ~10-50μs per command
- **Target**: Keep under 100μs for complex commands
- **Constraint**: Must remain O(n) linear time

### Shell Syntax Complexity Spectrum

```
Simple →────────────────────────────────────────────→ Complex
Fast   →────────────────────────────────────────────→ Slow

|-------|-------|-------|-------|-------|-------|
Basic  Variables  Globbing  Subshells  Functions  Full Shell
Tokens  $var      *.txt     $(cmd)     func()    Grammar
```

## Recommended Shell Syntax Support

### ✅ Level 1: Basic Variables (High Priority)

**Syntax:**
```bash
$VARIABLE, ${VARIABLE}, $1, $2, $#, $?, $$
```

**Performance Impact:** Minimal (~5-10% slower)
**Implementation:** Simple state machine extension
**Security:** Low risk (variables resolved by shell)

**Examples:**
```bash
cat $FILE        → cat [VARIABLE:FILE]
grep "$PATTERN"  → grep [QUOTED_VARIABLE:PATTERN]
echo ${USER}     → echo [VARIABLE:USER]
```

### ✅ Level 2: Simple Globbing (Medium Priority)

**Syntax:**
```bash
*.txt, file?.log, [abc]*, [a-z0-9]
```

**Performance Impact:** Moderate (~15-20% slower)
**Implementation:** Character class state machine
**Security:** Low risk (globbing handled by shell)

**Examples:**
```bash
ls *.txt         → ls [GLOB:*.txt]
rm file?.log     → rm [GLOB:file?.log]
find [a-z]*.txt  → find [GLOB:[a-z]*.txt]
```

### ⚠️ Level 3: Command Substitution (Conditional)

**Syntax:**
```bash
$(command), `command`
```

**Performance Impact:** Significant (~30-50% slower)
**Implementation:** Recursive tokenization
**Security:** Medium risk (subshell execution)

**Recommendation:** Support but mark as shell feature

**Examples:**
```bash
cat $(find .)    → cat [SUBSHELL:find .]
grep `ls`        → grep [SUBSHELL:ls]
```

### ❌ Level 4: Advanced Features (Not Recommended)

**Avoid for now:**
```bash
- Functions: func() { ... }
- Complex arrays: ${array[@]}
- Arithmetic: $((1+1))
- Process substitution: <(cmd)
- Here documents: <<EOF
```

**Reason:** Too complex, significant performance impact, low ROI

## Implementation Strategy

### Phase 1: Variable Support (Current Focus)

**Tokenizer Extension:**
```c
// Add variable token types
typedef enum {
    // ... existing types ...
    TOKEN_VARIABLE,        // $VAR, ${VAR}
    TOKEN_VARIABLE_QUOTED, // "$VAR", '$VAR'
    TOKEN_SPECIAL_VAR,     // $1, $#, $?, $$
    TOKEN_GLOB,            // *.txt, file?
    TOKEN_SUBSHELL         // $(cmd), `cmd`
} token_type_t;
```

**Variable Detection State Machine:**
```
NORMAL → $ → VAR_START → [a-zA-Z0-9_] → VAR_NAME
                      → { → VAR_BRACE → [a-zA-Z0-9_] → VAR_BRACE_END
                      → [0-9#?$] → SPECIAL_VAR
```

### Phase 2: Performance Optimization

**Optimization Techniques:**
1. **Single Pass**: Detect variables during main tokenization
2. **Lookahead Buffer**: 4-8 character buffer for variable detection
3. **State Caching**: Cache common variable patterns
4. **Early Termination**: Stop variable parsing at reasonable length

**Expected Performance:**
- Basic variables: +5-10μs per command
- Globbing: +10-15μs per command
- Subshells: +20-30μs per command

### Phase 3: Security Considerations

**Security Rules:**
1. **Variables are opaque**: Don't resolve, just tokenize
2. **Mark as shell features**: Variables indicate shell processing
3. **Preserve quoting**: Track quoted vs unquoted variables
4. **Length limits**: Prevent excessively long variables

## Detailed Implementation Plan

### 1. Variable Tokenization

**Algorithm:**
```c
while (processing command) {
    if (current_char == '$') {
        if (next_char is '{') {
            // ${VARIABLE} format
            parse_brace_variable();
        } else if (next_char is alphanumeric) {
            // $VARIABLE format
            parse_simple_variable();
        } else if (next_char is special) {
            // $1, $#, $?, etc.
            parse_special_variable();
        }
    }
}
```

**Examples:**
```bash
# Simple variables
echo $USER          → TOKEN_VARIABLE: USER
cat ${FILE}_backup  → TOKEN_VARIABLE: FILE

# Special variables
echo $1             → TOKEN_SPECIAL_VAR: 1
check $?             → TOKEN_SPECIAL_VAR: ?

# Quoted variables
grep "$PATTERN"     → TOKEN_VARIABLE_QUOTED: PATTERN
```

### 2. Globbing Support

**Algorithm:**
```c
while (processing token) {
    if (current_char is '*' or '?' or '[') {
        if (in_glob_context) {
            mark_as_glob();
            continue;
        }
    }
}
```

**Examples:**
```bash
ls *.txt           → TOKEN_GLOB: *.txt
rm file?.log       → TOKEN_GLOB: file?.log
find [a-z]*.txt    → TOKEN_GLOB: [a-z]*.txt
```

### 3. Subshell Detection

**Algorithm:**
```c
while (processing command) {
    if (current_char is '$' and next_char is '(') {
        // $(command) format
        parse_subshell_dollar();
    } else if (current_char is '`') {
        // `command` format (legacy)
        parse_subshell_backtick();
    }
}
```

**Examples:**
```bash
cat $(find .)      → TOKEN_SUBSHELL: find .
grep `ls`          → TOKEN_SUBSHELL: ls
process $(cmd)     → TOKEN_SUBSHELL: cmd
```

## Performance Benchmarks

### Test Commands
```bash
1. "cat file.txt"                          (baseline)
2. "cat $FILE"                            (simple variable)
3. "ls *.txt"                             (simple glob)
4. "grep $PATTERN *.log"                  (variable + glob)
5. "cat $(find .)"                        (subshell)
```

### Expected Results
```
Command                          Time (μs)  Overhead
----------------------------------------------
cat file.txt                     12         0%
cat $FILE                        15         +25%
ls *.txt                         18         +50%
grep $PATTERN *.log              22         +83%
cat $(find .)                    35        +191%
```

### Acceptability
- **< 50μs**: Excellent (all recommended features)
- **50-100μs**: Acceptable (with optimization)
- **> 100μs**: Too slow (avoid or optimize heavily)

## Security Impact Analysis

### Variable Support
**Risk:** Low
- Variables resolved by shell, not by us
- Tokenizer just identifies variable syntax
- No execution or resolution

### Globbing Support
**Risk:** Low
- Globbing handled by shell
- Tokenizer identifies patterns only
- No file system access

### Subshell Support
**Risk:** Medium
- Indicates complex shell processing
- Should be marked for caution
- No execution in tokenizer

## Recommended Implementation Order

### Phase 1: Basic Variables (Immediate)
- Simple `$VAR` and `${VAR}` syntax
- Special variables `$1`, `$#`, `$?`, `$$`
- Quoted variable detection
- **Time:** 1-2 days
- **Performance:** +5-10μs

### Phase 2: Globbing (Short-term)
- `*` and `?` wildcards
- Simple `[abc]` character classes
- **Time:** 2-3 days
- **Performance:** +10-15μs

### Phase 3: Subshells (Conditional)
- `$(command)` syntax
- Legacy `` `command` `` syntax
- **Time:** 3-5 days
- **Performance:** +20-30μs

## Code Examples

### Variable Tokenization
```c
// In shell_tokenizer.c
static bool parse_variable(shell_tokenizer_state_t* state, shell_token_t* token) {
    if (state->position >= state->length) return false;

    char current = state->input[state->position];
    if (current != '$') return false;

    size_t start = state->position;
    state->position++; // Skip '$'

    // Check for ${VAR} format
    if (state->position < state->length && state->input[state->position] == '{') {
        state->position++; // Skip '{'
        while (state->position < state->length) {
            char c = state->input[state->position];
            if (c == '}') {
                state->position++;
                token->type = TOKEN_VARIABLE;
                token->start = state->input + start;
                token->length = state->position - start;
                token->position = start;
                return true;
            }
            if (!isalnum(c) && c != '_') {
                // Invalid variable name
                return false;
            }
            state->position++;
        }
        return false; // Unclosed brace
    }

    // Check for special variables
    if (state->position < state->length) {
        char next = state->input[state->position];
        if (isdigit(next) || next == '#' || next == '?' || next == '$') {
            state->position++;
            token->type = TOKEN_SPECIAL_VAR;
            token->start = state->input + start;
            token->length = state->position - start;
            token->position = start;
            return true;
        }
    }

    // Simple $VAR format
    while (state->position < state->length) {
        char c = state->input[state->position];
        if (!isalnum(c) && c != '_') {
            break;
        }
        state->position++;
    }

    if (state->position > start + 1) { // At least $ + one char
        token->type = TOKEN_VARIABLE;
        token->start = state->input + start;
        token->length = state->position - start;
        token->position = start;
        return true;
    }

    return false;
}
```

### Globbing Detection
```c
// In shell_tokenizer.c
static bool is_glob_pattern(const char* str, size_t length) {
    for (size_t i = 0; i < length; i++) {
        char c = str[i];
        if (c == '*' || c == '?' || c == '[') {
            return true;
        }
    }
    return false;
}

// Modify token classification
if (token->type == TOKEN_ARGUMENT && is_glob_pattern(token->start, token->length)) {
    token->type = TOKEN_GLOB;
}
```

## Testing Strategy

### Unit Tests
```c
// Test variable detection
TEST("cat $FILE", "Should detect simple variable")
TEST("echo ${USER}", "Should detect brace variable")
TEST("check $1", "Should detect special variable")

// Test globbing detection
TEST("ls *.txt", "Should detect glob pattern")
TEST("rm file?.log", "Should detect glob pattern")

// Test subshell detection
TEST("cat $(find .)", "Should detect subshell")
TEST("grep `ls`", "Should detect backtick subshell")
```

### Performance Tests
```c
// Benchmark variable processing
BENCHMARK("cat $FILE", 10000, "Variable processing")
BENCHMARK("ls *.txt", 10000, "Glob processing")

// Ensure performance targets met
ASSERT(benchmark_result < 50, "Performance target met")
```

### Security Tests
```c
// Test variable boundary conditions
TEST("$A", "Should handle single char variable")
TEST("$VERY_LONG_VARIABLE_NAME", "Should handle long variable")
TEST("${}", "Should handle empty brace variable")

// Test globbing edge cases
TEST("*", "Should handle single star")
TEST("[", "Should handle unclosed bracket")
```

## Conclusion

### Recommended Implementation
1. **Immediate**: Basic variable support (`$VAR`, `${VAR}`, special vars)
2. **Short-term**: Simple globbing support (`*`, `?`, `[abc]`)
3. **Conditional**: Subshell detection (if performance acceptable)

### Performance Budget
- **Target**: Keep total processing under 50μs
- **Current**: ~15μs baseline
- **Available**: ~35μs for new features

### Security Guarantees
- No variable resolution (shell handles it)
- No glob expansion (shell handles it)
- No subshell execution (shell handles it)
- Tokenizer only identifies syntax

This approach provides meaningful shell syntax support while maintaining the performance and security requirements of the ReadOnlyBox system.