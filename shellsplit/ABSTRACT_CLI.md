# Shell Abstract CLI Tool

A command-line tool for abstracting shell commands into DFA-friendly forms for validation.

## Building

```bash
cd shellsplit
make tools/shell_abstract_cli
```

## Basic Usage

### Pass command as argument

```bash
./tools/shell_abstract_cli "grep $PATTERN /etc/passwd"
```

### Read from file

Commands can be stored in a file (one per line):

```bash
./tools/shell_abstract_cli -f commands.txt
```

### Interactive mode

Run without arguments to enter interactive mode:

```bash
./tools/shell_abstract_cli
# Type commands, Ctrl-D to exit
```

## Options

| Option | Description |
|--------|-------------|
| `-f <file>` | Read commands from file (one per line) |
| `-e <env>` | Add environment variable (VAR=value) |
| `-c <cwd>` | Set current working directory |
| `-x` | Expand variables using environment |
| `-h` | Show help |

## Examples

### Environment variables

```bash
$ ./tools/shell_abstract_cli "echo $PATH"

--- Results ---
Original:    echo $PATH
Abstracted:  echo $EV_1

[0] $EV_1
    Type: EV
    Original: $PATH
    Abstracted: $EV_1
    Var name: PATH
```

### Absolute paths

```bash
$ ./tools/shell_abstract_cli "cat /etc/passwd /etc/hosts"

--- Results ---
Original:    cat /etc/passwd /etc/hosts
Abstracted:  cat $AP_1 $AP_2
Elements:    2

[0] $AP_1
    Type: AP
    Original: /etc/passwd
    
[1] $AP_2
    Type: AP
    Original: /etc/hosts
```

### Home paths with expansion

```bash
$ ./tools/shell_abstract_cli -x -e "HOME=/home/testuser" "ls ~/documents"

--- Expansion ---
$HP_1 -> /home/testuser/documents
```

### Glob patterns

```bash
$ ./tools/shell_abstract_cli "ls *.txt"

--- Results ---
Abstracted:  ls $GB_1

[0] $GB_1
    Type: GB
    Original: *.txt
    Glob pattern: *.txt
```

### Command substitution

```bash
$ ./tools/shell_abstract_cli "cat $(cat file.txt)"

--- Results ---
Abstracted:  cat $CS_1

[0] $CS_1
    Type: CS
    Original: $(cat file.txt)
    Command: cat file.txt
```

## Abstraction Types

| Type | Code | Example | Abstracted |
|------|------|---------|------------|
| Environment Variable | EV | `$PATH` | `$EV_1` |
| Positional Variable | PV | `$1`, `${10}` | `$PV_1` |
| Special Variable | SV | `$?`, `$$` | `$SV_1` |
| Absolute Path | AP | `/etc/passwd` | `$AP_1` |
| Relative Path | RP | `./foo`, `../bar` | `$RP_1` |
| Home Path | HP | `~/file` | `$HP_1` |
| Glob Pattern | GB | `*.txt`, `file?.log` | `$GB_1` |
| Command Substitution | CS | `$(cmd)`, `` `cmd` `` | `$CS_1` |
| Arithmetic | AR | `$((x+1))` | `$AR_1` |
| Quoted String | STR | `"hello"` | `$STR_1` |

## Path Categories

For validation, paths are categorized:

| Category | Prefix |
|----------|--------|
| PATH_ROOT | `/` |
| PATH_ETC | `/etc/` |
| PATH_VAR | `/var/` |
| PATH_USR | `/usr/` |
| PATH_HOME | `/home/`, `/root/` |
| PATH_TMP | `/tmp/` |
| PATH_PROC | `/proc/` |
| PATH_SYS | `/sys/` |
| PATH_DEV | `/dev/` |
| PATH_OPT | `/opt/` |
| PATH_SRV | `/srv/` |
| PATH_RUN | `/run/` |
| PATH_OTHER | Other |

## Output Format

The tool provides detailed output:

- **Original**: The raw input command
- **Abstracted**: The abstracted form for DFA matching
- **Elements**: All extracted elements with type-specific data
- **Flags**: Boolean flags indicating what features are present
- **Expansion** (with `-x`): Resolved values for variables/paths

This information can be used for:
1. DFA pattern matching on the abstracted command
2. Validation of extracted elements based on command type
3. Runtime expansion and resolution of variables
