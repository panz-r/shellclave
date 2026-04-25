#!/usr/bin/env python3
"""
gen_lattice_tables.py - Generate join and compatibility tables from a declarative lattice.

Usage:
    python3 tools/gen_lattice_tables.py          # generate C tables to stdout
    python3 tools/gen_lattice_tables.py --diff   # diff generated vs current hand-coded tables

The lattice is defined as a list of chains (directed from specific to general).
The script computes the transitive closure to derive the partial order,
then computes the join table and compatibility table.

Adding a new type requires only adding it to the appropriate chains.
"""

import re
import sys
from typing import Dict, List, Set

# ------------------------------------------------------------------
# Declarative lattice definition
# ------------------------------------------------------------------
# Each chain lists types from most specific to most general.
# The script computes the partial order via transitive closure.

TYPE_ORDER: List[str] = [
    "LITERAL",
    "HEXHASH",
    "NUMBER",
    "IPV4",
    "WORD",
    "QUOTED",
    "QUOTED_SPACE",
    "FILENAME",
    "REL_PATH",
    "ABS_PATH",
    "PATH",
    "URL",
    "VALUE",
    "OPT",
    "UUID",
    "EMAIL",
    "HOSTNAME",
    "PORT",
    "SIZE",
    "SEMVER",
    "TIMESTAMP",
    "HASH_ALGO",
    "ENV_VAR",
    "HYPHENATED",
    "ANY",
]

# Chains: specific -> general
# LITERAL is NOT included in chains. It is the universal bottom:
# LITERAL ≤ X is true for ALL X (compatible(LITERAL, X) = true for all X).
# This means a literal token matches ANY wildcard policy type.
# Every other type is INCOMPARABLE with LITERAL.
#
# PORT appears in two separate chains: PORT ⊂ NUMBER ⊂ VALUE ⊂ ANY
# and PORT ⊂ IPV4 ⊂ VALUE ⊂ ANY. The union of both chains gives the
# correct transitive closure: PORT ≤ {NUMBER, IPV4, VALUE, ANY}.
CHAINS: List[List[str]] = [
    ["HEXHASH", "NUMBER", "VALUE", "ANY"],
    ["IPV4", "VALUE", "ANY"],
    ["WORD", "VALUE", "ANY"],
    ["QUOTED", "QUOTED_SPACE", "VALUE", "ANY"],
    ["FILENAME", "REL_PATH", "PATH", "ANY"],
    ["ABS_PATH", "PATH", "ANY"],
    ["URL", "ANY"],
    ["OPT", "VALUE", "ANY"],
    ["UUID", "VALUE", "ANY"],
    ["EMAIL", "VALUE", "ANY"],
    ["HOSTNAME", "VALUE", "ANY"],
    ["PORT", "NUMBER", "VALUE", "ANY"],
    ["PORT", "IPV4", "VALUE", "ANY"],
    ["SIZE", "VALUE", "ANY"],
    ["SEMVER", "VALUE", "ANY"],
    ["TIMESTAMP", "VALUE", "ANY"],
    ["HASH_ALGO", "WORD", "VALUE", "ANY"],
    ["ENV_VAR", "VALUE", "ANY"],
    ["HYPHENATED", "WORD", "VALUE", "ANY"],
]

# ------------------------------------------------------------------
# Compute partial order via transitive closure
# ------------------------------------------------------------------

def build_le_map() -> Dict[str, Set[str]]:
    """Compute le[a] = {b | a ≤ b} via transitive closure of chains.

    Model: each chain lists types from MOST SPECIFIC to MOST GENERAL.
    For every chain a -> b -> c -> ..., we derive a ≤ b, a ≤ c, b ≤ c, ...

    Example (from lattice):
      HEXHASH ⊂ NUMBER ⊂ VALUE ⊂ ANY
    means: HEXHASH ≤ NUMBER, HEXHASH ≤ VALUE, HEXHASH ≤ ANY,
           NUMBER ≤ VALUE, NUMBER ≤ ANY, VALUE ≤ ANY.
    So: le[HEXHASH] = {HEXHASH, NUMBER, VALUE, ANY}.

    LITERAL is the universal bottom: le[LITERAL] = {LITERAL, X for all X},
    meaning LITERAL ≤ X for all X. This makes compatible(LITERAL, X) = true
    (a literal token matches any policy type). LITERAL has no chains.
    """
    le: Dict[str, Set[str]] = {t: {t} for t in TYPE_ORDER}

    # LITERAL is the universal bottom: LITERAL ≤ X for all X.
    # compatible(LITERAL, X) = true for all X.
    le["LITERAL"] = set(TYPE_ORDER)

    # Build direct edges from chains (index i ≤ index i+1)
    for chain in CHAINS:
        for i, specific in enumerate(chain):
            for j in range(i + 1, len(chain)):
                le[specific].add(chain[j])

    # Transitive closure
    changed = True
    while changed:
        changed = False
        for a in TYPE_ORDER:
            for b in list(le[a]):
                added = len(le[a])
                le[a] |= le.get(b, set())
                if len(le[a]) > added:
                    changed = True
    return le


def build_le_matrix(le: Dict[str, Set[str]]) -> Dict[str, Dict[str, bool]]:
    """Return le_matrix[a][b] = (a ≤ b).

    This is the "compatibility" direction used by st_is_compatible(cmd, policy):
    returns true iff cmd_type ≤ policy_type (i.e., cmd is covered by policy).
    """
    return {a: {b: b in le[a] for b in TYPE_ORDER} for a in TYPE_ORDER}


def join_matrix(le: Dict[str, Set[str]]) -> Dict[str, Dict[str, str]]:
    """Compute join[a][b] = least upper bound of a and b.

    The join is the most specific type that is ≥ both a and b.
    This matches the hand-coded st_type_join semantics:
      st_type_join[a][b] = narrowest type covering both a and b

    Examples from the lattice:
      join(HEXHASH, NUMBER) = NUMBER  (NUMBER covers both)
      join(NUMBER, IPV4)     = VALUE   (VALUE covers both, nothing more specific does)
      join(LITERAL, X)       = X       (X covers LITERAL and X)

    If a and b are incomparable (no common ancestor above them), the join
    defaults to ANY (the top element).
    """
    join: Dict[str, Dict[str, str]] = {}
    for a in TYPE_ORDER:
        join[a] = {}
        for b in TYPE_ORDER:
            # Identity: join(LITERAL, X) = join(X, LITERAL) = X
            if a == "LITERAL":
                join[a][b] = b
                continue
            if b == "LITERAL":
                join[a][b] = a
                continue
            # Candidates: types that are ≥ both a and b
            candidates = le[a] & le[b]
            # Walk TYPE_ORDER from specific to general; pick the first c
            # such that c is above ALL other candidates: ∀d ∈ candidates: d ∈ le[c].
            for c in TYPE_ORDER:
                if c == "LITERAL":
                    continue
                if c in candidates:
                    is_lub = True
                    for d in candidates:
                        if d != c and d not in le[c]:
                            is_lub = False
                            break
                    if is_lub:
                        join[a][b] = c
                        break
            # If no common ancestor found, use ANY (top element)
            if join[a][b] not in candidates:
                join[a][b] = "ANY"
    return join


# ------------------------------------------------------------------
# Type name utilities
# ------------------------------------------------------------------

def to_enum(name: str) -> str:
    return "ST_TYPE_" + name


def symbol(name: str) -> str:
    symbols = {
        "LITERAL": '""',
        "HEXHASH": '"#h"',
        "NUMBER": '"#n"',
        "IPV4": '"#i"',
        "WORD": '"#w"',
        "QUOTED": '"#q"',
        "QUOTED_SPACE": '"#qs"',
        "FILENAME": '"#f"',
        "REL_PATH": '"#r"',
        "ABS_PATH": '"#p"',
        "PATH": '"#path"',
        "URL": '"#u"',
        "VALUE": '"#val"',
        "OPT": '"#opt"',
        "UUID": '"#uuid"',
        "EMAIL": '"#email"',
        "HOSTNAME": '"#host"',
        "PORT": '"#port"',
        "SIZE": '"#size"',
        "SEMVER": '"#semver"',
        "TIMESTAMP": '"#ts"',
        "HASH_ALGO": '"#hash"',
        "ENV_VAR": '"#env"',
        "HYPHENATED": '"#hyp"',
        "ANY": '"*"',
    }
    return symbols[name]


# ------------------------------------------------------------------
# C code generation
# ------------------------------------------------------------------

def generate_symbol_table() -> str:
    lines = ["const char *st_type_symbol[ST_TYPE_COUNT] = {",
             "    [ST_TYPE_LITERAL]       = \"\","]
    for name in TYPE_ORDER[1:]:
        lines.append(f"    [ST_TYPE_{name}]      = {symbol(name)},")
    lines.append("};")
    return "\n".join(lines)


def header_comment() -> str:
    return """/*
 * normalize.c - Command normalisation with typed wildcard lattice.
 *
 * Classifies each token into the most specific type in the lattice.
 * Provides join and compatibility tables for policy generation and verification.
 *
 * NOTE: st_type_join and st_type_compatible are generated by tools/gen_lattice_tables.py
 * from a declarative lattice definition in that script. Do not edit these tables by hand;
 * instead update the lattice definition and regenerate.
 */"""


def generate_join_table(join: Dict[str, Dict[str, str]]) -> str:
    abbrevs = {
        "LITERAL": "LIT", "HEXHASH": "HEX", "NUMBER": "NUM", "IPV4": "IPV4",
        "WORD": "WORD", "QUOTED": "QOT", "QUOTED_SPACE": "QS", "FILENAME": "FILE",
        "REL_PATH": "REL", "ABS_PATH": "ABS", "PATH": "PATH", "URL": "URL",
        "VALUE": "VAL", "OPT": "OPT", "UUID": "UUID", "EMAIL": "EMAIL",
        "HOSTNAME": "HOST", "PORT": "PORT", "SIZE": "SIZE", "SEMVER": "SEMV",
        "TIMESTAMP": "TS", "HASH_ALGO": "HASH", "ENV_VAR": "ENV",
        "HYPHENATED": "HYP", "ANY": "ANY",
    }
    lines = [
        "/* ============================================================",
        " * JOIN TABLE",
        " *",
        " * st_type_join[a][b] = narrowest type covering both a and b.",
        " *",
        " * Lattice:",
        " *   #h ⊂ #n ⊂ #val ⊂ *",
        " *   #i ⊂ #val ⊂ *",
        " *   #w ⊂ #val ⊂ *",
        " *   #q ⊂ #qs ⊂ #val ⊂ *",
        " *   #f ⊂ #r ⊂ #path ⊂ *",
        " *   #p ⊂ #path ⊂ *",
        " *   #u ⊂ *",
        " *   #opt ⊂ #val ⊂ *",
        " *   #uuid, #email, #host, #size, #semver, #ts, #env ⊂ #val ⊂ *",
        " *   #port ⊂ #n, #port ⊂ #i, #port ⊂ #val ⊂ *",
        " *   #hash, #hyp ⊂ #w ⊂ #val ⊂ *",
        " * ============================================================ */",
        "",
        "const st_token_type_t st_type_join[ST_TYPE_COUNT][ST_TYPE_COUNT] = {",
        "    /*                " + "  ".join(f"{abbrevs[t]:4}" for t in TYPE_ORDER) + " */",
    ]
    for a in TYPE_ORDER:
        row_vals = [to_enum(join[a][b]) for b in TYPE_ORDER]
        lines.append(f"    /* ST_TYPE_{a} */")
        lines.append("    { " + ", ".join(row_vals) + " },")
    lines.append("};")
    return "\n".join(lines)


def generate_compat_table(le_matrix: Dict[str, Dict[str, bool]]) -> str:
    lines = [
        "/* ============================================================",
        " * COMPATIBILITY TABLE",
        " *",
        " * st_type_compatible[cmd_type][policy_type] = true iff cmd_type ≤ policy_type.",
        " * A command token of cmd_type matches a policy node of policy_type.",
        " *",
        " * Derived from the same lattice via transitive closure.",
        " * ============================================================ */",
        "",
        "const bool st_type_compatible[ST_TYPE_COUNT][ST_TYPE_COUNT] = {",
    ]
    for a in TYPE_ORDER:
        matches = [b for b in TYPE_ORDER if le_matrix[a][b]]
        lines.append(f"    /* ST_TYPE_{a} matches: " + ", ".join(matches) + " */")
        row_vals = ["true" if le_matrix[a][b] else "false" for b in TYPE_ORDER]
        lines.append("    { " + ", ".join(row_vals) + " },")
    lines.append("};")
    return "\n".join(lines)


# ------------------------------------------------------------------
# Diff helper
# ------------------------------------------------------------------

def parse_hand_coded_tables(c: str) -> tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """Parse the hand-coded join and compat tables from a C source file."""
    join_start = c.find("const st_token_type_t st_type_join[")
    compat_start = c.find("const bool st_type_compatible[")
    join_text = c[join_start:compat_start] if join_start >= 0 and compat_start >= 0 else ""
    compat_text = c[compat_start:] if compat_start >= 0 else ""

    join_pat = re.compile(r'/\*\s*ST_TYPE_(\w+)[^}]*?\{([^}]+)\}')
    compat_pat = re.compile(r'/\*\s*ST_TYPE_(\w+)[^}]*?\{([^}]+)\}')

    rows_j = {}
    for m in join_pat.finditer(join_text):
        rows_j[m.group(1)] = [x.strip() for x in m.group(2).split(',')]

    rows_c = {}
    for m in compat_pat.finditer(compat_text):
        rows_c[m.group(1)] = [x.strip() for x in m.group(2).split(',')]

    return rows_j, rows_c


def main() -> None:
    le = build_le_map()
    le_matrix = build_le_matrix(le)
    join = join_matrix(le)

    if len(sys.argv) > 1 and sys.argv[1] == "--diff":
        path = sys.argv[2] if len(sys.argv) > 2 else "src/normalize.c"
        with open(path) as f:
            current = f.read()

        cur_j, cur_c = parse_hand_coded_tables(current)

        print("=== JOIN TABLE DIFF ===")
        for a in TYPE_ORDER:
            gen_row = [join[a][b] for b in TYPE_ORDER]
            if a in cur_j:
                cur_vals = cur_j[a]
                diffs = []
                for bi, b in enumerate(TYPE_ORDER):
                    if bi < len(cur_vals):
                        gen_val = gen_row[bi]
                        cur_val = cur_vals[bi].replace("ST_TYPE_", "")
                        if cur_val != gen_val:
                            diffs.append(f"{b}: hand={cur_val} gen={gen_val}")
                if diffs:
                    print(f"  ST_TYPE_{a}:")
                    for d in diffs:
                        print(f"    col[{d}]")
                else:
                    print(f"  ST_TYPE_{a}: OK")
            else:
                print(f"  ST_TYPE_{a}: MISSING in current")

        print()
        print("=== COMPAT TABLE DIFF ===")
        for a in TYPE_ORDER:
            gen_row = ["true" if le_matrix[a][b] else "false" for b in TYPE_ORDER]
            if a in cur_c:
                cur_vals = cur_c[a]
                diffs = []
                for bi, b in enumerate(TYPE_ORDER):
                    if bi < len(cur_vals):
                        if cur_vals[bi] != gen_row[bi]:
                            diffs.append(f"{b}: hand={cur_vals[bi]} gen={gen_row[bi]}")
                if diffs:
                    print(f"  ST_TYPE_{a}:")
                    for d in diffs:
                        print(f"    col[{d}]")
                else:
                    print(f"  ST_TYPE_{a}: OK")
            else:
                print(f"  ST_TYPE_{a}: MISSING in current")
        return

    # Generate C tables to stdout
    print(header_comment())
    print()
    print('#include "shelltype.h"')
    print()
    print("#include <ctype.h>")
    print("#include <stdbool.h>")
    print("#include <stdio.h>")
    print("#include <stdlib.h>")
    print("#include <string.h>")
    print("#include <strings.h>")
    print()
    print("/* ============================================================")
    print(" * TYPE SYMBOLS")
    print(" * ============================================================ */")
    print()
    print(generate_symbol_table())
    print()
    print(generate_join_table(join))
    print()
    print(generate_compat_table(le_matrix))
    print()
    print("/* ============================================================")
    print(" * CLASSIFICATION HELPERS")
    print(" * ============================================================ */")
    print("/* NOTE: The following section (classification helpers + public API)")
    print(" * is NOT generated. It follows the table section above.")
    print(" * Copy it from the original normalize.c file.")
    print(" */")


if __name__ == "__main__":
    main()
