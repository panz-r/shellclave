#ifndef SHELLSPLIT_BRACE_FUZZ_CASE_H
#define SHELLSPLIT_BRACE_FUZZ_CASE_H

#include "shell_processor.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct shell_brace_fuzz_io_t {
  std::string spelling;
  shell_group_io_kind_t kind;
  uint32_t fd;
  uint32_t target_fd;
  uint16_t group_depth;
  bool artifact_relation;
  size_t source_offset;

  shell_brace_fuzz_io_t(const std::string &spelling_value,
                        shell_group_io_kind_t kind_value, uint32_t fd_value,
                        uint32_t target_fd_value, uint16_t group_depth_value,
                        bool artifact_relation_value)
      : spelling(spelling_value), kind(kind_value), fd(fd_value),
        target_fd(target_fd_value), group_depth(group_depth_value),
        artifact_relation(artifact_relation_value), source_offset(0) {}
};

/* Shared, byte-driven supported-dialect inputs for the Shellsplit and
 * Shellgate fuzzers. Heredoc bodies deliberately live after the complete
 * command line, matching shell syntax rather than the AST test generator. */
struct shell_brace_fuzz_case_t {
  std::string command;
  bool valid;
  bool strict_valid;
  /* The lexical tokenizer deliberately retains some incomplete expansions so
   * callers can report source locations; the processor and semantic graph
   * must still reject them. */
  bool tokenizer_tolerates_malformed = false;
  uint32_t command_count;
  uint32_t group_count;
  uint32_t group_io_count;
  uint32_t document_count;
  uint32_t read_count;
  uint32_t group_command_count = 0;
  uint32_t pipe_count = 0;
  uint32_t write_count = 0;
  uint32_t dup_count = 0;
  uint32_t close_count = 0;
  bool sensitive_write = false;
  bool outer_subshell = false;
  /* Sibling groups can own distinct external I/O. These cases still check
   * membership and endpoint shape, but cannot use the uniform inherited-I/O
   * assertions for one enclosing group. */
  bool heterogeneous_group_io = false;
  /* A document owned by a simple command inside a group retains its READ edge
   * to that command; only trailing group redirects target the GROUP node. */
  bool command_local_documents = false;
  uint32_t deepest_command_count = 0;
  bool has_background_sibling = false;
  uint32_t base_read_count = 0;
  uint32_t base_write_count = 0;
  uint32_t nested_write_count_per_layer = 0;
  std::vector<shell_brace_fuzz_io_t> redirect_ops;
};

static inline shell_brace_fuzz_case_t
shell_brace_fuzz_make_case(const std::string &command, bool valid,
                           bool strict_valid, uint32_t command_count,
                           uint32_t group_count, uint32_t group_io_count,
                           uint32_t document_count, uint32_t read_count) {
  shell_brace_fuzz_case_t item = {};
  item.command = command;
  item.valid = valid;
  item.strict_valid = strict_valid;
  item.command_count = command_count;
  item.group_count = group_count;
  item.group_io_count = group_io_count;
  item.document_count = document_count;
  item.read_count = read_count;
  return item;
}

static inline void shell_brace_fuzz_add_redirect(
    shell_brace_fuzz_case_t *item, const std::string &spelling,
    shell_group_io_kind_t kind, uint32_t fd, uint32_t target_fd,
    uint16_t group_depth, bool artifact_relation) {
  item->redirect_ops.emplace_back(spelling, kind, fd, target_fd, group_depth,
                                  artifact_relation);
}

static inline void
shell_brace_fuzz_finalize_redirects(shell_brace_fuzz_case_t *item) {
  for (shell_brace_fuzz_io_t &expected : item->redirect_ops) {
    size_t offset = item->command.find(expected.spelling);
    if (offset == std::string::npos)
      offset = item->command.size();
    expected.source_offset = offset;
  }
  std::sort(item->redirect_ops.begin(), item->redirect_ops.end(),
            [](const shell_brace_fuzz_io_t &left,
               const shell_brace_fuzz_io_t &right) {
              return left.source_offset < right.source_offset;
            });
}

static inline uint8_t shell_brace_fuzz_byte(const uint8_t *data, size_t size,
                                            size_t index) {
  return size == 0 ? 0 : data[index % size];
}

static inline shell_brace_fuzz_case_t shell_brace_fuzz_case(const uint8_t *data,
                                                            size_t size) {
  static const char *const commands[] = {"echo", "printf", "cat", "sort"};
  const char *first = commands[shell_brace_fuzz_byte(data, size, 1) % 4];
  const char *second = commands[shell_brace_fuzz_byte(data, size, 2) % 4];
  const char *eol = shell_brace_fuzz_byte(data, size, 3) & 1 ? "\r\n" : "\n";
  uint8_t form = shell_brace_fuzz_byte(data, size, 0);
  if (form % 64 == 60) {
    shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
        "{ cat; cat; } <<E'OF' <<-\\D'ONE'\n}\nEOF\n\t$( { id; } )\n\tDONE\n",
        true, true, 2, 1, 2, 2, 1);
    item.group_command_count = 2;
    item.deepest_command_count = 2;
    /* Both trailing documents belong to the brace execution endpoint. The
     * final descriptor-0 redirect is therefore inherited by each member. */
    item.base_read_count = 1;
    shell_brace_fuzz_add_redirect(&item, "<<E'OF'", SHELL_GROUP_IO_HEREDOC, 0,
                                  UINT32_MAX, 1, true);
    shell_brace_fuzz_add_redirect(&item, "<<-\\D'ONE'", SHELL_GROUP_IO_HEREDOC,
                                  0, UINT32_MAX, 1, true);
    shell_brace_fuzz_finalize_redirects(&item);
    return item;
  }
  if (form % 64 == 61) {
    shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
        "{ cat; cat; } <<\"E\\qF\" <<''\nfirst\nE\\qF\n\n", true, true, 2, 1, 2,
        2, 1);
    item.group_command_count = 2;
    item.deepest_command_count = 2;
    item.base_read_count = 1;
    shell_brace_fuzz_add_redirect(&item, "<<\"E\\qF\"", SHELL_GROUP_IO_HEREDOC,
                                  0, UINT32_MAX, 1, false);
    shell_brace_fuzz_add_redirect(&item, "<<''", SHELL_GROUP_IO_HEREDOC, 0,
                                  UINT32_MAX, 1, true);
    shell_brace_fuzz_finalize_redirects(&item);
    return item;
  }
  if (form % 64 == 59) {
    shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
        "{ cat <<\"A B\"; printf after; }\nbody\nA B\n", true, true, 2, 1, 0, 1,
        1);
    item.group_command_count = 2;
    item.deepest_command_count = 2;
    item.command_local_documents = true;
    return item;
  }
  if (form % 64 == 58) {
    shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
        "{ cat <<<value; printf after; }", true, true, 2, 1, 0, 1, 1);
    item.group_command_count = 2;
    item.deepest_command_count = 2;
    item.command_local_documents = true;
    return item;
  }
  if (form % 16 == 13) {
    shell_brace_fuzz_case_t item =
        shell_brace_fuzz_make_case("{ " + std::string(first) + " one; } | { " +
                                       second + "; } && { printf done; }",
                                   true, true, 3, 3, 2, 0, 0);
    item.group_command_count = 3;
    item.pipe_count = 1;
    item.deepest_command_count = 3;
    return item;
  }
  if (form % 32 == 12) {
    shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
        "{ printf left; } 3>/tmp/left | { cat; } 2>>/tmp/right && "
        "{ printf tail; }",
        true, true, 3, 3, 4, 0, 0);
    item.group_command_count = 3;
    item.pipe_count = 1;
    item.write_count = 2;
    item.heterogeneous_group_io = true;
    item.deepest_command_count = 3;
    shell_brace_fuzz_add_redirect(&item, "3>/tmp/left",
                                  SHELL_GROUP_IO_WRITE_FILE, 3, UINT32_MAX, 1,
                                  true);
    shell_brace_fuzz_add_redirect(&item, "2>>/tmp/right",
                                  SHELL_GROUP_IO_APPEND_FILE, 2, UINT32_MAX, 1,
                                  true);
    shell_brace_fuzz_finalize_redirects(&item);
    return item;
  }
  if (form % 32 == 11) {
    shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
        "{ printf source; } <<'EOF' | { cat; } > /tmp/right && "
        "{ printf tail; }\n"
        "payload\n"
        "EOF\n",
        true, true, 3, 3, 4, 1, 1);
    item.group_command_count = 3;
    item.pipe_count = 1;
    item.write_count = 1;
    item.heterogeneous_group_io = true;
    item.deepest_command_count = 3;
    shell_brace_fuzz_add_redirect(&item, "<<'EOF'", SHELL_GROUP_IO_HEREDOC, 0,
                                  UINT32_MAX, 1, true);
    shell_brace_fuzz_add_redirect(&item, "> /tmp/right",
                                  SHELL_GROUP_IO_WRITE_FILE, 1, UINT32_MAX, 1,
                                  true);
    shell_brace_fuzz_finalize_redirects(&item);
    return item;
  }
  if (form % 16 >= 14) {
    uint32_t depth = form % 16 == 14 ? SHELL_MAX_GROUPS : SHELL_MAX_GROUPS + 1;
    std::string group = std::string(first) + " deep";
    for (uint32_t i = 0; i < depth; i++)
      group = "{ " + group + "; }";
    shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
        group, depth == SHELL_MAX_GROUPS, depth == SHELL_MAX_GROUPS,
        depth == SHELL_MAX_GROUPS ? 1u : 0u,
        depth == SHELL_MAX_GROUPS ? depth : 0u, 0, 0, 0);
    item.deepest_command_count = depth == SHELL_MAX_GROUPS ? 1u : 0u;
    item.group_command_count = item.deepest_command_count;
    return item;
  }
  if (form % 8 == 7) {
    switch (shell_brace_fuzz_byte(data, size, 4) % 12) {
    case 0:
      return shell_brace_fuzz_make_case("{ " + std::string(first) +
                                            " missing-separator }",
                                        false, false, 0, 0, 0, 0, 0);
    case 1:
      return shell_brace_fuzz_make_case("{ ( " + std::string(first) + "; } )",
                                        false, false, 0, 0, 0, 0, 0);
    case 2:
      return shell_brace_fuzz_make_case("{ " + std::string(first) +
                                            " <<EOF\nbody\n",
                                        false, false, 0, 0, 0, 0, 0);
    case 3:
      return shell_brace_fuzz_make_case("{ " + std::string(first) +
                                            "; } <<EOF\nbody\n",
                                        true, false, 1, 1, 1, 0, 0);
    case 4: {
      shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
          "{ " + std::string(first) + "; } < <(printf", false, false, 0, 0, 0,
          0, 0);
      item.tokenizer_tolerates_malformed = true;
      return item;
    }
    case 5: {
      shell_brace_fuzz_case_t item =
          shell_brace_fuzz_make_case("{ " + std::string(first) + "; } > >(cat",
                                     false, false, 0, 0, 0, 0, 0);
      item.tokenizer_tolerates_malformed = true;
      return item;
    }
    case 6:
      return shell_brace_fuzz_make_case("{ " + std::string(first) +
                                            "; } 3>> (cat)",
                                        false, false, 0, 0, 0, 0, 0);
    /* These are lexically recoverable source strings, but not supported
     * complete commands. Keep them in the strict-only family so fuzzing
     * asserts the same semantic boundary used by canonical APIs and
     * Shellgate without changing the intentionally tolerant lexer contract. */
    case 7:
      return shell_brace_fuzz_make_case(std::string(first) + "; }", true, false,
                                        0, 0, 0, 0, 0);
    case 8:
      return shell_brace_fuzz_make_case(std::string(first) + " | )", true,
                                        false, 0, 0, 0, 0, 0);
    case 9:
      return shell_brace_fuzz_make_case(std::string(first) + " { literal; }",
                                        true, false, 0, 0, 0, 0, 0);
    case 10:
      return shell_brace_fuzz_make_case(
          std::string(first) + " (" + second + ")", true, false, 0, 0, 0, 0, 0);
    default:
      return shell_brace_fuzz_make_case(std::string(first) + " ((1))", true,
                                        false, 0, 0, 0, 0, 0);
    }
  }

  /* Keep generated command counts comfortably below the public limit while
   * exercising materially deeper ownership stacks than the former 0..2
   * range. */
  uint8_t nesting = shell_brace_fuzz_byte(data, size, 4) % 8;
  bool outer_subshell = shell_brace_fuzz_byte(data, size, 7) & 1;
  std::string group = outer_subshell
                          ? "( " + std::string(first) + " one; " + second +
                                " two; " + first + " three; )"
                          : "{ " + std::string(first) + " one; " + second +
                                " two; " + first + " three; }";
  for (uint8_t depth = 0; depth < nesting; depth++) {
    outer_subshell = shell_brace_fuzz_byte(data, size, 8 + depth) & 1;
    std::string input = std::to_string(20u + depth) + ">/tmp/nested-in-" +
                        std::to_string(depth);
    std::string output = std::to_string(40u + depth) + ">/tmp/nested-out-" +
                         std::to_string(depth);
    /* Redirections belong after the nested compound command.  A prefix such
     * as "20>file { ...; }" is not POSIX syntax and must not be emitted as
     * a supposedly valid group case. */
    group = outer_subshell ? "( :; " + group + " " + input + " " + output +
                                 "; " + first + " nested; )"
                           : "{ :; " + group + " " + input + " " + output +
                                 "; " + first + " nested; }";
  }
  uint32_t command_count = 3 + nesting * 2;
  uint32_t group_count = nesting + 1;
  std::string prefix;
  std::string suffix;
  uint8_t redirect_kind = shell_brace_fuzz_byte(data, size, 6) % 8;
  uint8_t composition = shell_brace_fuzz_byte(data, size, 5) % 6;
  /* Deferred heredoc bodies begin only after the complete command line. Keep
   * those fixtures out of the trailing control-list forms, whose ownership is
   * intentionally outside this focused group-I/O oracle. */
  if ((redirect_kind >= 3 && redirect_kind <= 5) || redirect_kind == 7)
    if (composition >= 4)
      composition = 0;
  switch (composition) {
  case 1:
    prefix = "cat /tmp/in | ";
    command_count++;
    break;
  case 2:
    suffix = " | sort";
    command_count++;
    break;
  case 3:
    prefix = "cat /tmp/in | ";
    suffix = " | sort";
    command_count += 2;
    break;
  case 4:
    suffix = " && printf tail";
    command_count++;
    break;
  case 5:
    suffix = " & { printf tail; }";
    command_count++;
    group_count++;
    break;
  default:
    break;
  }

  uint32_t document_count = 0;
  uint32_t read_count = 0;
  uint32_t pipe_count = (composition == 1 || composition == 2) ? 1
                        : composition == 3                     ? 2
                                                               : 0;
  uint32_t write_count = nesting * 2;
  uint32_t redirect_op_count = nesting * 2;
  uint32_t dup_count = 0;
  uint32_t close_count = 0;
  bool sensitive_write = false;
  std::string redirect;
  std::string bodies;
  switch (redirect_kind) {
  case 1:
    redirect = " </tmp/in >/tmp/brace-sensitive 2>>/tmp/err 6>&1 4<&0 5>&-";
    /* 4<&0 aliases the active input document and 6>&1 aliases the active
     * stdout document.  The stdout redirect also supersedes any outgoing
     * pipeline before the duplicate is evaluated. */
    read_count = 2;
    write_count += 3;
    redirect_op_count += 6;
    dup_count = 2;
    close_count = 1;
    sensitive_write = true;
    break;
  case 2:
    redirect = " <<< \"two words\"";
    document_count = 1;
    read_count = 1;
    redirect_op_count++;
    break;
  case 3:
    redirect = " <<EOF";
    bodies = std::string(eol) + "payload" + eol + "EOF" + eol;
    document_count = 1;
    read_count = 1;
    redirect_op_count++;
    break;
  case 4:
    redirect = " <<-'EOF'";
    bodies = std::string(eol) + "\tpayload" + eol + "\tEOF" + eol;
    document_count = 1;
    read_count = 1;
    redirect_op_count++;
    break;
  case 5:
    redirect = " <<A <<-'B'";
    bodies = std::string(eol) + "one" + eol + "A" + eol + "\ttwo" + eol +
             "\tB" + eol;
    document_count = 2;
    /* Both heredocs remain syntax documents, but the later redirect owns
     * descriptor 0 and is the only effective document input. */
    read_count = 1;
    redirect_op_count += 2;
    break;
  case 6:
    redirect = " 3>/tmp/trace 4<&0 5>&- </tmp/in 6>&1 8<&0 9>&-";
    /* 4<&0 precedes the document, so it can retain an incoming pipeline;
     * 8<&0 follows the document and aliases that document input. */
    read_count = 2;
    write_count++;
    redirect_op_count += 7;
    dup_count = 3;
    close_count = 2;
    break;
  case 7:
    redirect = " 4<&0 5>&- <<-'EOF' 3>\"/tmp/trace file\" 6>&1";
    bodies = std::string(eol) + "\tpayload" + eol + "\tEOF" + eol;
    document_count = 1;
    read_count = 1;
    write_count++;
    redirect_op_count += 5;
    dup_count = 2;
    close_count = 1;
    break;
  default:
    break;
  }
  /* A group-owned stdin redirect supersedes an incoming pipeline at fd 0.
   * The graph retains that producer-to-terminal-pipe relation: the writer
   * still exists even though the group no longer consumes its original read
   * descriptor.  Only redirect kinds 6 and 7 need to remove the initial edge
   * temporarily: their source-order 4<&0 duplicate preserves a live group
   * read endpoint, which the accounting below adds back explicitly. */
  if ((redirect_kind == 6 || redirect_kind == 7) &&
      (composition == 1 || composition == 3))
    pipe_count--;
  /* Redirection and descriptor duplication have source-order semantics. A
   * direct stdout redirect replaces an outgoing pipe; the other duplicate
   * forms retain the pipe endpoint that was live when the duplicate appeared.
   */
  if (redirect_kind == 1 && (composition == 2 || composition == 3))
    pipe_count--;
  if (redirect_kind == 6) {
    if (composition == 1 || composition == 3)
      pipe_count++;
    if (composition == 2 || composition == 3)
      pipe_count++;
  } else if (redirect_kind == 7) {
    /* 4<&0 retains the incoming pipeline before the heredoc replaces fd 0;
     * 6>&1 also exposes the outgoing pipeline through a second descriptor. */
    if (composition == 1 || composition == 3)
      pipe_count++;
    if (composition == 2 || composition == 3)
      pipe_count++;
  }
  uint32_t group_io_count = redirect_op_count +
                            ((composition == 1 || composition == 2) ? 1
                             : composition == 3                     ? 2
                                                                    : 0) +
                            (composition == 5 ? 1 : 0);
  shell_brace_fuzz_case_t item = shell_brace_fuzz_make_case(
      prefix + group + redirect + suffix + bodies, true, true, command_count,
      group_count, group_io_count, document_count, read_count);
  item.pipe_count = pipe_count;
  item.write_count = write_count;
  item.dup_count = dup_count;
  item.close_count = close_count;
  item.sensitive_write = sensitive_write;
  item.outer_subshell = outer_subshell;
  item.deepest_command_count = 3;
  item.group_command_count =
      item.deepest_command_count + (item.group_count - 1) * 2;
  item.has_background_sibling = composition == 5;
  item.base_read_count = read_count;
  item.base_write_count = write_count - nesting * 2;
  item.nested_write_count_per_layer = 2;
  for (uint8_t depth = 0; depth < nesting; depth++) {
    uint16_t group_depth = (uint16_t)(nesting - depth + 1);
    shell_brace_fuzz_add_redirect(
        &item,
        std::to_string(20u + depth) + ">/tmp/nested-in-" +
            std::to_string(depth),
        SHELL_GROUP_IO_WRITE_FILE, 20u + depth, UINT32_MAX, group_depth, true);
    shell_brace_fuzz_add_redirect(
        &item,
        std::to_string(40u + depth) + ">/tmp/nested-out-" +
            std::to_string(depth),
        SHELL_GROUP_IO_WRITE_FILE, 40u + depth, UINT32_MAX, group_depth, true);
  }
  switch (redirect_kind) {
  case 1:
    shell_brace_fuzz_add_redirect(&item, "</tmp/in", SHELL_GROUP_IO_READ_FILE,
                                  0, UINT32_MAX, 1, true);
    shell_brace_fuzz_add_redirect(&item, ">/tmp/brace-sensitive",
                                  SHELL_GROUP_IO_WRITE_FILE, 1, UINT32_MAX, 1,
                                  true);
    shell_brace_fuzz_add_redirect(&item, "2>>/tmp/err",
                                  SHELL_GROUP_IO_APPEND_FILE, 2, UINT32_MAX, 1,
                                  true);
    shell_brace_fuzz_add_redirect(&item, "6>&1", SHELL_GROUP_IO_DUP_FD, 6, 1, 1,
                                  false);
    shell_brace_fuzz_add_redirect(&item, "4<&0", SHELL_GROUP_IO_DUP_FD, 4, 0, 1,
                                  false);
    shell_brace_fuzz_add_redirect(&item, "5>&-", SHELL_GROUP_IO_CLOSE_FD, 5,
                                  UINT32_MAX, 1, false);
    break;
  case 2:
    shell_brace_fuzz_add_redirect(&item, "<<< \"two words\"",
                                  SHELL_GROUP_IO_HERESTRING, 0, UINT32_MAX, 1,
                                  true);
    break;
  case 3:
    shell_brace_fuzz_add_redirect(&item, "<<EOF", SHELL_GROUP_IO_HEREDOC, 0,
                                  UINT32_MAX, 1, true);
    break;
  case 4:
    shell_brace_fuzz_add_redirect(&item, "<<-'EOF'", SHELL_GROUP_IO_HEREDOC, 0,
                                  UINT32_MAX, 1, true);
    break;
  case 5:
    shell_brace_fuzz_add_redirect(&item, "<<A", SHELL_GROUP_IO_HEREDOC, 0,
                                  UINT32_MAX, 1, false);
    shell_brace_fuzz_add_redirect(&item, "<<-'B'", SHELL_GROUP_IO_HEREDOC, 0,
                                  UINT32_MAX, 1, true);
    break;
  case 6:
    shell_brace_fuzz_add_redirect(&item, "3>/tmp/trace",
                                  SHELL_GROUP_IO_WRITE_FILE, 3, UINT32_MAX, 1,
                                  true);
    shell_brace_fuzz_add_redirect(&item, "4<&0", SHELL_GROUP_IO_DUP_FD, 4, 0, 1,
                                  false);
    shell_brace_fuzz_add_redirect(&item, "5>&-", SHELL_GROUP_IO_CLOSE_FD, 5,
                                  UINT32_MAX, 1, false);
    shell_brace_fuzz_add_redirect(&item, "</tmp/in", SHELL_GROUP_IO_READ_FILE,
                                  0, UINT32_MAX, 1, true);
    shell_brace_fuzz_add_redirect(&item, "6>&1", SHELL_GROUP_IO_DUP_FD, 6, 1, 1,
                                  false);
    shell_brace_fuzz_add_redirect(&item, "8<&0", SHELL_GROUP_IO_DUP_FD, 8, 0, 1,
                                  false);
    shell_brace_fuzz_add_redirect(&item, "9>&-", SHELL_GROUP_IO_CLOSE_FD, 9,
                                  UINT32_MAX, 1, false);
    break;
  case 7:
    shell_brace_fuzz_add_redirect(&item, "4<&0", SHELL_GROUP_IO_DUP_FD, 4, 0, 1,
                                  false);
    shell_brace_fuzz_add_redirect(&item, "5>&-", SHELL_GROUP_IO_CLOSE_FD, 5,
                                  UINT32_MAX, 1, false);
    shell_brace_fuzz_add_redirect(&item, "<<-'EOF'", SHELL_GROUP_IO_HEREDOC, 0,
                                  UINT32_MAX, 1, true);
    shell_brace_fuzz_add_redirect(&item, "3>\"/tmp/trace file\"",
                                  SHELL_GROUP_IO_WRITE_FILE, 3, UINT32_MAX, 1,
                                  true);
    shell_brace_fuzz_add_redirect(&item, "6>&1", SHELL_GROUP_IO_DUP_FD, 6, 1, 1,
                                  false);
    break;
  default:
    break;
  }
  shell_brace_fuzz_finalize_redirects(&item);
  return item;
}

/* Substitution topology has a different contract from ordinary compound
 * groups: the graph represents dynamic bytes rather than merely nesting
 * syntax. Keep these compact cases separate from shell_brace_fuzz_case_t so
 * both fuzzers can assert exact stream endpoints without conflating recursive
 * graph command counts with the processor's immediate command list. */
struct shell_substitution_fuzz_case_t {
  std::string command;
  /* Full-tokenizer/processor records intentionally omit nested substitution
   * producers, unlike the dependency graph and Shellgate. Generated cases
   * retain both views so the fuzzers can verify every public boundary without
   * pretending those APIs expose the same representation. A zero value keeps
   * the legacy fixed topology cases on their existing graph-only contract. */
  uint32_t surface_command_count;
  uint32_t command_count;
  uint32_t group_count;
  uint32_t endpoint_count;
  uint32_t substitution_edge_count;
  uint32_t file_substitution_count;
  uint32_t collector_write_count;
  uint32_t result_dynamic_consumer_count;
  uint32_t command_mapping_count;
  bool requires_substitution_evaluation;
  /* UINT32_MAX leaves the general stream forms unconstrained. Dynamic file
   * names set an exact count so an unflagged command-to-command edge cannot
   * accidentally satisfy their topology contract. */
  uint32_t dynamic_name_substitution_count;
  bool output_process;
  uint32_t outer_fd;
  /* The dynamic-source checks above intentionally describe all substitution
   * forms.  Keep the document-specific expectations separate so that a new
   * implementation cannot accidentally satisfy the stream topology while
   * losing heredoc semantics. */
  uint32_t heredoc_count;
  uint32_t literal_heredoc_count;
  uint32_t transient_heredoc_count;
  uint32_t heredoc_substitution_count;
  uint32_t herestring_count;
  uint32_t herestring_substitution_count;
  /* The fixed matrix also exercises bounded heredoc prescanning. A
   * truncated graph remains structurally valid, but it is not a successful
   * parse or Shellgate evaluation. */
  bool depgraph_truncated;
  /* Boundary redirects belong to GROUP rather than a member command. These
   * optional expectations let the Shellsplit fuzzer verify that ownership and
   * any surviving descriptor-specific pipe route exactly. */
  bool group_substitution_owner;
  uint32_t group_pipe_target_fd;

  shell_substitution_fuzz_case_t(const char *command_value,
                                 uint32_t command_count_value,
                                 uint32_t group_count_value,
                                 uint32_t endpoint_count_value,
                                 uint32_t substitution_edge_count_value,
                                 uint32_t file_substitution_count_value,
                                 uint32_t collector_write_count_value,
                                 uint32_t result_dynamic_consumer_count_value,
                                 uint32_t command_mapping_count_value,
                                 bool requires_substitution_evaluation_value,
                                 bool output_process_value,
                                 uint32_t outer_fd_value)
      : command(command_value), surface_command_count(0),
        command_count(command_count_value), group_count(group_count_value),
        endpoint_count(endpoint_count_value),
        substitution_edge_count(substitution_edge_count_value),
        file_substitution_count(file_substitution_count_value),
        collector_write_count(collector_write_count_value),
        result_dynamic_consumer_count(result_dynamic_consumer_count_value),
        command_mapping_count(command_mapping_count_value),
        requires_substitution_evaluation(
            requires_substitution_evaluation_value),
        dynamic_name_substitution_count(UINT32_MAX),
        output_process(output_process_value), outer_fd(outer_fd_value),
        heredoc_count(0), literal_heredoc_count(0), transient_heredoc_count(0),
        heredoc_substitution_count(0), herestring_count(0),
        herestring_substitution_count(0), depgraph_truncated(false),
        group_substitution_owner(false), group_pipe_target_fd(UINT32_MAX) {}

  shell_substitution_fuzz_case_t(
      const char *command_value, uint32_t command_count_value,
      uint32_t group_count_value, uint32_t endpoint_count_value,
      uint32_t substitution_edge_count_value,
      uint32_t file_substitution_count_value,
      uint32_t collector_write_count_value,
      uint32_t result_dynamic_consumer_count_value,
      uint32_t command_mapping_count_value,
      bool requires_substitution_evaluation_value, bool output_process_value,
      uint32_t outer_fd_value, uint32_t heredoc_count_value,
      uint32_t literal_heredoc_count_value,
      uint32_t transient_heredoc_count_value,
      uint32_t heredoc_substitution_count_value)
      : command(command_value), surface_command_count(0),
        command_count(command_count_value), group_count(group_count_value),
        endpoint_count(endpoint_count_value),
        substitution_edge_count(substitution_edge_count_value),
        file_substitution_count(file_substitution_count_value),
        collector_write_count(collector_write_count_value),
        result_dynamic_consumer_count(result_dynamic_consumer_count_value),
        command_mapping_count(command_mapping_count_value),
        requires_substitution_evaluation(
            requires_substitution_evaluation_value),
        dynamic_name_substitution_count(UINT32_MAX),
        output_process(output_process_value), outer_fd(outer_fd_value),
        heredoc_count(heredoc_count_value),
        literal_heredoc_count(literal_heredoc_count_value),
        transient_heredoc_count(transient_heredoc_count_value),
        heredoc_substitution_count(heredoc_substitution_count_value),
        herestring_count(0), herestring_substitution_count(0),
        depgraph_truncated(false), group_substitution_owner(false),
        group_pipe_target_fd(UINT32_MAX) {}
};

enum {
  SHELL_BRACE_FUZZ_SUBSTITUTION_CASE_COUNT = 69,
  SHELL_BRACE_FUZZ_COMPOSED_SUBSTITUTION_CASE_COUNT = 48,
};

static inline shell_substitution_fuzz_case_t
shell_brace_fuzz_substitution_case(const uint8_t *data, size_t size) {
  switch (shell_brace_fuzz_byte(data, size, 0) %
          SHELL_BRACE_FUZZ_SUBSTITUTION_CASE_COUNT) {
  case 0:
    return {"echo $( { sleep 2; printf q; } | ./clock )",
            4,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            true,
            false,
            1};
  case 1:
    return {"echo $( { printf first; } ; { printf second; } )",
            3,
            2,
            1,
            1,
            0,
            2,
            1,
            0,
            true,
            false,
            1};
  case 2:
    return {"echo $( { printf hidden > /tmp/hidden; } )",
            2,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            false,
            1};
  case 3:
    return {"printf value 2> >(cat)", 2, 0, 1, 1, 0, 1, 1, 0, false, true, 2};
  case 4:
    return {"echo $(</tmp/fuzz-substitution-input)",
            1,
            0,
            0,
            1,
            1,
            0,
            1,
            0,
            true,
            false,
            1};
  case 5:
    return {"echo $( { printf $(date); } )",
            3,
            1,
            0,
            2,
            0,
            0,
            2,
            1,
            true,
            false,
            1};
  case 6:
    return {"echo $(</tmp/one)$(<\"/tmp/two words\")",
            1,
            0,
            0,
            2,
            2,
            0,
            1,
            0,
            true,
            false,
            1};
  case 7:
    return {"{ echo $(</tmp/group-input); }",
            1,
            1,
            0,
            1,
            1,
            0,
            1,
            0,
            true,
            false,
            1};
  case 8:
    return {"echo $( { printf $(</tmp/nested-input); } )",
            2,
            1,
            0,
            2,
            1,
            0,
            2,
            0,
            true,
            false,
            1};
  case 9:
    return {"cat <<EOF\n$(id)\nEOF",
            2,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            true,
            false,
            1,
            1,
            0,
            0,
            1};
  case 10:
    return {"cat <<'EOF'\n$(id)\nEOF",
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            false,
            1,
            1,
            1,
            0,
            0};
  case 11:
    /* The first heredoc is still expanded by the shell even though the later
     * redirect becomes fd 0. It therefore affects the root result without
     * falsely flagging the command as a dynamic consumer. */
    return {"cat <<EOF </dev/null\n$(id)\nEOF",
            2,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            true,
            false,
            1,
            1,
            0,
            1,
            1};
  case 12:
    return {"cat <<EOF\n$(</tmp/heredoc-input)\nEOF",
            1,
            0,
            0,
            1,
            1,
            0,
            1,
            0,
            true,
            false,
            1,
            1,
            0,
            0,
            1};
  case 13:
    return {"{ cat; cat; } <<EOF\n$(id)\nEOF",
            3,
            1,
            0,
            1,
            0,
            0,
            2,
            0,
            true,
            false,
            1,
            1,
            0,
            0,
            1};
  case 14:
    return {
        "echo $(</tmp/direct)$(id)", 2, 0, 0, 2, 1, 0, 1, 1, true, false, 1};
  case 15:
    return {"cat <<-EOF\r\n\t$(id)\r\n\tEOF\r\n",
            2,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            true,
            false,
            1,
            1,
            0,
            0,
            1};
  case 16:
    return {"cat <<EOF\n\"$(id)\" '$(pwd)' `date`\nEOF",
            4,
            0,
            0,
            3,
            0,
            0,
            1,
            3,
            true,
            false,
            1,
            1,
            0,
            0,
            3};
  case 17:
    return {"cat <<A <<-B\n$(id)\nA\n\t$(pwd)\n\tB\n",
            3,
            0,
            0,
            2,
            0,
            0,
            1,
            1,
            true,
            false,
            1,
            2,
            0,
            1,
            2};
  case 18:
    return {"cat <<EOF\n$(printf one; printf two)\nEOF",
            3,
            0,
            1,
            1,
            0,
            2,
            1,
            0,
            true,
            false,
            1,
            1,
            0,
            0,
            1};
  case 19:
    return {"cat <<EOF\n$( { sleep 2; printf q; } | ./clock )\nEOF",
            4,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            true,
            false,
            1,
            1,
            0,
            0,
            1};
  case 20:
    return {"cat <<\\EOF\n$(id)\nEOF",
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            false,
            1,
            1,
            1,
            0,
            0};
  case 21:
    return {"cat <<EOF\n\\$(id) \\`date\\`\nEOF",
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            false,
            1,
            1,
            0,
            0,
            0};
  case 22:
    /* A document can receive direct file bytes, one command's stdout, and a
     * multi-command collector in one expansion. */
    return {"cat <<EOF\n$(</tmp/mixed-file)$(id)$(printf one; printf two)\nEOF",
            4,
            0,
            1,
            3,
            1,
            2,
            1,
            1,
            true,
            false,
            1,
            1,
            0,
            0,
            3};
  case 23:
    return {"cat <<EOF\n$(cat < <(printf config))\nEOF",
            3,
            0,
            0,
            2,
            0,
            0,
            2,
            2,
            true,
            false,
            1,
            1,
            0,
            0,
            1};
  case 24:
    return {"cat <<EOF\n$(printf value 2> >(cat))\nEOF",
            3,
            0,
            2,
            2,
            0,
            3,
            2,
            0,
            true,
            true,
            2,
            1,
            0,
            0,
            1};
  case 25:
    return {
        "cat <<EOF\n$( { printf payload; } | ./clock < <(printf config) )\nEOF",
        4,
        1,
        1,
        2,
        0,
        0,
        2,
        2,
        true,
        false,
        1,
        1,
        0,
        0,
        1};
  case 26:
    return {"{ cat <&4; } 3<<EOF 4<&3 3>&-\n$(id)\nEOF",
            2,
            1,
            0,
            1,
            0,
            0,
            1,
            0,
            true,
            false,
            1,
            1,
            0,
            0,
            1};
  case 27:
    /* Closing fd 3 before duplicating it leaves this document transient, but
     * its expansion remains a root-level dynamic-content requirement. */
    return {"{ cat <&4; } 3<<EOF 3>&- 4<&3\n$(id)\nEOF",
            2,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            true,
            false,
            1,
            1,
            0,
            1,
            1};
  case 28:
    return {"cat <<A <<B <<C <<D <<E <<F <<G <<H\n"
            "one\nA\ntwo\nB\nthree\nC\nfour\nD\nfive\nE\nsix\nF\n"
            "seven\nG\n$(id)\nH\n",
            2,
            0,
            0,
            1,
            0,
            0,
            1,
            1,
            true,
            false,
            1,
            8,
            0,
            7,
            1};
  case 29:
    return {"{ echo $(id); } | cat", 3, 1, 0, 1, 0, 0, 1, 1, true, false, 1};
  case 30:
    return {"{ cat < <(printf config); } | sort",
            3,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            false,
            false,
            1,
            0,
            0,
            0,
            0};
  case 31:
    return {"{ printf value 3> >(cat); }",
            2,
            1,
            1,
            1,
            0,
            1,
            1,
            0,
            false,
            true,
            3,
            0,
            0,
            0,
            0};
  case 32:
    return {"{ cat <<'EOF'\n$(id)\nEOF\n}",
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            false,
            false,
            1,
            1,
            1,
            0,
            0};
  case 33:
    return {"{ cat <(printf config); } | sort",
            3,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            false,
            false,
            1};
  case 34: {
    shell_substitution_fuzz_case_t item = {
        "{ printf value; } > >(cat)", 2, 1, 1, 1, 0, 1, 1, 0, false, true, 1};
    item.group_substitution_owner = true;
    return item;
  }
  case 35: {
    shell_substitution_fuzz_case_t item = {"{ printf value >&3; } 3> >(cat)",
                                           2,
                                           1,
                                           1,
                                           1,
                                           0,
                                           1,
                                           1,
                                           0,
                                           false,
                                           true,
                                           3};
    item.group_substitution_owner = true;
    return item;
  }
  case 36: {
    shell_substitution_fuzz_case_t item = {
        "{ cat; } < <(printf config)", 2, 1, 0, 1, 0, 0, 1, 0, false, false, 1};
    item.group_substitution_owner = true;
    return item;
  }
  case 37: {
    shell_substitution_fuzz_case_t item = {
        "printf source | { cat; } 3<&0 < <(printf config)",
        3,
        1,
        0,
        1,
        0,
        0,
        1,
        0,
        false,
        false,
        1};
    item.group_substitution_owner = true;
    item.group_pipe_target_fd = 3;
    return item;
  }
  case 38:
    return {"{ echo $(id); } & printf after",
            3,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            true,
            false,
            1};
  case 39:
    return {"{ echo $(id); } && printf after",
            3,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            true,
            false,
            1};
  case 40:
    return {"printf before || { echo $(id); }",
            3,
            1,
            0,
            1,
            0,
            0,
            1,
            1,
            true,
            false,
            1};
  case 41: {
    shell_substitution_fuzz_case_t item = {
        "{ printf value; } 3> >(printf '%s' 'a)')",
        2,
        1,
        1,
        1,
        0,
        1,
        1,
        0,
        false,
        true,
        3};
    item.group_substitution_owner = true;
    return item;
  }
  case 42: {
    shell_substitution_fuzz_case_t item = {
        "{ printf value; } 3> >(printf '%s' \\))",
        2,
        1,
        1,
        1,
        0,
        1,
        1,
        0,
        false,
        true,
        3};
    item.group_substitution_owner = true;
    return item;
  }
  case 43: {
    shell_substitution_fuzz_case_t item = {
        "{ printf value; } 3> >(printf '%s' \"$(id)\")",
        3,
        1,
        1,
        2,
        0,
        1,
        1,
        1,
        true,
        true,
        3};
    item.group_substitution_owner = true;
    return item;
  }
  case 44: {
    shell_substitution_fuzz_case_t item = {"{ sh; cat; } < <(printf config)",
                                           3,
                                           1,
                                           0,
                                           1,
                                           0,
                                           0,
                                           2,
                                           0,
                                           false,
                                           false,
                                           1};
    item.group_substitution_owner = true;
    return item;
  }
  case 45:
    return {
        "printf payload > >({ sh; })", 2, 1, 1, 1, 0, 1, 1, 0, false, true, 1};
  case 46:
    return {"sh < <(printf config)", 2, 0, 0, 1, 0, 0, 1, 1, false, false, 1};
  case 48:
    return {"printf value 2>> >(cat)", 2, 0, 1, 1, 0, 1, 1, 0, false, true, 2};
  case 49: {
    shell_substitution_fuzz_case_t item = {
        "{ printf value; } 3>> >(cat)", 2, 1, 1, 1, 0, 1, 1, 0, false, true, 3};
    item.group_substitution_owner = true;
    return item;
  }
  case 50: {
    /* The target group already has fd 0 from its own process input. The outer
     * output process substitution must not create a collector bypass. */
    shell_substitution_fuzz_case_t item = {
        "printf outer > >({ cat; } < <(printf inner))",
        3,
        1,
        0,
        1,
        0,
        0,
        1,
        0,
        false,
        true,
        1};
    item.group_substitution_owner = false;
    return item;
  }
  case 51:
    /* The inner group is a separate recursive substitution graph. Its bytes
     * must reach only the enclosing echo, never bypass it to the outer word. */
    return {"echo $({ echo $({ printf nested; }); })",
            3,
            2,
            0,
            2,
            0,
            0,
            2,
            0,
            true,
            false,
            1};
  case 52: {
    /* Only GROUP-edge descendants inherit the outer process input. The inner
     * producer remains a direct substitution source for `cat`, not a second
     * group-owned dynamic consumer. */
    shell_substitution_fuzz_case_t item = {
        "{ cat < <(printf inner); } < <(printf outer)",
        3,
        1,
        0,
        2,
        0,
        0,
        1,
        1,
        false,
        false,
        1};
    item.group_substitution_owner = true;
    return item;
  }
  case 53:
    /* The directions disagree, so the process still runs but no bytes have a
     * shell-defined route from it to cat's redirected descriptor. */
    return {"cat < >(sh)", 2, 0, 0, 0, 0, 0, 0, 0, false, false, 1};
  case 54:
    return {"cat > <(printf input)", 2, 0, 0, 0, 0, 0, 0, 0, false, false, 1};
  case 55:
    /* Adjacent `><(` is the compact cross-direction spelling, not a
     * read/write redirect and not a producer-to-cat byte route. */
    return {"cat><(printf input)", 2, 0, 0, 0, 0, 0, 0, 0, false, false, 1};
  case 56:
    return {"cat <> <(printf input)", 2, 0, 0, 1, 0, 0, 1, 1, false, false, 1};
  case 57:
    return {"cat <> >(sh)", 2, 0, 1, 1, 0, 1, 1, 0, false, true, 0};
  case 58: {
    /* The `)` in the deferred body belongs to the heredoc, not the process
     * substitution. The resulting stream is dynamic descriptor I/O only. */
    shell_substitution_fuzz_case_t item = {"cat <(cat <<EOF\n)\nEOF\n)",
                                           2,
                                           0,
                                           0,
                                           1,
                                           0,
                                           0,
                                           1,
                                           1,
                                           false,
                                           false,
                                           1,
                                           1,
                                           0,
                                           0,
                                           0};
    item.surface_command_count = 1;
    return item;
  }
  case 59: {
    /* The heredoc body is also opaque while matching a command substitution.
     * Unlike process substitution, its completed bytes are a shell word. */
    shell_substitution_fuzz_case_t item = {"echo $(cat <<E'OF'\n)\nEOF\n)",
                                           2,
                                           0,
                                           0,
                                           1,
                                           0,
                                           0,
                                           1,
                                           1,
                                           true,
                                           false,
                                           1,
                                           1,
                                           1,
                                           0,
                                           0};
    item.surface_command_count = 1;
    return item;
  }
  case 60: {
    /* Arithmetic remains opaque while the enclosing command substitution
     * still carries a shell-word inspection edge. */
    shell_substitution_fuzz_case_t item = {"echo $(printf '%s' $((1 << 2)))",
                                           2,
                                           0,
                                           0,
                                           1,
                                           0,
                                           0,
                                           1,
                                           1,
                                           true,
                                           false,
                                           1};
    item.surface_command_count = 1;
    return item;
  }
  case 61: {
    /* The same lexical boundary applies to process-substitution I/O. */
    shell_substitution_fuzz_case_t item = {"cat <(printf '%s' $((1 << 2)))",
                                           2,
                                           0,
                                           0,
                                           1,
                                           0,
                                           0,
                                           1,
                                           1,
                                           false,
                                           false,
                                           1};
    item.surface_command_count = 1;
    return item;
  }
  case 62: {
    /* A here-string word is a dynamic document consumer, not a direct stdin
     * route from the nested producer. */
    shell_substitution_fuzz_case_t item = {
        "sh <<< $(printf data)", 2, 0, 0, 1, 0, 0, 1, 1, true, false, 1};
    item.herestring_count = 1;
    item.herestring_substitution_count = 1;
    return item;
  }
  case 63: {
    /* File-command substitution uses the same document target without
     * inventing an executable producer. */
    shell_substitution_fuzz_case_t item = {
        "sh <<< $(</tmp/here-input)", 1, 0, 0, 1, 1, 0, 1, 0, true, false, 1};
    item.herestring_count = 1;
    item.herestring_substitution_count = 1;
    return item;
  }
  case 64: {
    /* A brace redirect owns the document. Its member inherits dynamic state
     * without a fabricated direct command-to-document substitution edge. */
    shell_substitution_fuzz_case_t item = {
        "{ cat; } <<< $(printf data)", 2, 1, 0, 1, 0, 0, 1, 0, true, false, 1};
    item.herestring_count = 1;
    item.herestring_substitution_count = 1;
    return item;
  }
  case 65:
    /* A process substitution can be the operand of Bash's $(<word) shortcut:
     * its producer output is the outer shell-word data, not a static file. */
    return {"echo $(< <(printf q))", 2, 0, 0, 1, 0, 0, 1, 1, true, false, 1};
  case 66:
    /* Command output selects the FILE path, then that file's contents supply
     * the outer word. The two SUBST edges intentionally have different flags.
     */
    return {"echo $(<$(printf /tmp/dynamic-name))",
            2,
            0,
            0,
            2,
            1,
            0,
            1,
            0,
            true,
            false,
            1};
  case 67: {
    /* A command substitution in a redirection selects a pathname. It is
     * dynamic I/O topology, never shell-word content for cat. */
    shell_substitution_fuzz_case_t item = {
        "cat >\"$(id)\"", 2, 0, 0, 1, 0, 0, 1, 0, false, false, 1};
    item.dynamic_name_substitution_count = 1;
    return item;
  }
  case 68: {
    /* The same pathname-selection edge terminates at a FILE document owned by
     * a brace group, rather than fabricating a producer-to-member relation. */
    shell_substitution_fuzz_case_t item = {
        "{ cat; } >\"$(id)\"", 2, 1, 0, 1, 0, 0, 1, 0, false, false, 1};
    item.dynamic_name_substitution_count = 1;
    return item;
  }
  default: {
    shell_substitution_fuzz_case_t item = {
        "cat <<A <<B <<C <<D <<E <<F <<G <<H <<I\n"
        "one\nA\ntwo\nB\nthree\nC\nfour\nD\nfive\nE\nsix\nF\n"
        "seven\nG\neight\nH\n$(id)\nI\n",
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        false,
        false,
        1};
    item.depgraph_truncated = true;
    return item;
  }
  }
}

/* A bounded compositional reference model for the supported dialect. It
 * deliberately combines only constructs whose execution relations the graph
 * represents: nested brace/subshell groups, one process or command/file
 * substitution, an optional outer pipeline, and one heredoc form. The model
 * calculates its graph and immediate-tokenizer expectations before rendering
 * shell text, so it remains an independent contract rather than a second
 * parser. */
static inline shell_substitution_fuzz_case_t
shell_brace_fuzz_composed_substitution_case(const uint8_t *data, size_t size) {
  const uint8_t form = shell_brace_fuzz_byte(data, size, 0) % 6;
  const uint8_t depth = 1 + shell_brace_fuzz_byte(data, size, 1) % 3;
  const bool append_pipeline =
      form != 5 && (shell_brace_fuzz_byte(data, size, 2) & 1) != 0;
  const bool literal_heredoc =
      form == 5 && (shell_brace_fuzz_byte(data, size, 3) & 1) != 0;

  std::string body;
  uint32_t graph_commands = 0;
  uint32_t endpoints = 0;
  uint32_t substitutions = 1;
  uint32_t file_substitutions = 0;
  uint32_t collector_writes = 0;
  uint32_t dynamic_consumers = 1;
  uint32_t command_mappings = 1;
  bool requires_shell_word = false;
  bool output_process = false;
  uint32_t outer_fd = 1;
  uint32_t heredocs = 0;
  uint32_t literal_heredocs = 0;
  uint32_t heredoc_substitutions = 0;

  switch (form) {
  case 0:
    body = "echo $(id)";
    graph_commands = 2;
    requires_shell_word = true;
    break;
  case 1:
    body = "cat <(printf config)";
    graph_commands = 2;
    break;
  case 2:
    body = "cat < <(printf config)";
    graph_commands = 2;
    break;
  case 3:
    body = "printf value 3> >(cat)";
    graph_commands = 2;
    endpoints = 1;
    collector_writes = 1;
    command_mappings = 0;
    output_process = true;
    outer_fd = 3;
    break;
  case 4:
    body = "echo $(</tmp/composed-substitution-input)";
    graph_commands = 1;
    file_substitutions = 1;
    command_mappings = 0;
    requires_shell_word = true;
    break;
  default:
    body = "cat <<";
    body += literal_heredoc ? "'EOF'\n$(id)\nEOF\n" : "EOF\n$(id)\nEOF\n";
    graph_commands = literal_heredoc ? 1 : 2;
    substitutions = literal_heredoc ? 0 : 1;
    dynamic_consumers = literal_heredoc ? 0 : 1;
    command_mappings = literal_heredoc ? 0 : 1;
    heredocs = 1;
    literal_heredocs = literal_heredoc ? 1 : 0;
    heredoc_substitutions = literal_heredoc ? 0 : 1;
    requires_shell_word = !literal_heredoc;
    break;
  }

  std::string command;
  if (form == 5) {
    std::vector<bool> subshell_groups;
    for (uint8_t level = 0; level < depth; level++) {
      bool subshell = (shell_brace_fuzz_byte(data, size, 4 + level) & 1) != 0;
      command += subshell ? "( " : "{ ";
      subshell_groups.push_back(subshell);
    }
    command += body;
    for (uint8_t level = depth; level > 0; level--) {
      if (subshell_groups[level - 1])
        command += ")";
      else
        command += level == depth ? "}" : "; }";
    }
  } else {
    command = body;
    for (uint8_t level = 0; level < depth; level++) {
      bool subshell = (shell_brace_fuzz_byte(data, size, 4 + level) & 1) != 0;
      command = subshell ? "( " + command + " )" : "{ " + command + "; }";
    }
    if (append_pipeline) {
      command += " | sort";
      graph_commands++;
    }
  }

  shell_substitution_fuzz_case_t item(
      "", graph_commands, depth, endpoints, substitutions, file_substitutions,
      collector_writes, dynamic_consumers, command_mappings,
      requires_shell_word, output_process, outer_fd, heredocs, literal_heredocs,
      0, heredoc_substitutions);
  item.command = command;
  item.surface_command_count = 1 + (append_pipeline ? 1 : 0);
  return item;
}

#endif
