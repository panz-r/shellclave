#ifndef SHELL_PIPELINE_INTERNAL_H
#define SHELL_PIPELINE_INTERNAL_H

#include "shell_source_internal.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full_internal.h"
#include <stdlib.h>

#define SHELL_PIPELINE_WORK() SHELL_SOURCE_PREFIX_SCAN(1)

/* Private prechecked interfaces: source is required immutable storage for
 * length bytes. parsed is trusted fast-parser metadata for that same span:
 * either the unchanged result or graph construction's local copy with
 * parser-truncated groups disabled. Parser capacities, range bounds, nested
 * group intervals and parent indices are established by the parser, not
 * revalidated here. A group pointer
 * belongs to parsed->groups; range indices are below parsed->count. Index/map
 * storage is distinct from the borrowed inputs and remains valid throughout
 * the operation. Lookup/traversal helpers require the index/map built for this
 * parse. Empty groups and UINT16_MAX parent/owner sentinels are meaningful.
 */
/* Fast ranges are source fragments, not execution stages: inline documents
 * can be adjunct redirects or complete argv-less members, and a compound's
 * body occupies several ranges. Walk pipeline syntax without treating either
 * kind of fragment as a list boundary. */
typedef struct {
  uint32_t range;
  const shell_group_t *group;
} shell_pipeline_stage_t;

/* Empty timing syntax keeps its prefix span so lexical consumers can still
 * reconcile it. Its execution target is structural, not an argv-less command
 * with redirections or assignments. Inherited pipeline timing is not syntax:
 * a later executable named `time` keeps its argv and descriptor routes. */
static SHELL_NONNULL(1, 2) inline bool shell_pipeline_range_is_empty_timing(
    const char *source, const shell_range_t *range) {
  size_t end = (size_t)range->start + range->len;
  if (!range->pipeline_time_direct ||
      (range->modifiers & SHELL_CMD_MOD_PIPE_TIMED) == 0)
    return false;
  shell_source_pipeline_prefix_t prefix =
      shell_source_parse_pipeline_prefix(source, range->start, end);
  /* Direct timing metadata already establishes a valid timing prefix. Only
   * the presence of its execution stage is queried here. */
  return prefix.stage_start == end;
}

typedef struct {
  uint16_t opening_group[SHELL_MAX_SUBCOMMANDS];
  uint16_t containing_group[SHELL_MAX_SUBCOMMANDS];
  /* Compound trailing-redirect owner of each lexical range, if any. */
  uint16_t trailing_group[SHELL_MAX_SUBCOMMANDS];
  shell_source_compound_tail_t group_tail[SHELL_MAX_GROUPS];
  uint16_t range_connector[SHELL_MAX_SUBCOMMANDS];
  uint16_t range_successor[SHELL_MAX_SUBCOMMANDS];
  /* Logical top-level Bash input units, indexed during the connector walk. */
  uint32_t range_input_unit[SHELL_MAX_SUBCOMMANDS];
  uint32_t group_input_unit[SHELL_MAX_GROUPS];
  /* Lexically established descriptor prefix for operator-only documents. */
  uint32_t document_start[SHELL_MAX_SUBCOMMANDS];
  uint16_t group_connector[SHELL_MAX_GROUPS];
  uint16_t group_successor[SHELL_MAX_GROUPS];
  uint32_t group_connector_start[SHELL_MAX_GROUPS];
  uint32_t group_connector_end[SHELL_MAX_GROUPS];
  /* Local simple-stage isolation, independent of an enclosing compound's
   * pipeline/background modifiers. Filled by the execution-stage sweep. */
  bool local_process[SHELL_MAX_SUBCOMMANDS];
} shell_pipeline_index_t;

/* Recover local list relationships in one lexical stream, not by restarting
 * at a physical line before every owner. Quotes, substitutions and deferred
 * document bodies are opaque to this iterator. Prefix words keep the pending
 * connector until its stage, and compound entry starts a fresh inner list. */
static SHELL_NONNULL(1, 3, 4) inline void shell_pipeline_index_connectors(
    const char *source, size_t length, const shell_parse_result_t *parsed,
    shell_pipeline_index_t *index) {
  for (uint32_t i = 0; i < parsed->count; i++) {
    index->range_connector[i] = SHELL_TYPE_SIMPLE;
    index->range_successor[i] = SHELL_TYPE_SIMPLE;
    index->range_input_unit[i] = 0;
    index->document_start[i] = parsed->cmds[i].start;
  }
  for (uint32_t i = 0; i < parsed->group_count; i++) {
    index->group_connector[i] = SHELL_TYPE_SIMPLE;
    index->group_successor[i] = SHELL_TYPE_SIMPLE;
    index->group_input_unit[i] = 0;
  }
  shell_tokenizer_state_t state;
  shell_tokenizer_init_prechecked(&state, source, length);
  shell_token_t token;
  uint32_t range = 0, group = 0;
  uint16_t stack[SHELL_MAX_GROUPS];
  uint32_t parent_range[SHELL_MAX_GROUPS];
  uint32_t last_range = UINT32_MAX;
  uint32_t depth = 0;
  uint16_t closed = UINT16_MAX;
  uint16_t connector = SHELL_TYPE_SIMPLE;
  bool command_position = true;
  uint32_t connector_start = 0, connector_end = 0;
  uint32_t input_unit = 0;
  while (shell_tokenizer_next(&state, &token)) {
    SHELL_PIPELINE_WORK();
    uint16_t next = SHELL_TYPE_SIMPLE;
    bool list = true;
    switch (token.type) {
    case SHELL_TOKEN_PIPE:
    case SHELL_TOKEN_PIPE_BOTH:
      next = SHELL_TYPE_PIPELINE;
      break;
    case SHELL_TOKEN_AND:
      next = SHELL_TYPE_AND;
      break;
    case SHELL_TOKEN_OR:
      next = SHELL_TYPE_OR;
      break;
    case SHELL_TOKEN_BACKGROUND:
      next = SHELL_TYPE_BACKGROUND;
      break;
    case SHELL_TOKEN_SEMICOLON:
      break;
    default:
      list = false;
      break;
    }
    if (list) {
      bool newline =
          token.type == SHELL_TOKEN_SEMICOLON && (token.start[0] == '\n');
      /* A physical newline after a binary list operator is continuation,
       * not a new list. The lexical API still exposes that newline token. */
      if (newline &&
          (connector == SHELL_TYPE_PIPELINE || connector == SHELL_TYPE_AND ||
           connector == SHELL_TYPE_OR))
        continue;
      if (depth == 0 && newline)
        input_unit++;
      /* `&` already terminates its execution unit. Following newlines start
       * new input units, but retain the background successor and connector. */
      if (newline && connector == SHELL_TYPE_BACKGROUND)
        continue;
      if (closed != UINT16_MAX)
        index->group_successor[closed] = next;
      else if (last_range != UINT32_MAX)
        index->range_successor[last_range] = next;
      closed = UINT16_MAX;
      connector = next;
      connector_start = (uint32_t)token.position;
      connector_end = (uint32_t)(token.position + token.length);
      command_position = true;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_START) {
      if (group < parsed->group_count &&
          parsed->groups[group].start == token.position) {
        index->group_connector[group] = connector;
        index->group_input_unit[group] = input_unit;
        index->group_connector_start[group] = connector_start;
        index->group_connector_end[group] = connector_end;
        parent_range[depth] = last_range;
        stack[depth++] = (uint16_t)group++;
      }
      last_range = UINT32_MAX;
      closed = UINT16_MAX;
      connector = SHELL_TYPE_SIMPLE;
      command_position = true;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_END) {
      size_t end = token.position + token.length;
      if (depth != 0 && parsed->groups[stack[depth - 1]].end == end) {
        closed = stack[--depth];
        last_range = parent_range[depth];
      }
      connector = SHELL_TYPE_SIMPLE;
      command_position = false;
      continue;
    }
    size_t end = token.position + token.length;
    while (range < parsed->count && parsed->cmds[range].start < end) {
      index->range_connector[range] = connector;
      index->range_input_unit[range] = input_unit;
      if ((token.type == SHELL_TOKEN_HEREDOC ||
           token.type == SHELL_TOKEN_HERESTRING) &&
          parsed->cmds[range].start >= token.position)
        index->document_start[range] = (uint32_t)token.position;
      last_range = range++;
      SHELL_PIPELINE_WORK();
    }
    if (command_position && !state.lexical_command_position)
      connector = SHELL_TYPE_SIMPLE;
    command_position = state.lexical_command_position;
  }
}

/* Build all range/group relationships in one forward sweep. Parser-produced
 * group command intervals are properly nested and parent indices identify the
 * containing interval, so consumers never need to search the complete group
 * table for each range. Compound tails are likewise scanned once per group and
 * reused by every pipeline, timing, and execution-map consumer. */
static SHELL_NONNULL(1, 3, 4) inline void shell_pipeline_index_build(
    const char *source, size_t length, const shell_parse_result_t *parsed,
    shell_pipeline_index_t *index) {
  shell_pipeline_index_connectors(source, length, parsed, index);
  uint16_t innermost_start[SHELL_MAX_SUBCOMMANDS];
  for (uint32_t range = 0; range < parsed->count; range++) {
    index->opening_group[range] = UINT16_MAX;
    index->containing_group[range] = UINT16_MAX;
    index->trailing_group[range] = UINT16_MAX;
    index->local_process[range] = false;
    innermost_start[range] = UINT16_MAX;
  }
  for (uint32_t group = 0; group < parsed->group_count; group++) {
    SHELL_PIPELINE_WORK();
    const shell_group_t *candidate = &parsed->groups[group];
    index->group_tail[group] =
        shell_source_parse_compound_tail(source, length, candidate->end);
    if (candidate->command_count == 0)
      continue;
    uint32_t first = candidate->first_command;
    uint16_t opening = index->opening_group[first];
    if (opening == UINT16_MAX ||
        candidate->start < parsed->groups[opening].start)
      index->opening_group[first] = (uint16_t)group;
    uint16_t inner = innermost_start[first];
    if (inner == UINT16_MAX || candidate->start > parsed->groups[inner].start)
      innermost_start[first] = (uint16_t)group;
  }

  uint16_t current = UINT16_MAX;
  for (uint32_t range = 0; range < parsed->count; range++) {
    SHELL_PIPELINE_WORK();
    while (current != UINT16_MAX) {
      SHELL_PIPELINE_WORK();
      const shell_group_t *group = &parsed->groups[current];
      uint32_t end = (uint32_t)group->first_command + group->command_count;
      if (range < end)
        break;
      current = group->parent;
    }
    if (innermost_start[range] != UINT16_MAX)
      current = innermost_start[range];
    index->containing_group[range] = current;
  }
}

static SHELL_NONNULL(1, 2) inline const shell_group_t *shell_pipeline_group_at(
    const shell_parse_result_t *parsed, const shell_pipeline_index_t *index,
    uint32_t range) {
  uint16_t group = index->opening_group[range];
  return group == UINT16_MAX ? NULL : &parsed->groups[group];
}

typedef struct {
  bool pipeline_member;
  bool backgrounded;
} shell_pipeline_group_context_t;

/* Isolation follows syntax even if redirects replace every live pipe route.
 * Only the outermost group at a stage boundary inherits its incoming pipe;
 * a nested group sharing the first range remains in that stage's scope. */
static SHELL_NONNULL(1, 3, 4, 5) inline shell_pipeline_group_context_t
    shell_pipeline_group_context(const char *source, size_t length,
                                 const shell_parse_result_t *parsed,
                                 const shell_pipeline_index_t *index,
                                 const shell_group_t *group) {
  uint32_t group_index = (uint32_t)(group - parsed->groups);
  shell_source_compound_tail_t tail = index->group_tail[group_index];
  bool incoming =
      group->command_count != 0 &&
      shell_pipeline_group_at(parsed, index, group->first_command) == group &&
      parsed->cmds[group->first_command].pipe_input_mode !=
          SHELL_PIPE_MODE_NONE;
  size_t position =
      shell_source_skip_inline_continuations(source, length, tail.redirect_end);
  bool backgrounded = position < length && source[position] == '&' &&
                      !shell_source_match_logical_punctuation(
                          source, length, position, "&&", NULL);
  return (shell_pipeline_group_context_t){incoming || tail.has_pipeline,
                                          backgrounded};
}

/* Return the exclusive flattened-range bound of the lexical pipeline scope
 * containing one simple-command range. A nested pipeline can use the same
 * modifier mode as its parent, so mode is never a usable scope identity. */
static SHELL_NONNULL(1, 2) inline uint32_t
    shell_pipeline_range_limit(const shell_parse_result_t *parsed,
                               const shell_pipeline_index_t *index,
                               uint32_t range) {
  uint16_t container = index->containing_group[range];
  return container == UINT16_MAX
             ? parsed->count
             : (uint32_t)parsed->groups[container].first_command +
                   parsed->groups[container].command_count;
}

/* A compound pipeline member itself lives in its parent's pipeline scope, not
 * in the command interval enclosed by the compound. */
static SHELL_NONNULL(1, 2) inline uint32_t
    shell_pipeline_group_limit(const shell_parse_result_t *parsed,
                               const shell_group_t *group) {
  if (group->parent != UINT16_MAX) {
    const shell_group_t *parent = &parsed->groups[group->parent];
    return (uint32_t)parent->first_command + parent->command_count;
  }
  return parsed->count;
}

/* cursor is the first fragment after the preceding stage and end is that
 * stage's source end before trailing redirects. Always extend end through
 * those redirects, even if there is no following member. pipe_input_mode,
 * rather than range.type alone, identifies document-only pipeline members.
 * The explicit limit keeps a nested pipeline inside its lexical group.
 * cursor/end are distinct writable storage, initially cursor <= limit <=
 * parsed->count and end <= length. Traversal advances them within those
 * bounds; reaching limit is normal exhaustion, not malformed metadata. */
static SHELL_NONNULL(1, 3, 4, 6, 7) inline shell_source_compound_tail_t
    shell_pipeline_extend_stage(const char *source, size_t length,
                                const shell_parse_result_t *parsed,
                                const shell_pipeline_index_t *index,
                                uint32_t limit, uint32_t *cursor,
                                uint32_t *end) {
  shell_source_compound_tail_t tail;
  for (;;) {
    /* A trimmed fast fragment can end on the escape of a physical newline.
     * Start the tail scan at that escape, not in the middle of its spelling. */
    if (*end != 0 && *end < length && source[*end - 1] == '\\' &&
        (source[*end] == '\n'))
      (*end)--;
    tail = shell_source_parse_compound_tail(source, length, *end);
    *end = (uint32_t)tail.redirect_end;
    if (tail.has_pipeline)
      break;
    /* A simple command may resume its argv after a document redirect. Such
     * a fast range is another fragment of this stage, not a new command.
     * Requiring exact inline adjacency avoids crossing list separators,
     * comments, heredoc bodies, or compound delimiters. */
    size_t word = shell_source_skip_inline_continuations(source, length, *end);
    while (*cursor < limit &&
           (size_t)parsed->cmds[*cursor].start + parsed->cmds[*cursor].len <=
               word)
      (*cursor)++;
    /* A resumed fragment can begin with file redirects which the tail scan
     * has already consumed. Do not discard its following argv merely because
     * the fragment starts before the next word. */
    if (*cursor >= limit || parsed->cmds[*cursor].start > word ||
        parsed->cmds[*cursor].pipe_input_mode != SHELL_PIPE_MODE_NONE ||
        shell_pipeline_group_at(parsed, index, *cursor) ||
        (parsed->cmds[*cursor].type != SHELL_TYPE_SIMPLE &&
         parsed->cmds[*cursor].type != SHELL_TYPE_SUBSTITUTION))
      break;
    uint32_t next_end = parsed->cmds[*cursor].start + parsed->cmds[*cursor].len;
    if (next_end <= *end)
      break;
    *end = next_end;
    (*cursor)++;
  }
  return tail;
}

static SHELL_NONNULL(1, 3, 4, 6, 7, 8) inline bool shell_pipeline_next(
    const char *source, size_t length, const shell_parse_result_t *parsed,
    const shell_pipeline_index_t *index, uint32_t limit, uint32_t *cursor,
    uint32_t *end, shell_pipeline_stage_t *stage) {
  shell_source_compound_tail_t tail = shell_pipeline_extend_stage(
      source, length, parsed, index, limit, cursor, end);
  if (!tail.has_pipeline)
    return false;
  while (*cursor < limit && parsed->cmds[*cursor].start < tail.next_stage)
    (*cursor)++;
  if (*cursor >= limit)
    return false;
  const shell_range_t *range = &parsed->cmds[*cursor];
  if (range->pipe_input_mode != tail.pipe_mode &&
      !(range->type == SHELL_TYPE_PIPELINE &&
        range->pipe_input_mode == SHELL_PIPE_MODE_NONE &&
        tail.pipe_mode == SHELL_PIPE_MODE_STDOUT))
    return false;
  stage->range = *cursor;
  stage->group = shell_pipeline_group_at(parsed, index, *cursor);
  if (stage->group) {
    *end = stage->group->end;
    *cursor =
        (uint32_t)stage->group->first_command + stage->group->command_count;
  } else {
    *end = range->start + range->len;
    (*cursor)++;
  }
  return true;
}

/* A bounded borrowed-source map for simple execution stages. Keep document
 * ranges available to lexical/document consumers, but never interpret an
 * ordinary fragment after an inline redirect as a second executable. */
typedef struct {
  shell_pipeline_index_t pipeline;
  uint32_t owner[SHELL_MAX_SUBCOMMANDS];
  uint32_t start[SHELL_MAX_SUBCOMMANDS];
  uint32_t anchor[SHELL_MAX_SUBCOMMANDS];
  uint32_t end[SHELL_MAX_SUBCOMMANDS];
  uint16_t type[SHELL_MAX_SUBCOMMANDS];
  bool stage[SHELL_MAX_SUBCOMMANDS];
} shell_execution_map_t;

typedef struct {
  uint32_t start;
  uint32_t end;
  uint16_t group;
} shell_pipeline_tail_interval_t;

static SHELL_NONNULL(1, 2) inline int shell_pipeline_tail_interval_compare(
    const void *left, const void *right) {
  SHELL_PIPELINE_WORK();
  const shell_pipeline_tail_interval_t *a = left;
  const shell_pipeline_tail_interval_t *b = right;
  if (a->start != b->start)
    return a->start < b->start ? -1 : 1;
  if (a->end != b->end)
    return a->end < b->end ? -1 : 1;
  return 0;
}

static SHELL_NONNULL(1) inline bool shell_execution_document(
    const shell_range_t *range) {
  return range->type == SHELL_TYPE_HEREDOC ||
         range->type == SHELL_TYPE_HERESTRING;
}

static SHELL_NONNULL(1, 3, 4) inline void shell_execution_map_build(
    const char *source, size_t length, const shell_parse_result_t *parsed,
    shell_execution_map_t *map) {
  shell_pipeline_index_build(source, length, parsed, &map->pipeline);
  for (uint32_t i = 0; i < parsed->count; i++) {
    map->owner[i] = i;
    map->start[i] = parsed->cmds[i].start;
    map->end[i] = parsed->cmds[i].start + parsed->cmds[i].len;
    map->type[i] = parsed->cmds[i].type;
    map->stage[i] = true;
    map->anchor[i] = map->start[i];
    if (shell_execution_document(&parsed->cmds[i])) {
      map->start[i] = map->pipeline.document_start[i];
      map->anchor[i] = map->start[i];
      /* A later pipeline member inherits modifiers, not their source prefix.
       * Recover a direct document prefix at its grammar boundary only once. */
      if (parsed->cmds[i].pipeline_time_direct ||
          (parsed->cmds[i].pipeline_negation_count != 0 &&
           parsed->cmds[i].pipe_input_mode == SHELL_PIPE_MODE_NONE)) {
        size_t gap = i == 0 ? 0 : map->end[i - 1];
        const shell_group_t *group =
            shell_pipeline_group_at(parsed, &map->pipeline, i);
        if (group && group->start >= gap)
          gap = group->start + 1;
        /* The gap starts after the preceding lexical fragment. Skip list and
         * group delimiters plus their trivia, never retry at every byte of a
         * whitespace run or inside a comment. The unchanged parse supplies
         * the document's stage membership; this is source-span recovery, not
         * metadata validation. */
        for (;;) {
          gap = shell_source_skip_list_trivia(source, map->start[i], gap);
          if (gap == map->start[i] || !strchr(";|&(){}", source[gap]))
            break;
          gap++;
        }
        shell_source_pipeline_prefix_t prefix =
            shell_source_parse_pipeline_prefix(source, gap, map->start[i]);
        if (prefix.has_modifier && prefix.stage_start == map->start[i])
          map->anchor[i] = (uint32_t)prefix.prefix_start;
      }
      map->type[i] = map->pipeline.range_connector[i];
    }
  }
  /* A compound's trailing redirect list belongs to the compound endpoint,
   * not to a new simple command. Parser group descriptors are parent-before-
   * child, while their closing delimiters are not necessarily ordered. Sort
   * the already-scanned tail intervals, then consume them and the ordered
   * range table once rather than testing every group against every range. */
  shell_pipeline_tail_interval_t intervals[SHELL_MAX_GROUPS];
  uint32_t interval_count = 0;
  for (uint32_t group = 0; group < parsed->group_count; group++) {
    SHELL_PIPELINE_WORK();
    uint32_t start = parsed->groups[group].end;
    uint32_t end = (uint32_t)map->pipeline.group_tail[group].redirect_end;
    if (start != 0 && end > start)
      intervals[interval_count++] =
          (shell_pipeline_tail_interval_t){start, end, (uint16_t)group};
  }
  qsort(intervals, interval_count, sizeof(*intervals),
        shell_pipeline_tail_interval_compare);
  uint32_t range = 0;
  for (uint32_t interval = 0; interval < interval_count; interval++) {
    while (range < parsed->count &&
           map->end[range] <= intervals[interval].start) {
      SHELL_PIPELINE_WORK();
      range++;
    }
    for (; range < parsed->count && map->start[range] < intervals[interval].end;
         range++) {
      SHELL_PIPELINE_WORK();
      if (map->start[range] >= intervals[interval].start)
        map->pipeline.trailing_group[range] = intervals[interval].group;
      if (map->start[range] >= intervals[interval].start &&
          map->end[range] <= intervals[interval].end)
        map->stage[range] = false;
    }
  }
  for (uint32_t i = 0; i < parsed->count; i++) {
    SHELL_PIPELINE_WORK();
    if (map->owner[i] != i || !map->stage[i])
      continue;
    uint32_t cursor = i + 1, end = map->end[i];
    uint32_t limit = shell_pipeline_range_limit(parsed, &map->pipeline, i);
    shell_source_compound_tail_t tail = shell_pipeline_extend_stage(
        source, length, parsed, &map->pipeline, limit, &cursor, &end);
    size_t after = shell_source_skip_inline_continuations(source, length,
                                                          tail.redirect_end);
    bool background = after < length && source[after] == '&' &&
                      !shell_source_match_logical_punctuation(
                          source, length, after, "&&", NULL);
    map->pipeline.local_process[i] =
        map->pipeline.range_connector[i] == SHELL_TYPE_PIPELINE ||
        tail.has_pipeline || background;
    map->end[i] = end;
    for (uint32_t member = i + 1;
         member < limit && parsed->cmds[member].start < end; member++) {
      SHELL_PIPELINE_WORK();
      map->owner[member] = i;
    }
  }
  /* The final lexical fragment owns the stage's outgoing list connector.
   * Compounds remain stages in their parent's list, not aliases for their
   * first body range; the lexical scope sweep records that distinction. */
  for (uint32_t i = 0; i < parsed->count; i++)
    if (map->owner[i] != i)
      map->pipeline.range_successor[map->owner[i]] =
          map->pipeline.range_successor[i];
}

static SHELL_NONNULL(1, 2) inline shell_range_t
    shell_execution_range(const shell_parse_result_t *parsed,
                          const shell_execution_map_t *map, uint32_t range) {
  shell_range_t stage = parsed->cmds[range];
  stage.start = map->start[range];
  stage.len = map->end[range] - stage.start;
  stage.type = map->type[range];
  for (uint32_t member = range + 1;
       member < parsed->count && map->owner[member] == range; member++)
    stage.features |= parsed->cmds[member].features;
  return stage;
}

static SHELL_NONNULL(1, 2) inline bool shell_execution_backgrounded(
    const shell_parse_result_t *parsed, const shell_execution_map_t *map,
    uint32_t range) {
  uint32_t root = map->owner[range];
  for (uint32_t member = root; member < parsed->count; member++) {
    if (map->owner[member] != root)
      break;
    if ((parsed->cmds[member].features & SHELL_FEAT_BACKGROUND) != 0)
      return true;
  }
  return false;
}

#endif
