#ifndef SHELLTYPE_TRIE_INTERNAL_H
#define SHELLTYPE_TRIE_INTERNAL_H

#include "shelltype.h"

typedef struct st_node st_node_t;
typedef struct st_trie st_trie_t;

struct st_node {
  char *token;
  st_token_type_t type;
  uint32_t count;
  uint64_t observed_types;
  char **sample_values;
  size_t num_samples;
  uint32_t metadata_observations;
  uint16_t common_metadata;
  bool metadata_mixed;
  struct st_node **children;
  size_t num_children;
  size_t children_capacity;
};

struct st_trie {
  st_node_t *root;
  uint32_t total_commands;
};

struct st_learner {
  st_trie_t trie;
  st_learner_config_t config;
  char **blacklist;
  size_t blacklist_count;
  size_t blacklist_capacity;
};

#endif
