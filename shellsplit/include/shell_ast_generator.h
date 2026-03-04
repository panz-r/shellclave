#ifndef SHELL_AST_GENERATOR_H
#define SHELL_AST_GENERATOR_H

#include "shell_ast.h"
#include <stdint.h>
#include <stdbool.h>

// Opaque type - implementation in .c file
typedef struct shell_ast_generator shell_ast_generator_t;

shell_ast_generator_t* shell_ast_generator_create(uint64_t seed);
void shell_ast_generator_destroy(shell_ast_generator_t* gen);

void shell_ast_generator_init(shell_ast_generator_t* gen, uint64_t seed);

shell_ast_t* shell_ast_generator_generate(shell_ast_generator_t* gen, size_t max_len);

#endif
