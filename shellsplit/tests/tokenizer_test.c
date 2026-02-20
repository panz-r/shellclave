#include "shell_tokenizer.h"
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <shell_command>\n", argv[0]);
        printf("Example: %s \"cat xx | less -G > rsr\"\n", argv[0]);
        return 1;
    }

    const char* command = argv[1];
    printf("Tokenizing command: %s\n\n", command);

    shell_command_t* commands;
    size_t command_count;

    if (!shell_tokenize_commands(command, &commands, &command_count)) {
        printf("Failed to tokenize command\n");
        return 1;
    }

    printf("Found %zu command(s):\n\n", command_count);

    for (size_t i = 0; i < command_count; i++) {
        printf("Command %zu (positions %zu-%zu):\n",
               i + 1, commands[i].start_pos, commands[i].end_pos);

        for (size_t j = 0; j < commands[i].token_count; j++) {
            shell_token_t* token = &commands[i].tokens[j];
            printf("  Token %zu: [%zu-%zu] %s = '%.*s'\n",
                   j + 1, token->position, token->position + token->length - 1,
                   shell_token_type_name(token->type),
                   (int)token->length, token->start);
        }
        printf("\n");
    }

    // Extract individual commands for DFA validation
    printf("Individual commands for DFA validation:\n");
    for (size_t i = 0; i < command_count; i++) {
        printf("Command %zu: '%.*s'\n",
               i + 1,
               (int)(commands[i].end_pos - commands[i].start_pos),
               command + commands[i].start_pos);
    }

    shell_free_commands(commands, command_count);
    return 0;
}