#include "shell_abstract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int passed = 0;
static int failed = 0;

#define TEST(name, cond) do { \
    if (cond) { \
        printf("  [PASS] %s\n", name); \
        passed++; \
    } else { \
        printf("  [FAIL] %s\n", name); \
        failed++; \
    } \
} while(0)

void test_basic_abstraction() {
    printf("\n=== Basic Abstraction Tests ===\n");
    
    // Test 1: Simple command with environment variable
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo $PATH", &result);
        TEST("Abstract env var", ok && result != NULL);
        if (result) {
            TEST("Abstracted form contains $EV_1", 
                 strstr(result->abstracted, "$EV_1") != NULL);
            TEST("Has variables flag", shell_has_variables(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test 2: Command with absolute path
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("cat /etc/passwd", &result);
        TEST("Abstract absolute path", ok && result != NULL);
        if (result) {
            TEST("Abstracted form contains $AP_1", 
                 strstr(result->abstracted, "$AP_1") != NULL);
            TEST("Has paths flag", shell_has_paths(result));
            TEST("Has abs_paths flag", shell_has_abs_paths(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test 3: Command with relative path
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("cat ./foo.txt", &result);
        TEST("Abstract relative path", ok && result != NULL);
        if (result) {
            TEST("Abstracted form contains $RP_1", 
                 strstr(result->abstracted, "$RP_1") != NULL);
            TEST("Has rel_paths flag", shell_has_rel_paths(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test 4: Command with home path
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("ls ~/documents", &result);
        TEST("Abstract home path", ok && result != NULL);
        if (result) {
            TEST("Abstracted form contains $HP_1", 
                 strstr(result->abstracted, "$HP_1") != NULL);
            TEST("Has home_paths flag", shell_has_home_paths(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test 5: Command with glob
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("ls *.txt", &result);
        TEST("Abstract glob", ok && result != NULL);
        if (result) {
            TEST("Abstracted form contains $GB_1", 
                 strstr(result->abstracted, "$GB_1") != NULL);
            TEST("Has globs flag", shell_has_globs(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test 6: Command with positional variable
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo $1", &result);
        TEST("Abstract positional var", ok && result != NULL);
        if (result) {
            TEST("Abstracted form contains $PV_1", 
                 strstr(result->abstracted, "$PV_1") != NULL);
            TEST("Has pos_vars flag", shell_has_pos_vars(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test 7: Command with special variable
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo $?", &result);
        TEST("Abstract special var", ok && result != NULL);
        if (result) {
            TEST("Abstracted form contains $SV_1", 
                 strstr(result->abstracted, "$SV_1") != NULL);
            TEST("Has special_vars flag", shell_has_special_vars(result));
            shell_abstracted_destroy(result);
        }
    }
}

void test_combined_abstraction() {
    printf("\n=== Combined Abstraction Tests ===\n");
    
    // Test: Multiple elements of same type
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("grep $USER $HOME/file $PATH", &result);
        TEST("Multiple vars get unique indices", ok && result != NULL);
        if (result) {
            // 4 tokens: grep, $USER, $HOME/file, $PATH -> 3 abstractable elements
            TEST("Has $EV_1", strstr(result->abstracted, "$EV_1") != NULL);
            TEST("Has $EV_2", strstr(result->abstracted, "$EV_2") != NULL);
            TEST("Has $EV_3", strstr(result->abstracted, "$EV_3") != NULL);
            TEST("Element count is 4", result->element_count == 4);
            shell_abstracted_destroy(result);
        }
    }
    
    // Test: Mix of different types
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("grep -i $PATTERN /etc/*.conf ~user/*.txt", &result);
        TEST("Mixed types", ok && result != NULL);
        if (result) {
            TEST("Has $EV_1", strstr(result->abstracted, "$EV_1") != NULL);
            TEST("Has $GB_1", strstr(result->abstracted, "$GB_1") != NULL);
            TEST("Has $GB_2", strstr(result->abstracted, "$GB_2") != NULL);
            TEST("Has variables", shell_has_variables(result));
            TEST("Has globs", shell_has_globs(result));
            TEST("Has no paths", !shell_has_paths(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test: Command with command substitution
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("cat $(cat file.txt)", &result);
        TEST("Command substitution", ok && result != NULL);
        if (result) {
            TEST("Has $CS_1", strstr(result->abstracted, "$CS_1") != NULL);
            TEST("Has cmd_subst flag", shell_has_cmd_subst(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test: Command with backtick substitution
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo `date`", &result);
        TEST("Backtick substitution", ok && result != NULL);
        if (result) {
            TEST("Has $CS_1", strstr(result->abstracted, "$CS_1") != NULL);
            shell_abstracted_destroy(result);
        }
    }
    
    // Test: Command with arithmetic
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo $((x+1))", &result);
        TEST("Arithmetic expansion", ok && result != NULL);
        if (result) {
            TEST("Has $AR_1", strstr(result->abstracted, "$AR_1") != NULL);
            TEST("Has arithmetic flag", shell_has_arithmetic(result));
            shell_abstracted_destroy(result);
        }
    }
    
    // Test: Command with quoted string
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo \"hello world\"", &result);
        TEST("Quoted string", ok && result != NULL);
        if (result) {
            TEST("Has $STR_1", strstr(result->abstracted, "$STR_1") != NULL);
            TEST("Has strings flag", shell_has_strings(result));
            shell_abstracted_destroy(result);
        }
    }
}

void test_element_access() {
    printf("\n=== Element Access Tests ===\n");
    
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("cat $HOME/file.txt /etc/passwd *.log", &result);
        TEST("Element access setup", ok && result != NULL);
        
        if (result) {
            size_t count = 0;
            shell_get_elements(result, &count);
            TEST("Get element count", count == 4);
            
            // Test element by abstract - $EV_1 is $HOME/file
            abstract_element_t* elem = shell_get_element_by_abstract(result, "$EV_1");
            TEST("Get element by $EV_1", elem != NULL);
            if (elem) {
                TEST("Element original is $HOME", 
                     strcmp(elem->original, "$HOME") == 0);
                TEST("Element data.var.name is HOME",
                     elem->data.var.name && strcmp(elem->data.var.name, "HOME") == 0);
            }
            
            // Test element by index
            elem = shell_get_element_at(result, 0);
            TEST("Get element at 0", elem != NULL);
            
            // Test get original
            const char* orig = shell_get_original(result);
            TEST("Get original", orig != NULL && strlen(orig) > 0);
            
            // Test get abstracted
            const char* abst = shell_get_abstracted(result);
            TEST("Get abstracted", abst != NULL && strlen(abst) > 0);
            
            shell_abstracted_destroy(result);
        }
    }
}

void test_path_categorization() {
    printf("\n=== Path Categorization Tests ===\n");
    
    TEST("Category / is ROOT", shell_get_path_category("/") == PATH_ROOT);
    TEST("Category /etc is ETC", shell_get_path_category("/etc") == PATH_ETC);
    TEST("Category /etc/ is ETC", shell_get_path_category("/etc/") == PATH_ETC);
    TEST("Category /etc/passwd is ETC", shell_get_path_category("/etc/passwd") == PATH_ETC);
    TEST("Category /var is VAR", shell_get_path_category("/var") == PATH_VAR);
    TEST("Category /var/log is VAR", shell_get_path_category("/var/log") == PATH_VAR);
    TEST("Category /usr is USR", shell_get_path_category("/usr") == PATH_USR);
    TEST("Category /home is HOME", shell_get_path_category("/home") == PATH_HOME);
    TEST("Category /home/user is HOME", shell_get_path_category("/home/user") == PATH_HOME);
    TEST("Category /root is HOME", shell_get_path_category("/root") == PATH_HOME);
    TEST("Category /tmp is TMP", shell_get_path_category("/tmp") == PATH_TMP);
    TEST("Category /proc is PROC", shell_get_path_category("/proc") == PATH_PROC);
    TEST("Category /sys is SYS", shell_get_path_category("/sys") == PATH_SYS);
    TEST("Category /dev is DEV", shell_get_path_category("/dev") == PATH_DEV);
    TEST("Category /opt is OPT", shell_get_path_category("/opt") == PATH_OPT);
    TEST("Category relative is OTHER", shell_get_path_category("relative") == PATH_OTHER);
    TEST("Category empty is OTHER", shell_get_path_category("") == PATH_OTHER);
}

void test_name_functions() {
    printf("\n=== Name Function Tests ===\n");
    
    TEST("Abstract type name EV", strcmp(shell_abstract_type_name(ABSTRACT_EV), "EV") == 0);
    TEST("Abstract type name PV", strcmp(shell_abstract_type_name(ABSTRACT_PV), "PV") == 0);
    TEST("Abstract type name SV", strcmp(shell_abstract_type_name(ABSTRACT_SV), "SV") == 0);
    TEST("Abstract type name AP", strcmp(shell_abstract_type_name(ABSTRACT_AP), "AP") == 0);
    TEST("Abstract type name RP", strcmp(shell_abstract_type_name(ABSTRACT_RP), "RP") == 0);
    TEST("Abstract type name HP", strcmp(shell_abstract_type_name(ABSTRACT_HP), "HP") == 0);
    TEST("Abstract type name GB", strcmp(shell_abstract_type_name(ABSTRACT_GB), "GB") == 0);
    TEST("Abstract type name CS", strcmp(shell_abstract_type_name(ABSTRACT_CS), "CS") == 0);
    TEST("Abstract type name AR", strcmp(shell_abstract_type_name(ABSTRACT_AR), "AR") == 0);
    TEST("Abstract type name STR", strcmp(shell_abstract_type_name(ABSTRACT_STR), "STR") == 0);
    
    TEST("Path category name ETC", strcmp(shell_path_category_name(PATH_ETC), "ETC") == 0);
    TEST("Path category name VAR", strcmp(shell_path_category_name(PATH_VAR), "VAR") == 0);
    TEST("Path category name HOME", strcmp(shell_path_category_name(PATH_HOME), "HOME") == 0);
}

void test_expansion() {
    printf("\n=== Runtime Expansion Tests ===\n");
    
    // Create a mock environment
    char* env[] = {
        "HOME=/home/testuser",
        "PATH=/usr/bin:/bin",
        "USER=testuser",
        NULL
    };
    
    runtime_context_t ctx = {
        .env = env,
        .cwd = "/home/testuser",
        .resolve_symlinks = false
    };
    
    // Test env variable expansion
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo $USER $HOME", &result);
        TEST("Setup for expansion", ok && result != NULL);
        
        if (result) {
            ok = shell_expand_all_elements(result, &ctx);
            TEST("Expand all elements", ok);
            
            // Find the USER element
            abstract_element_t* elem = shell_get_element_by_abstract(result, "$EV_1");
            if (elem) {
                TEST("USER expanded to testuser", 
                     elem->expanded && strcmp(elem->expanded, "testuser") == 0);
            }
            
            // Find the HOME element
            elem = shell_get_element_by_abstract(result, "$EV_2");
            if (elem) {
                TEST("HOME expanded to /home/testuser", 
                     elem->expanded && strcmp(elem->expanded, "/home/testuser") == 0);
            }
            
            shell_abstracted_destroy(result);
        }
    }
    
    // Test home path expansion
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("ls ~/documents", &result);
        TEST("Setup for home path expansion", ok && result != NULL);
        
        if (result) {
            ok = shell_expand_all_elements(result, &ctx);
            TEST("Expand home path", ok);
            
            abstract_element_t* elem = shell_get_element_by_abstract(result, "$HP_1");
            if (elem) {
                TEST("~/documents expanded correctly", 
                     elem->expanded && strcmp(elem->expanded, "/home/testuser/documents") == 0);
            }
            
            shell_abstracted_destroy(result);
        }
    }
}

void test_edge_cases() {
    printf("\n=== Edge Case Tests ===\n");
    
    // Empty command
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("", &result);
        TEST("Empty command returns false", !ok);
        if (result) shell_abstracted_destroy(result);
    }
    
    // Simple command with no special tokens
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("ls -la", &result);
        TEST("Simple command no abstraction", ok && result != NULL);
        if (result) {
            TEST("Original preserved", strcmp(result->original, "ls -la") == 0);
            TEST("No elements", result->element_count == 0);
            TEST("Abstracted equals original", strcmp(result->abstracted, "ls -la") == 0);
            shell_abstracted_destroy(result);
        }
    }
    
    // Braced variable
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo ${USER}", &result);
        TEST("Braced variable", ok && result != NULL);
        if (result) {
            TEST("Abstracted contains $EV_1", strstr(result->abstracted, "$EV_1") != NULL);
            // Check element data
            abstract_element_t* elem = shell_get_element_by_abstract(result, "$EV_1");
            if (elem) {
                TEST("Braced var name correct", 
                     elem->data.var.name && strcmp(elem->data.var.name, "USER") == 0);
                TEST("Is braced", elem->data.var.is_braced);
            }
            shell_abstracted_destroy(result);
        }
    }
    
    // Path with trailing slash
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("ls /etc/", &result);
        TEST("Path with trailing slash", ok && result != NULL);
        if (result) {
            abstract_element_t* elem = shell_get_element_by_abstract(result, "$AP_1");
            if (elem) {
                TEST("Path ends with slash flag", elem->data.path.ends_with_slash);
            }
            shell_abstracted_destroy(result);
        }
    }
    
    // Relative path with ../
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("cat ../foo.txt", &result);
        TEST("Relative path with ..", ok && result != NULL);
        if (result) {
            TEST("Abstracted contains $RP_1", strstr(result->abstracted, "$RP_1") != NULL);
            shell_abstracted_destroy(result);
        }
    }
    
    // Glob with slash
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("ls /var/log/*.log", &result);
        TEST("Glob with path", ok && result != NULL);
        if (result) {
            // Tokenized as single glob token -> single abstract element
            TEST("Element count is 1", result->element_count == 1);
            shell_abstracted_destroy(result);
        }
    }
    
    // Multiple digits in positional var
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo ${10}", &result);
        TEST("Multi-digit positional var", ok && result != NULL);
        if (result) {
            TEST("Abstracted contains $PV_1", strstr(result->abstracted, "$PV_1") != NULL);
            shell_abstracted_destroy(result);
        }
    }
    
    // Quoted variable
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("echo \"$USER\"", &result);
        TEST("Quoted variable", ok && result != NULL);
        if (result) {
            // Should still abstract the variable
            TEST("Has variables", shell_has_variables(result));
            shell_abstracted_destroy(result);
        }
    }
}

void test_dfa_patterns() {
    printf("\n=== DFA Pattern Matching Tests ===\n");
    
    // These tests verify the abstracted form can be used for DFA matching
    
    // grep pattern
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("grep $PATTERN /etc/passwd", &result);
        TEST("grep command abstraction", ok && result != NULL);
        if (result) {
            printf("    Original:   %s\n", result->original);
            printf("    Abstracted: %s\n", result->abstracted);
            // The DFA would match this as a "file-read" command
            shell_abstracted_destroy(result);
        }
    }
    
    // cat with multiple paths
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("cat /etc/passwd /etc/hosts", &result);
        TEST("cat multiple files", ok && result != NULL);
        if (result) {
            printf("    Original:   %s\n", result->original);
            printf("    Abstracted: %s\n", result->abstracted);
            shell_abstracted_destroy(result);
        }
    }
    
    // find command
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("find /var -name *.log -mtime +7", &result);
        TEST("find command", ok && result != NULL);
        if (result) {
            printf("    Original:   %s\n", result->original);
            printf("    Abstracted: %s\n", result->abstracted);
            shell_abstracted_destroy(result);
        }
    }
    
    // Variable as filename
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("cat $FILE", &result);
        TEST("Variable as filename", ok && result != NULL);
        if (result) {
            printf("    Original:   %s\n", result->original);
            printf("    Abstracted: %s\n", result->abstracted);
            shell_abstracted_destroy(result);
        }
    }
    
    // Complex real-world command
    {
        abstracted_command_t* result = NULL;
        bool ok = shell_abstract_command("tail -f /var/log/$APP.log | grep -i error | head -n 100", &result);
        TEST("Complex pipeline", ok && result != NULL);
        if (result) {
            printf("    Original:   %s\n", result->original);
            printf("    Abstracted: %s\n", result->abstracted);
            shell_abstracted_destroy(result);
        }
    }
}

int main(void) {
    printf("=== Shell Abstract Tests ===\n");
    printf("Testing abstraction engine for shell command rewriting\n\n");
    
    test_basic_abstraction();
    test_combined_abstraction();
    test_element_access();
    test_path_categorization();
    test_name_functions();
    test_expansion();
    test_edge_cases();
    test_dfa_patterns();
    
    printf("\n=== Summary ===\n");
    printf("Passed: %d\n", passed);
    printf("Failed: %d\n", failed);
    printf("Total:  %d\n", passed + failed);
    
    return failed > 0 ? 1 : 0;
}
