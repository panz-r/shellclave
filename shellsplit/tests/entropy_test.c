#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "../include/env_screener.h"
#include "../include/relative_permutation_entropy.h"

static int test_count = 0;
static int pass_count = 0;

void test(const char* name, int result) {
    test_count++;
    if (result) {
        pass_count++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
    }
}

/* Check if value is within 0.1% of expected */
int within_0_1_percent(double actual, double expected) {
    if (expected == 0.0) {
        return fabs(actual) < 0.0001;
    }
    double diff = fabs(actual - expected);
    double percent_diff = diff / fabs(expected);
    return percent_diff < 0.001;  /* 0.1% */
}

int main() {
    printf("Running env_screener and entropy tests...\n\n");
    
    /* Test corpus: 50 strings with known characteristics */
    const char* corpus[] = {
        /* API keys with prefixes */
        "sk-abcdef1234567890abcdef1234567890",  /* OpenAI */
        "sk_live_abcdef1234567890abcdef1234567890",  /* Stripe live */
        "AKIAIOSFODNN7EXAMPLE",  /* AWS */
        "ghp_abcdefghijklmnopqrstuvwxyz1234567890",  /* GitHub */
        "xoxb-1234567890123-1234567890123-abcd1234efgh",  /* Slack */
        
        /* Secrets without obvious prefix */
        "mySecretPassword123!@#",
        "anotherHighEntropyValueXYZ789",
        "superSecretKeyNoPrefixHere999",
        
        /* Base64 encoded strings */
        "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBzZWNyZXQ=",  /* Hello World! This is a secret= */
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODk=",  /* abcdefghijklmnopqrstuvwxyz123456789 */
        "c29tZXZlcnlsb25nc3RyaW5n",  /* someverylongstring */
        
        /* File paths (should be excluded) */
        "/tmp/some/random/path/with/many/segments",
        "/home/user/.config/some/app/config.json",
        "/var/log/system/messages",
        "~/Documents/my file.txt",
        
        /* Natural language / normal text */
        "hello world this is normal text",
        "The quick brown fox jumps over the lazy dog",
        "this is a test message",
        "password123",
        "admin123",
        
        /* Variable names (not secrets) */
        "DISPLAY=:0",
        "TMUX=/tmp/tmux-1000/default,12345,0",
        "SSH_AUTH_SOCK=/run/user/1000/gnome-keyring-daemon/ssh",
        "LANG=en_US.UTF-8",
        
        /* Structured strings */
        "2024-01-15T10:30:00Z",  /* ISO date */
        "user@example.com",  /* email */
        "http://example.com/path",  /* URL */
        
        /* UUIDs */
        "550e8400-e29b-41d4-a716-446655440000",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        
        /* Hashes (hex) */
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  /* SHA-256 */
        "abcdef0123456789",  /* short hex */
        
        /* Numbers */
        "1234567890",
        "3.141592653589793",
        
        /* Low entropy */
        "aaaaaaaaaaaaaaaaaaaa",
        "1111111111111111",
        "AAAAAAAAAAAAAAA",
        "abcabcabcabcabcabcabcabc",
        
        /* Medium entropy */
        "a1b2c3d4e5f6g7h8",
        "Password1!",
        
        /* High entropy random */
        "xK9mLp2nQ4rS6tU8vW0yZ2aB4cD6eF8gH0j",
        
        /* Whitelisted names but unusual values */
        "MY_VAR=someRandomValue123",
        "ANOTHER_VAR=anotherValue456",
        
        /* Edge cases */
        "",  /* empty */
        "a",  /* single char */
        "12",  /* two digits */
        "abc",  /* short */
    };
    
    int corpus_size = sizeof(corpus) / sizeof(corpus[0]);
    
    printf("=== ENTROPY CALCULATIONS ===\n\n");
    
    /* Calculate and print all values with full Bayesian posterior */
    for (int i = 0; i < corpus_size; i++) {
        const char* s = corpus[i];
        double shannon = env_screener_calculate_entropy(s);
        double rel_conditional = relative_conditional_entropy(s, 5);
        double rel_2gram = relative_entropy_ratio(s, 5, 2);
        double posterior = env_screener_combined_score_name(NULL, s);
        
        printf("  [%d] \"%s\"\n", i, s);
        printf("      Shannon: %.6f\n", shannon);
        printf("      Rel Conditional: %.6f\n", rel_conditional);
        printf("      Rel 2-gram: %.6f\n", rel_2gram);
        printf("      Posterior: %.6f\n\n", posterior);
    }
    
    printf("=== BASELINE VERIFICATION ===\n\n");
    
    /* Expected posterior probabilities (from reference run) */
    /* Allow up to 1% deviation */
    struct { const char* value; double expected; } expected[] = {
        {"sk-abcdef1234567890abcdef1234567890", 0.877750},
        {"sk_live_abcdef1234567890abcdef1234567890", 0.896819},
        {"AKIAIOSFODNN7EXAMPLE", 0.997336},
        {"ghp_abcdefghijklmnopqrstuvwxyz1234567890", 0.980423},
        {"xoxb-1234567890123-1234567890123-abcd1234efgh", 0.862557},
        {"mySecretPassword123!@#", 0.680517},
        {"anotherHighEntropyValueXYZ789", 0.613152},
        {"superSecretKeyNoPrefixHere999", 0.387906},
        {"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBzZWNyZXQ=", 0.625894},
        {"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODk=", 0.884446},
        {"c29tZXZlcnlsb25nc3RyaW5n", 0.434173},
        {"/tmp/some/random/path/with/many/segments", 0.000535},
        {"/home/user/.config/some/app/config.json", 0.000009},
        {"/var/log/system/messages", 0.000380},
        {"~/Documents/my file.txt", 0.000301},
        {"hello world this is normal text", 0.456321},
        {"The quick brown fox jumps over the lazy dog", 0.743211},
        {"this is a test message", 0.243695},
        {"password123", 0.406075},
        {"admin123", 0.010052},
        {"DISPLAY=:0", 0.014957},
        {"TMUX=/tmp/tmux-1000/default,12345,0", 0.000024},
        {"SSH_AUTH_SOCK=/run/user/1000/gnome-keyring-daemon/ssh", 0.001739},
        {"LANG=en_US.UTF-8", 0.590617},
        {"2024-01-15T10:30:00Z", 0.291374},
        {"user@example.com", 0.188082},
        {"http://example.com/path", 0.491797},
        {"550e8400-e29b-41d4-a716-446655440000", 0.279652},
        {"6ba7b810-9dad-11d1-80b4-00c04fd430c8", 0.450198},
        {"5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", 0.564207},
        {"abcdef0123456789", 0.034226},
        {"1234567890", 0.014957},
        {"3.141592653589793", 0.362660},
        {"aaaaaaaaaaaaaaaaaaaa", 0.000005},
        {"1111111111111111", 0.000005},
        {"AAAAAAAAAAAAAAA", 0.000005},
        {"abcabcabcabcabcabcabcabc", 0.000024},
        {"a1b2c3d4e5f6g7h8", 0.034226},
        {"Password1!", 0.360125},
        {"xK9mLp2nQ4rS6tU8vW0yZ2aB4cD6eF8gH0j", 0.828812},
        {"MY_VAR=someRandomValue123", 0.547310},
        {"ANOTHER_VAR=anotherValue456", 0.731729},
        {"", 0.000000},
        {"a", 0.000000},
        {"12", 0.000000},
        {"abc", 0.000000},
    };
    int num_expected = sizeof(expected) / sizeof(expected[0]);
    
    for (int i = 0; i < num_expected; i++) {
        double actual = env_screener_combined_score_name(NULL, expected[i].value);
        double deviation = fabs(actual - expected[i].expected);
        
        /* For very small values (< 0.001), use absolute tolerance of 1% of value or 0.000001 */
        /* For larger values, use relative tolerance of 1% */
        double tolerance;
        if (expected[i].expected < 0.001) {
            tolerance = fmax(0.000001, expected[i].expected * 0.01);
        } else {
            tolerance = expected[i].expected * 0.01;
        }
        
        if (deviation > tolerance) {
            printf("  [FAIL] posterior(%s): expected %.6f, got %.6f (diff %.6f > tol %.6f)\n",
                   expected[i].value, expected[i].expected, actual, deviation, tolerance);
        }
        test_count++;
        if (deviation <= tolerance) {
            pass_count++;
        }
    }
    
    printf("  Checked %d posterior values (1%% tolerance)\n", num_expected);
    
    printf("\n--- Key Test Cases ---\n");
    
    /* API key with prefix - entropy function returns raw Shannon, prefix handled in scan */
    test("sk- key Shannon > 0", 
        env_screener_calculate_entropy("sk-abcdef1234567890abcdef1234567890") > 3.0);
    
    /* Path exclusion */
    test("Path lookslike_path", looks_like_path("/tmp/some/path"));
    test("Home path lookslike_path", looks_like_path("~/Documents/file"));
    test("Non-path doesn't lookslike_path", !looks_like_path("sk-abc123"));
    
    /* Base64 detection */
    test("Base64 looks_like_base64", looks_like_base64("SGVsbG8gV29ybGQh"));
    test("Non-base64 doesn't look_like_base64", !looks_like_base64("hello world!"));
    
    /* Known prefix */
    test("sk- prefix detected", check_secret_prefix("sk-abc123", NULL));
    test("AKIA- prefix detected", check_secret_prefix("AKIAIOSFODNN7EXAMPLE", NULL));
    test("No prefix returns false", !check_secret_prefix("noPrefixHere", NULL));
    
    /* Whitelist */
    test("DISPLAY whitelisted", env_screener_is_whitelisted("DISPLAY"));
    test("TMUX whitelisted", env_screener_is_whitelisted("TMUX"));
    test("Random not whitelisted", !env_screener_is_whitelisted("MY_SECRET"));
    
    /* Secret patterns */
    test("API_KEY secret pattern", env_screener_is_secret_pattern("API_KEY"));
    test("PASSWORD secret pattern", env_screener_is_secret_pattern("MY_PASSWORD"));
    test("TOKEN secret pattern", env_screener_is_secret_pattern("AUTH_TOKEN"));
    test("Non-secret not flagged", !env_screener_is_secret_pattern("DISPLAY"));
    
    printf("\n=== SUMMARY ===\n");
    printf("Tests: %d, Passed: %d, Failed: %d\n", 
           test_count, pass_count, test_count - pass_count);
    
    return (test_count == pass_count) ? 0 : 1;
}
