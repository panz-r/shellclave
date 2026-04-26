# Statistical Anomaly Detection for Shellgate

Shellgate uses a **hybrid dual-model** language model to detect anomalous shell command sequences. Two independent n-gram models score each command and their results are combined with configurable weights.

## How It Works

### Architecture

Two models run in parallel:

1. **Raw model** — scores command names (e.g., `["ls", "cd", "pwd"]`)
2. **Type model** — scores abstracted type sequences (e.g., `["ls", "cd OPT AP", "pwd"]`)

The type model generalises arguments: paths become `AP`, options become `OPT`, environment variables become `EV`, etc. This catches structural anomalies even when specific commands differ.

### Scoring

Each model uses a **4-gram language model** with Kneser-Ney smoothing and backoff to trigram/bigram/unigram. Scores are in bits per command (higher = more anomalous).

The combined score is a weighted sum in bit-space:

```
combined = weight_raw * score_raw + weight_type * score_type
```

Default weights: `weight_raw=0.5`, `weight_type=0.5`.

### Kneser-Ney Smoothing

Both models use **absolute discounting** (Kneser-Ney) instead of Dirichlet add-α:

```
P_KN(w | ctx) = max(0, c(w,ctx) - D) / c(ctx)
                + D * |{w' : c(w',ctx) > 0}| / c(ctx) * P_KN_lower(w)
```

- `D = 0.5` (default discount)
- Continuation counts from lower-order models prevent overfitting on rare n-grams
- Backoff chain: 4-gram → trigram → bigram → unigram → UNK

Sequences of ≥ 4 commands use 4-gram context; shorter sequences use trigram scoring. Sequences with < 3 commands are not scored (score = 0, detected = false) but still contribute to learning.

### Backoff Example

For sequence `[ls, cd, pwd, gcc]` (4 commands → 4-gram scoring):

- 4-gram `ls → cd → pwd → gcc`: if seen, use KN discounting
- If unseen, back off to trigram `cd → pwd → gcc`
- If unseen, back off to bigram `pwd → gcc`
- If unseen, back off to unigram `gcc`
- If unseen, use UNK probability (adaptive from observed unseen count)

## Configuration

### Fixed Threshold

| Threshold | Behavior | Use Case |
|-----------|----------|----------|
| 2.0–3.0 | Sensitive | Learning environments, catching unusual patterns |
| 4.0–5.0 | Balanced | **Recommended default** |
| 7.0+ | Conservative | Production with low false positive tolerance |

### Adaptive Threshold

Instead of a fixed threshold, enable adaptive mode to compute the threshold from a rolling window of normal scores:

```c
sg_gate_set_anomaly_adaptive(gate, true, 1000);  /* window of 1000 scores */
sg_gate_set_anomaly_k_factor(gate, 3.0);         /* mean + 3*stddev */
```

- The window records scores from non-anomalous commands only
- Threshold is computed as `mean + k * stddev` once the window is full
- Until the window fills, the fixed threshold (from `sg_gate_enable_anomaly`) is used
- Larger window = more stable threshold; smaller window = more responsive

| k | Behavior | Use Case |
|---|----------|----------|
| 0.5–1.0 | Strict | Low false positive tolerance |
| 3.0 | Balanced | **Recommended default** |
| 10.0+ | Permissive | Learning environments |

### Combination Weights

Control how raw and type model scores are combined:

```c
sg_gate_set_anomaly_weights(gate, 1.0, 0.0);  /* raw model only */
sg_gate_set_anomaly_weights(gate, 0.5, 0.5);  /* balanced (default) */
sg_gate_set_anomaly_weights(gate, 0.0, 1.0);  /* type model only */
```

Weights must be non-negative and sum to approximately 1.0.

### Hyperparameters

- **alpha** (0.1): Fallback smoothing parameter (used when KN data is sparse).
- **unk_prior** (-10.0): Fallback log-probability for unseen commands in bits.
- **kn_discount** (0.5): Kneser-Ney absolute discount parameter.

### Per-Model Scores

`sg_result_t` provides individual model scores for debugging:

```c
r.anomaly_score;       /* combined weighted score */
r.anomaly_score_raw;   /* raw command name model score */
r.anomaly_score_type;  /* type sequence model score */
```

## Type Sequence Caching

An LRU cache avoids recomputing type sequences for repeated commands:

```c
sg_gate_set_anomaly_cache_size(gate, 256);  /* enable with 256 entries */
sg_gate_set_anomaly_cache_size(gate, 0);    /* disable */
```

- Default: disabled (cache_size = 0)
- On cache hit, `shell_build_type_sequence` is skipped
- Least-recently-used entries are evicted when the cache is full
- Maximum allowed size: 8192 entries
- Cache is not persisted through save/load (only the model is saved)

## Update Behavior

The model learns from command sequences subject to two flags:

1. **`anomaly_update_only_on_allow`** (default: false)
   - When true: model only updates on ALLOW verdicts
   - When false: model updates on every eval call

2. **`anomaly_update_on_non_anomaly`** (default: true)
   - When true: model skips learning from anomalous commands
   - When false: model learns from all commands

Both models (raw and type) are always updated together.

### Short Sequences

Sequences with < 3 commands are not scored for anomaly detection (score = 0, detected = false). However, they still contribute to unigram and bigram learning.

## Memory Management

- Model owns all memory (hash tables with length-prefixed keys)
- Use `sg_gate_anomaly_had_error()` to check for OOM conditions
- Save/load with `sg_gate_save_anomaly_model()` / `sg_gate_load_anomaly_model()`
- Type model is saved alongside raw model at `{path}_type`

## Long-Running Model Maintenance

For long-running processes (daemons), the model can grow unboundedly:

| Risk | Impact | Mitigation |
|------|--------|------------|
| Memory growth | Model can consume gigabytes after months | Use `sg_anomaly_model_decay()` periodically |
| Slower scoring | Larger hash tables increase lookup time | Use `sg_anomaly_model_prune()` to remove rare entries |
| Disk usage | Saved model files grow large | Prune before saving |

### Decay

Apply exponential decay to "forget" old patterns:

```c
/* Apply 1% decay (scale = 0.99) */
sg_anomaly_model_decay(model, 0.99);

/* Apply 10% decay (scale = 0.90) */
sg_anomaly_model_decay(model, 0.90);
```

Call this periodically (e.g., hourly) in long-running processes.

### Pruning

Remove rare n-grams to reduce model size:

```c
/* Remove n-grams that appeared fewer than 3 times */
size_t removed = sg_anomaly_model_prune(model, 3);
printf("Removed %zu rare entries\n", removed);
```

Prune before saving the model for disk efficiency.

## Best Practices

1. **Train on normal behavior**: Start with a threshold of 5.0 and adjust based on false positive rate
2. **Enable adaptive threshold**: Use `sg_gate_set_anomaly_adaptive(gate, true, 1000)` for production workloads to reduce false positives as the model learns
3. **Periodic model refresh**: Use `sg_anomaly_reset()` to clear old data and relearn
4. **Monitor OOM**: Check `sg_gate_anomaly_had_error()` after heavy usage
5. **Save checkpoints**: Periodically save model to disk for recovery
6. **Enable type caching**: Use `sg_gate_set_anomaly_cache_size(gate, 256)` when evaluating repeated commands

## Example Usage

```c
sg_gate_t *gate = sg_gate_new();
sg_gate_enable_anomaly(gate, 5.0, 0.1, -10.0);
sg_gate_set_anomaly_adaptive(gate, true, 1000);
sg_gate_set_anomaly_cache_size(gate, 256);

// Train on normal commands
for (int i = 0; i < 100; i++) {
    char buf[8192];
    sg_result_t r;
    sg_eval(gate, "ls ; cd /tmp ; pwd", 18, buf, sizeof(buf), &r);
    // r.anomaly_detected tells if sequence is anomalous
    // r.anomaly_score_raw / r.anomaly_score_type for debugging
}

// Save model
sg_gate_save_anomaly_model(gate, "/tmp/anomaly_model.bin");

// Load model later
sg_gate_load_anomaly_model(gate, "/tmp/anomaly_model.bin");
```
