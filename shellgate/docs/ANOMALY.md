# Statistical Anomaly Detection for Shellgate

Shellgate includes a trigram language model to detect anomalous command sequences based on learned patterns.

## How It Works

The model uses a **second-order Markov model** (trigram with backoff) with Dirichlet smoothing:

1. **Trigram scoring**: For each consecutive triple (p2, p1, curr), compute P(curr | p2, p1)
2. **Backoff chain**: If trigram is unseen → bigram → unigram → unknown prior
3. **Smoothing**: Add-α smoothing prevents zero probabilities for unseen events

```
Sequence score = average -log(probability) per command (in bits)
Higher score = more anomalous
```

## Backoff Example

For sequence `[ls, cd, pwd, gcc]`:
- Trigram `ls → cd → pwd`: if seen, use it
- Trigram `cd → pwd → gcc`: if unseen, back off to bigram `pwd → gcc`
- Bigram `pwd → gcc`: if unseen, back off to unigram `gcc`
- Unigram `gcc`: if unseen, use `unk_prior` (-10 bits = very rare)

## Configuration

### Threshold Tuning

| Threshold | Behavior | Use Case |
|-----------|----------|----------|
| 2.0-3.0 | Sensitive | Learning environments, catching unusual patterns |
| 4.0-5.0 | Balanced | **Recommended default** |
| 7.0+ | Conservative | Production with low false positive tolerance |

### Hyperparameters

- **alpha** (0.1): Smoothing parameter. Higher = smoother probabilities.
- **unk_prior** (-10.0): Log-probability of unseen command in bits.

## Update Behavior

The model learns from command sequences subject to two flags:

1. **`anomaly_update_only_on_allow`** (default: false)
   - When true: model only updates on ALLOW verdicts
   - When false: model updates on every eval call

2. **`anomaly_update_on_non_anomaly`** (default: true)
   - When true: model skips learning from anomalous commands
   - When false: model learns from all commands

### Short Sequences

Sequences with < 3 commands are not scored for anomaly detection (score = 0, detected = false). However, they still contribute to unigram and bigram learning.

## Memory Management

- Model owns all memory (hash tables with length-prefixed keys)
- Use `sg_gate_anomaly_had_error()` to check for OOM conditions
- Save/load with `sg_gate_save_anomaly_model()` / `sg_gate_load_anomaly_model()`

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
2. **Periodic model refresh**: Use `sg_anomaly_reset()` to clear old data and relearn
3. **Monitor OOM**: Check `sg_gate_anomaly_had_error()` after heavy usage
4. **Save checkpoints**: Periodically save model to disk for recovery

## Example Usage

```c
sg_gate_t *gate = sg_gate_new();
sg_gate_enable_anomaly(gate, 5.0, 0.1, -10.0);

// Train on normal commands
for (int i = 0; i < 100; i++) {
    sg_result_t r;
    sg_eval(gate, "ls ; cd /tmp", &r);
    // r.anomaly_detected tells if sequence is anomalous
}

// Save model
sg_gate_save_anomaly_model(gate, "/tmp/anomaly_model.bin");

// Load model later
sg_gate_load_anomaly_model(gate, "/tmp/anomaly_model.bin");
```
