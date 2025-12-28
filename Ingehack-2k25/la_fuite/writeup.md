# La Fuite

## Code Analysis

The server takes `r` from the user and returns `p` after performing some binary operations on it.
```python
partial_p = self.get_chapeau()
return ((partial_p & r) | leaky) ^ r
```
where:
- `partial_p` consists of the first 896 bits of `p`.
- `leaky` is a randomly generated 896-bit value, with each bit having an 80% probability of being `0`.

## Exploit

### Recovering `p`:

1. **Remove the effect of `r`**
   - Set `r` to all ones (`0xFFFFFFFF...`).
   - XOR the output with the same `r`, eliminating its effect.

2. **Retrieve (`partial_p | leaky`)**
   - From the OR logic table, if a position in the output is `0`, then both `partial_p` and `leaky` must be `0` at that position.
   - This allows us to recover all `0` bits of `p`.

3. **Determine the `1` bits of `p`**
   - Since `leaky` has a high probability (80%) of containing `0`s, every position will eventually have `0` in the output.
   - If a position in the output is never `0`, then `p` must have been `1` at that position.

### Recovering missing 128 bits:
 we simply apply coppersmith 
## Code

[Check the script](solution/sol.py)
