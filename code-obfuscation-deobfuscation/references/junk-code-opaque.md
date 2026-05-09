# Junk Code & Opaque Predicates

> **Belongs to**: `code-obfuscation-deobfuscation` skill (defensive/deobfuscation perspective)

## 1. Junk Code Insertion

Dead code that never affects program output, added to increase analysis time.

**Identification**:
- Instructions that write to registers/memory never read afterward
- Function calls whose return values are discarded and have no side effects
- Loops with invariant bounds that compute unused results

**Removal strategy**:
1. Compute def-use chains (IDA/Ghidra data flow analysis)
2. Mark instructions with no downstream use as dead
3. Verify removal doesn't change program behavior (trace comparison)

## 2. Opaque Predicates

Conditional branches where the condition is always true or always false, but this is non-obvious.

| Type | Example | Always Evaluates To |
|---|---|---|
| Arithmetic | `x² ≥ 0` | True |
| Number theory | `x*(x+1) % 2 == 0` | True (product of consecutive ints) |
| Pointer-based | `ptr == ptr` after aliasing | True |
| Hash-based | `CRC32(constant) == known_value` | True |

**Deobfuscation**:
- Abstract interpretation: prove the condition is constant
- Symbolic execution: Z3 proves `∀x: predicate(x) = True`
- Pattern matching: recognize known opaque predicate families
- Dynamic: trace and observe the branch is never taken / always taken

```python
import z3
x = z3.BitVec('x', 32)
s = z3.Solver()
s.add(x * (x + 1) % 2 != 0)
print(s.check())  # unsat → always true
```
