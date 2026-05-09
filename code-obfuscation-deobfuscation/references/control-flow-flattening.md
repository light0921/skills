# Control Flow Flattening (CFF)

> **Belongs to**: `code-obfuscation-deobfuscation` skill (defensive/deobfuscation perspective)

## 1. Structure

Original sequential blocks are transformed into a dispatcher loop:

```
Original:      A → B → C → D

Flattened:     ┌──────────────────┐
               │   dispatcher     │
               │   switch(state)  │◄─────┐
               ├──────────────────┤      │
               │ case 1: block A  │──────┤
               │ case 2: block B  │──────┤
               │ case 3: block C  │──────┤
               │ case 4: block D  │──────┘
               └──────────────────┘
```

Each block sets `state = next_state` before jumping back to the dispatcher.

## 2. Recovery Techniques

| Technique | Tool | Effectiveness |
|---|---|---|
| Symbolic execution | angr, Triton, miasm | High — traces all state transitions |
| Trace-based recovery | Pin/DynamoRIO trace → reconstruct CFG | Medium — covers executed paths only |
| Pattern matching | Custom IDA/Ghidra script | Medium — works for known flatteners |
| D-810 (IDA plugin) | IDA Pro | High — specifically designed for CFF |

## 3. Symbolic Deflattening (angr approach)

```python
import angr, claripy

proj = angr.Project('./obfuscated')
cfg = proj.analyses.CFGFast()

# Find dispatcher block (highest in-degree basic block)
dispatcher = max(cfg.graph.nodes(), key=lambda n: cfg.graph.in_degree(n))

# For each case block, symbolically determine successor
for block in case_blocks:
    state = proj.factory.blank_state(addr=block.addr)
    # ... solve state variable to find real successor
```
