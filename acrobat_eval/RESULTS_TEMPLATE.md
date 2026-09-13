# Adobe Acrobat evaluation — results (fill from a real run)

- Product / version: `________________________`  (Help → About)
- OS: `________________________`
- Trust mode for this sheet:  [ ] roots NOT trusted   [ ] roots trusted

## Table 1 — top banner and per-signature verdict

| File | Top banner (verbatim) | #sigs | ECDSA field verdict | ML-DSA field verdict |
|------|-----------------------|-------|---------------------|----------------------|
| A_intact_hybrid.pdf          | `____` | `__` | `____` | `____` |
| A_downgraded.pdf             | `____` | `__` | `____` | (none) |
| A_legit_classical_only.pdf   | `____` | `__` | `____` | (none) |
| B_intact_hybrid.pdf          | `____` | `__` | `____` | `____` |
| B_truncated_pqonly.pdf       | `____` | `__` | (none) | `____` |
| LTA_intact_hybrid.pdf        | `____` | `__` | `____` | `____` |
| LTA_downgraded.pdf           | `____` | `__` | `____` | (none) |

## Table 2 — coverage line (verbatim) for the surviving classical signature

| File | Coverage line shown by Acrobat |
|------|--------------------------------|
| A_intact_hybrid.pdf (ECDSA field)        | `________________________` |
| A_downgraded.pdf                         | `________________________` |
| B_intact_hybrid.pdf (ECDSA field)        | `________________________` |

## Confirmations (yes/no)

- A_downgraded.pdf and A_legit_classical_only.pdf give an identical panel:  Y / N
- LTA_downgraded.pdf and LTA_legit_classical_only.pdf identical:            Y / N
- Downgraded file's banner is "greener"/cleaner than the intact hybrid's:   Y / N
- Any crash / "unsupported algorithm" / parse error on the ML-DSA field:    Y / N
  - If yes, verbatim message: `________________________`

## Free-text notes / anything surprising

```
(...)
```

## Screenshots attached

- [ ] A_intact_hybrid_panel.png
- [ ] A_downgraded_panel.png
- [ ] A_intact_hybrid_sigprops_mldsa.png
- [ ] B_intact_hybrid_panel.png
- [ ] LTA_intact_hybrid_panel.png
- [ ] LTA_downgraded_panel.png
