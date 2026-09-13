# Adobe Acrobat evaluation — OBSERVED results

- Product: **Adobe Acrobat Reader (64-bit), version 26.002.21901** (the free
  Reader; unified "Acrobat DC" build), on Windows 10.
- Trust: the self-signed test certificates were **NOT** added to Acrobat's
  trusted identities (the honest default a recipient sees). "Verify signatures
  when the document opens" was enabled.
- Capture: each file was opened in Acrobat and its window captured with
  `PrintWindow` (screenshots in `figures/`). Banner text is transcribed verbatim
  from those screenshots.

## Top-banner verdict per document

| Document | Icon | Banner text (verbatim) | Figure |
|----------|------|------------------------|--------|
| `A_intact_hybrid.pdf` (ECDSA, then ML-DSA) | red ✗ | **At least one signature is invalid.** | fig_A_intact_invalid.png |
| `A_downgraded.pdf` (= legit classical-only) | yellow ⚠ | **At least one signature has problems.** | fig_A_downgraded_hasproblems.png |
| `B_intact_hybrid.pdf` (ML-DSA, then ECDSA) | red ✗ | **At least one signature is invalid.** | fig_B_intact_invalid.png |
| `B_truncated_pqonly.pdf` (ML-DSA only) | red ✗ | **At least one signature is invalid.** | fig_B_truncated_invalid.png |
| `LTA_intact_hybrid.pdf` | yellow ⚠ | **At least one signature has problems.** | fig_LTA_intact_hasproblems.png |
| `LTA_downgraded.pdf` (= legit classical-only) | yellow ⚠ | **At least one signature has problems.** | fig_LTA_downgraded_hasproblems.png |

## Findings

1. **The "validates better" inversion is visible to end users (plain, order A).**
   The intact, *protected* hybrid raises a **red "At least one signature is
   invalid."** because Acrobat 26 cannot process the ML-DSA-44 field. The
   **downgraded** document — from which that field has been removed — raises only
   a **yellow "At least one signature has problems."** (the surviving ECDSA
   signature is cryptographically fine; the sole "problem" is the untrusted
   self-signed identity, which would clear if the signer's CA were trusted). So
   the attacked file presents **less alarmingly** than the one it replaced — the
   graphical analogue, in the most common consumer viewer, of the DSS result in
   Section~\ref{sec:validatebetter}.

2. **Downgraded ≡ legitimate.** `A_downgraded.pdf` is byte-identical (SHA-256) to
   `A_legit_classical_only.pdf`, so Acrobat necessarily renders them identically;
   the same holds for the B-LTA pair. No screenshot can separate them.

3. **ML-DSA is the trigger.** Every plain PDF that still contains an ML-DSA
   signature — order-A intact, order-B intact, and the order-B PQ-only residue —
   is marked **red "invalid"**, because this Acrobat build has no ML-DSA support.

4. **Order-B note.** After an order-B truncation the residue is PQ-only and shows
   red "invalid" in a legacy Acrobat: the mitigation's safe residue is not
   silently accepted — if anything it is flagged harder than the attacker's
   classical-only residue would be. This is a transition-period artifact of
   missing ML-DSA support, not a property of the construction.

5. **LTA nuance.** In the B-LTA set both the intact hybrid and the downgraded
   archive show the **same** yellow "has problems" banner, so here the downgrade
   does not look *better* (nor worse). The red-vs-yellow inversion is specific to
   the plain order-A case.

## To extend

Per-signature detail (open the "Signature Panel" button: the ECDSA field as
"valid, signer's identity unknown" vs the ML-DSA field's error state) and other
Acrobat versions can be added with the same procedure in `PROTOCOL.md`.
