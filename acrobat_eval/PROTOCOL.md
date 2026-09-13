# Adobe Acrobat signature-panel evaluation — test protocol

**Purpose.** The paper validates the downgrade attack on two command-line
verifiers (pyHanko, DSS 6.5). A reviewer asked how the *graphical* signature
panel of Adobe Acrobat — the validator most end users actually see — presents a
downgraded document. This bundle and protocol let you run that evaluation on a
machine with Acrobat and record the observations the paper needs.

> The bundle was prepared on a machine without Acrobat; the observations were
> then made in Adobe Acrobat Reader 26.002 on Windows 10 and are recorded, with
> screenshots, in `RESULTS.md` and `figures/`. `RESULTS_TEMPLATE.md` is the
> blank form for repeating the evaluation on another Acrobat version.

## What is in this bundle

| File | What it is | Paper claim it tests |
|------|------------|----------------------|
| `A_intact_hybrid.pdf` | Order A hybrid, intact: ECDSA P-256 signed first, ML-DSA-44 added as an incremental update | How does the panel render an unknown-algorithm (ML-DSA) second signature? (§ validate-better analogue) |
| `A_downgraded.pdf` | The hybrid above, truncated at the previous `%%EOF` (ML-DSA layer discarded) | The attack product |
| `A_legit_classical_only.pdf` | A document that was *only ever* ECDSA-signed | Downgraded vs. legitimate — must be indistinguishable |
| `B_intact_hybrid.pdf` | Order B hybrid (proposed): ML-DSA first, ECDSA added on top | Mitigation, intact |
| `B_truncated_pqonly.pdf` | Order B hybrid truncated (ECDSA layer discarded) | Truncation leaves the *PQ* layer — safe direction |
| `B_legit_pqonly.pdf` | A document only ever ML-DSA-signed | byte-identical to the truncation above |
| `LTA_intact_hybrid.pdf` | PAdES-B-LTA hybrid, intact (two signatures + document timestamps) | Archival profile |
| `LTA_downgraded.pdf` | B-LTA hybrid truncated at the decisive boundary | Archival downgrade product |
| `LTA_legit_classical_only.pdf` | Legitimately B-LTA-archived, classical only | byte-identical to the downgrade above |
| `trust_*.pem` | The signer / timestamp certificates | Add as *trusted identities* so the panel can show a clean "valid" state |

**Byte-identity is already proven (SHA-256).** See `MANIFEST.sha256`. Three pairs
are byte-for-byte identical:

- `A_downgraded.pdf`  ==  `A_legit_classical_only.pdf`
- `LTA_downgraded.pdf`  ==  `LTA_legit_classical_only.pdf`
- `B_truncated_pqonly.pdf`  ==  `B_legit_pqonly.pdf`

Because a deterministic reader given identical bytes produces identical output,
Acrobat **necessarily** renders each downgraded file and its legitimate twin
identically. The interesting, non-derivable observations are therefore the
*intact hybrid* files and the *coverage* wording — those are what to record
carefully.

## Setup (do once)

1. Note the exact product and version: Acrobat menu → **Help → About Adobe
   Acrobat**. Record e.g. "Acrobat Pro (64-bit) 2024.x (Continuous)". Also note
   the OS.
2. These certificates are self-signed test roots, so Acrobat will otherwise show
   "identity unknown". To get a clean *trusted* state, import the roots:
   **Preferences → Signatures → Identities & Trusted Certificates → More →
   Trusted Certificates → Import** → add each `trust_*.pem`, and tick **Use this
   certificate as a trusted root** and **Certified documents / Data signatures**.
   - Run the whole protocol **twice** if you can: once *without* the roots
     trusted (shows the honest default a real recipient sees) and once *with*
     them trusted (isolates the algorithm/coverage behaviour from the trust
     question). Record which mode each observation came from.
3. Turn on: **Preferences → Signatures → Verification → "Verify signatures when
   the document is opened."**

## For each PDF, record these fields

Open the file, open the **Signature Panel** (the pen/ribbon icon on the left, or
**View → Show/Hide → Navigation Panes → Signatures**), then for every signature
listed, right-click → **Show Signature Properties**.

Record, per file:

- **Top-of-document banner** — the coloured bar Acrobat shows, verbatim
  (e.g. "Signed and all signatures are valid.", "At least one signature has
  problems.", "Signature validity is unknown.").
- **Number of signatures** listed in the panel.
- For **each** signature field:
  - Field / signer name and the green-check / warning-triangle / red-X icon.
  - Validity summary text (verbatim), e.g. "The signature is valid" /
    "…is invalid" / "…validity is unknown".
  - **Coverage line**, verbatim — this is the key one. Acrobat says one of:
    "This is a signed document. The signature covers the entire document." vs.
    "There have been changes made to this document since it was signed." /
    "The signature covers only a portion of the document." Which one appears?
  - Any error dialog or "unsupported" / parsing message when Acrobat meets the
    ML-DSA field (screenshot it verbatim).
- **A screenshot** of the panel + the Signature Properties dialog for each file.
  Name screenshots after the file, e.g. `A_intact_hybrid_panel.png`.

## The two questions the paper turns on

1. **Downgraded vs. legitimate (indistinguishability).** Confirm that
   `A_downgraded.pdf` and `A_legit_classical_only.pdf` produce a pixel-identical
   panel (they must — identical bytes). Likewise the B-LTA pair. One screenshot
   captioned "identical for both files" suffices.
2. **Intact hybrid rendering (the genuinely new observation).** On
   `A_intact_hybrid.pdf`, does Acrobat:
   - show the ECDSA signature as valid but the ML-DSA one as invalid/unknown
     (the graphical analogue of DSS's `PDF-NOT-ETSI`)? and
   - does the *downgraded* file then present as *cleaner* (one all-green
     signature) than the intact protected one — i.e. does Acrobat reproduce the
     "validates better" inversion the paper reports for DSS?
   Record the banner text for the intact hybrid and for the downgraded file
   side by side.
3. **Coverage warning (backward-compatibility hypothesis).** On the intact
   order-A hybrid, does the ECDSA signature's coverage line warn that changes
   were made after signing (because it covers only its own revision), while the
   order-B intact hybrid shows the last-applied ECDSA signature covering the
   whole file with no such warning? This is the concrete viewer test the paper
   currently flags as unmeasured.

## Reporting back

Fill `RESULTS_TEMPLATE.md`, attach the screenshots, and hand both back. The
paper section will be finalised from the verbatim banner/coverage text and the
screenshots.
