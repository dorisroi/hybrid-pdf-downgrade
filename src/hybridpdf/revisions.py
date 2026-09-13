"""
Revision boundaries — the whole attack surface in thirty lines.

A PDF revision ends at %%EOF. Because an incremental update appends, the bytes
before each %%EOF are an earlier, complete, independently verifiable document.
`eof_offsets` returns the offset just past each one; truncating there yields
that earlier document exactly.

The final offset is the end of the file, so the adversary's candidate cuts are
`eof_offsets(data)[:-1]`.
"""
import hashlib
import os


def eof_offsets(data):
    """Offsets just past each %%EOF marker, in file order."""
    out, i = [], data.find(b"%%EOF")
    while i >= 0:
        j = i + 5
        while data[j:j + 1] in (b"\r", b"\n"):
            j += 1
        out.append(j)
        i = data.find(b"%%EOF", i + 1)
    return out


def cut_points(data):
    """Every offset an adversary could truncate at (the file end is not a cut)."""
    return eof_offsets(data)[:-1]


def write_cuts(path, prefix):
    """Write one file per candidate cut. Returns [(index, offset, path)]."""
    data = open(path, "rb").read()
    out = []
    for idx, cut in enumerate(cut_points(data)):
        fp = f"{prefix}_cut{idx}.pdf"
        open(fp, "wb").write(data[:cut])
        out.append((idx, cut, fp))
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def identical(a, b):
    """Byte-identity, the claim the downgrade result actually rests on.

    Sizes drift a few bytes between runs because DER-encoded ECDSA signatures
    vary in length, so identity -- not any absolute size -- is what the paper
    should quote.
    """
    return (os.path.getsize(a) == os.path.getsize(b)
            and open(a, "rb").read() == open(b, "rb").read())
