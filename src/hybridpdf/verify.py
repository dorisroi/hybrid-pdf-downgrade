"""
Validation, normalised.

pyHanko reports a signature's status as a rich object; every experiment needs
the same five fields from it, and needs document timestamps handled separately
from ordinary signatures. `inspect` returns a plain list of dicts so results are
JSON-serialisable and comparable across experiments.

`modification_level` is the field that matters for the t2 result: it is derived
by differencing the revision a signature covers against the final state of the
file, and it is the only thing that separates an honest order-B document from a
forged one (both report coverage ENTIRE_REVISION).
"""
import logging

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp

# pyHanko logs a full traceback whenever its difference analysis rejects a
# revision. That rejection is a measurement, not an error.
logging.getLogger("pyhanko").setLevel(logging.CRITICAL)


def _enum(v):
    return None if v is None else str(v).split(".")[-1]


def inspect(path, vc, include_timestamps=True):
    """Validate every signature in `path`. Never raises."""
    rows = []
    try:
        with open(path, "rb") as f:
            reader = PdfFileReader(f)
            for s in reader.embedded_signatures:
                is_ts = s.sig_object.get("/Type") == "/DocTimeStamp"
                if is_ts and not include_timestamps:
                    continue
                try:
                    st = (validate_pdf_timestamp(s, vc) if is_ts
                          else validate_pdf_signature(s, vc))
                    rows.append({
                        "field": "DocTimeStamp" if is_ts else s.field_name,
                        "timestamp": is_ts,
                        "intact": bool(getattr(st, "intact", False)),
                        "valid": bool(getattr(st, "valid", False)),
                        "trusted": bool(getattr(st, "trusted", False)),
                        "coverage": _enum(getattr(st, "coverage", None)),
                        "modification_level": _enum(getattr(st, "modification_level", None)),
                    })
                except Exception as e:
                    rows.append({
                        "field": "DocTimeStamp" if is_ts else s.field_name,
                        "timestamp": is_ts, "intact": False, "valid": False,
                        "trusted": False, "coverage": None,
                        "modification_level": f"ERROR:{type(e).__name__}",
                    })
    except Exception:
        pass                      # an unreadable prefix is simply not a document
    return rows


def good_signatures(rows):
    """Field names of ordinary signatures that are intact and valid."""
    return [r["field"] for r in rows
            if not r["timestamp"] and r["intact"] and r["valid"]]


def is_valid_signed_document(rows):
    """Does any signature at all still verify in this file?"""
    return any(r["intact"] and r["valid"] for r in rows)


def find(rows, field):
    for r in rows:
        if r["field"] == field:
            return r
    return None
