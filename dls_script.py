#!/usr/bin/env python3
"""
CyberGuardX SOC Diploma - Project 04: Egyptian Data Protection DLP Challenge
Mini-DLP prototype  (classroom prototype - NOT an enterprise DLP, NOT legal advice)

Pipeline:  DETECT -> VALIDATE -> CLASSIFY -> RISK -> POLICY -> MASK -> LOG

Usage:
    python project4.py                      # run the mandatory test scenario
    python project4.py --text "Email: a@b.com, Phone: 01012345678"
    python project4.py --file data.csv notes.txt report.pdf folder/
                                            # file scanning (.txt/.csv/.pdf); PDF needs: pip install pypdf
    python project4.py --file screenshot.png  # OPTIONAL OCR: pip install pytesseract pillow + Tesseract program
    python project4.py --selftest           # run built-in test cases
    python project4.py --watch inbox/       # ACTIVE mode: keep monitoring a folder (Ctrl+C to stop)
    python project4.py --json               # also print the SIEM-ready JSON alert

Outputs:  dlp.log (human readable)  +  dlp_siem.jsonl (SIEM-ready JSON, one event per line)
Only SYNTHETIC test data is used. Raw sensitive values are never written to any log.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import re
import shutil
import socket
import sys
import time
import unicodedata
import uuid
from bisect import bisect_right
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

LOG_FILE = "dlp.log"
SIEM_FILE = "dlp_siem.jsonl"
MAX_FILE_BYTES = 20 * 1024 * 1024

# Classification labels (ordered by severity for reporting)
CRED, HIGH, FIN, SENS, PERS = (
    "CREDENTIAL_CRITICAL", "HIGHLY_SENSITIVE", "FINANCIAL_SENSITIVE",
    "SENSITIVE", "PERSONAL_DATA",
)
RANK = {CRED: 5, HIGH: 4, FIN: 3, SENS: 2, PERS: 1}

# Per-run secret so SOC can correlate the same value across events WITHOUT storing it.
# Set DLP_FP_KEY in the environment to correlate across runs.
_FP_KEY = os.environ.get("DLP_FP_KEY", uuid.uuid4().hex).encode()


# ───────────────────────── Normalisation (Arabic-aware) ─────────────────────────
# Length-preserving, so match offsets on the normalised text are valid on the original.
_NORM = str.maketrans({
    **{chr(0x660 + i): str(i) for i in range(10)},   # Arabic-Indic digits  ٠-٩
    **{chr(0x6F0 + i): str(i) for i in range(10)},   # Persian digits       ۰-۹
    "أ": "ا", "إ": "ا", "آ": "ا", "ى": "ي", "ة": "ه",
})


def normalize(text: str) -> str:
    return text.translate(_NORM)


# ───────────────────────────────── Masking ──────────────────────────────────────
def mask_tail(value: str, keep: int = 4, fixed: int | None = None) -> str:
    """29801011234567 -> ************4567  (fixed=12 also hides the real length)"""
    chars = [c for c in value if c.isalnum()]
    stars = fixed if fixed is not None else max(len(chars) - keep, 0)
    return "*" * stars + "".join(chars[-keep:])


def mask_email(value: str) -> str:
    """ahmed@example.com -> a***@example.com"""
    local, _, domain = value.partition("@")
    return f"{local[:1]}***@{domain}"


def mask_secret(_: str) -> str:
    return "********"


def fingerprint(raw: str) -> str:
    return hmac.new(_FP_KEY, raw.encode(), hashlib.sha256).hexdigest()[:12]


# ──────────────────────────────── Validators ────────────────────────────────────
GOVERNORATES = {
    "01", "02", "03", "04", "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "21", "22", "23", "24", "25", "26", "27", "28", "29", "31", "32", "33", "34",
    "35", "88",  # 88 = born abroad
}


def validate_national_id(s: str) -> tuple[bool, str]:
    """Century digit + real calendar date (not in future) + governorate code."""
    year = (1900 if s[0] == "2" else 2000) + int(s[1:3])
    try:
        born = date(year, int(s[3:5]), int(s[5:7]))
    except ValueError:
        return False, "impossible birth date"
    if born > date.today():
        return False, "birth date in the future"
    if s[7:9] not in GOVERNORATES:
        return False, "unknown governorate code"
    return True, "structure valid"


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def card_brand(d: str) -> str | None:
    if d[0] == "4" and len(d) in (13, 16, 19):
        return "VISA"
    if len(d) == 16 and (51 <= int(d[:2]) <= 55 or 2221 <= int(d[:4]) <= 2720):
        return "MASTERCARD"
    if len(d) == 15 and d[:2] in ("34", "37"):
        return "AMEX"
    if len(d) == 16 and d.startswith("507803"):
        return "MEEZA"          # Egypt's national scheme (BIN per public lists - verify)
    return None


def iban_ok(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


# ──────────────────────────────── Detection ─────────────────────────────────────
NID_ANY = re.compile(r"(?<!\d)[23]\d{13}(?!\d)")
CARD_RE = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
PHONE_RE = re.compile(r"(?<![\d+])(?:\+20|0020|0)[ -]?1[0125](?:[ -]?\d){8}(?!\d)")
EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IBAN_RE = re.compile(r"(?<![A-Za-z0-9])EG\d{2}(?: ?\d){25}(?!\d)", re.I)

# Sensitive keywords (English + Arabic). val = regex for the value after "KEY: value".
KEYWORDS = [
    dict(type="PASSWORD", cls=CRED, score=50, mention=5, val=r"\S+", mask="secret", force=True,
         words=["password", "passwd", "pwd", "كلمة السر", "كلمة المرور", "الباسورد", "باسورد"]),
    dict(type="MEDICAL_RECORD", cls=SENS, score=50, mention=5, val=r"[^\n,;]+", mask="secret",
         force=False, words=["medical record", "diagnosis", "سجل طبي", "ملف طبي", "تشخيص"]),
    dict(type="SALARY", cls=SENS, score=20, mention=3, val=r"[^\n,;]+", mask="secret",
         force=False, words=["salary", "الراتب", "المرتب"]),
    dict(type="PASSPORT", cls=HIGH, score=30, mention=3, val=r"[A-Za-z]?\d{7,9}", mask="tail",
         force=False, words=["passport", "جواز السفر", "رقم الجواز"]),
    dict(type="BANK_ACCOUNT", cls=FIN, score=40, mention=5, val=r"[A-Za-z]{0,2}\d[\d \-]{6,}\d",
         mask="tail", force=False,
         words=["bank account", "account number", "رقم الحساب", "الحساب البنكي", "حساب بنكي"]),
    # Context-only labels: shown to the analyst, add 0 risk (reduces false positives)
    dict(type="NATIONAL_ID", cls=HIGH, score=0, mention=0, val=None, mask="tail", force=False,
         words=["national id", "الرقم القومي", "رقم قومي"]),
    dict(type="CREDIT_CARD", cls=FIN, score=0, mention=0, val=None, mask="tail", force=False,
         words=["credit card", "card number", "بطاقة ائتمان", "بطاقه ائتمان", "فيزا"]),
]
for _k in KEYWORDS:
    _alt = "|".join(normalize(w) for w in _k["words"])
    _val = rf"(?:[ \t]*[:=\-–][ \t]*(?P<val>{_k['val']}))?" if _k["val"] else ""
    _k["re"] = re.compile(rf"(?<!\w)(?:{_alt})(?!\w){_val}", re.I)


@dataclass
class Finding:
    type: str
    cls: str
    score: int
    start: int
    end: int
    masked: str
    fp: str = ""
    note: str = ""
    prio: int = 5             # lower = wins overlaps
    force_block: bool = False
    sensitive: bool = True    # False = context keyword only (not redacted)
    line: int = 1
    page: int = 0             # PDF page (0 = not a PDF)


def _mk(typ, cls, score, s, e, raw, masked, **kw) -> Finding:
    return Finding(typ, cls, score, s, e, masked, fingerprint(raw), **kw)


def detect(norm: str) -> list[Finding]:
    c: list[Finding] = []

    for k in KEYWORDS:                                            # keywords (+ values)
        for m in k["re"].finditer(norm):
            if m.groupdict().get("val"):
                val = m.group("val").rstrip()
                s = m.start("val")
                masked = mask_tail(val) if k["mask"] == "tail" else mask_secret(val)
                c.append(_mk(k["type"], k["cls"], k["score"], s, s + len(val), val, masked,
                             note="keyword + value", prio=0, force_block=k["force"]))
            else:
                c.append(_mk("KEYWORD_" + k["type"], k["cls"], k["mention"], m.start(), m.end(),
                             m.group(), m.group(), note="keyword only (no value)",
                             prio=9, sensitive=False))

    for m in NID_ANY.finditer(norm):                              # National ID
        ok, why = validate_national_id(m.group())
        c.append(_mk("EGYPTIAN_NATIONAL_ID" if ok else "EGYPTIAN_NATIONAL_ID_SUSPECTED", HIGH,
                     40 if ok else 15, m.start(), m.end(), m.group(),
                     mask_tail(m.group(), fixed=12), note=why, prio=1 if ok else 3))

    for m in IBAN_RE.finditer(norm):                              # Egyptian IBAN (mod-97)
        ok = iban_ok(m.group())
        c.append(_mk("EGYPTIAN_IBAN" if ok else "EGYPTIAN_IBAN_SUSPECTED", FIN, 40 if ok else 15,
                     m.start(), m.end(), m.group(), mask_tail(m.group()),
                     note="mod-97 OK" if ok else "mod-97 failed", prio=1 if ok else 4))

    for m in CARD_RE.finditer(norm):                              # Credit cards (+ Luhn)
        d = re.sub(r"\D", "", m.group())
        if not 13 <= len(d) <= 19:
            continue
        brand, ok = card_brand(d), luhn_ok(d)
        if brand and ok:
            c.append(_mk("CREDIT_CARD", FIN, 40, m.start(), m.end(), d, mask_tail(d),
                         note=f"{brand}, Luhn OK", prio=2))
        elif brand or ok:
            c.append(_mk("CREDIT_CARD_SUSPECTED", FIN, 15, m.start(), m.end(), d, mask_tail(d),
                         note=("Luhn failed" if brand else "no known brand prefix"), prio=4))

    for m in PHONE_RE.finditer(norm):                             # Egyptian mobile
        c.append(_mk("EGYPTIAN_MOBILE", PERS, 10, m.start(), m.end(), m.group(),
                     mask_tail(m.group()), note="01[0125] + 8 digits", prio=5))

    for m in EMAIL_RE.finditer(norm):                             # Email
        c.append(_mk("EMAIL", PERS, 10, m.start(), m.end(), m.group(), mask_email(m.group()),
                     note="email pattern", prio=6))
    return c


def resolve_overlaps(cands: list[Finding]) -> list[Finding]:
    """One piece of text = one finding (e.g. a 14-digit ID is not ALSO a 'card')."""
    taken: list[tuple[int, int]] = []
    out: list[Finding] = []
    for f in sorted(cands, key=lambda f: (f.prio, f.start)):
        if all(f.end <= s or f.start >= e for s, e in taken):
            out.append(f)
            taken.append((f.start, f.end))
    return sorted(out, key=lambda f: f.start)


# ─────────────────────────── Risk engine + Policy engine ────────────────────────
@dataclass
class Result:
    scan_id: str
    source: str
    findings: list[Finding]
    breakdown: dict
    correlations: list
    total: int
    level: str
    action: str
    redacted: str
    ocr: bool = False         # text came from an image (OCR) -> may contain read errors


def calculate_risk(findings: list[Finding]) -> tuple[int, dict, list]:
    """
    Per type: base score, +25% for each extra occurrence, capped at 2x base
    (10 emails are worse than 1, but not 10x worse -> fewer noisy BLOCKs).
    Plus correlation rules for dangerous *combinations*.
    """
    by_type: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_type[f.type].append(f)
    breakdown = {}
    for t, fs in by_type.items():
        base, n = max(f.score for f in fs), len(fs)
        breakdown[t] = (n, int(min(base * (1 + 0.25 * (n - 1)), base * 2)))

    real = [f for f in findings if f.sensitive and f.score > 0]
    types, classes = {f.type for f in real}, {f.cls for f in real}
    corr = []
    if "EGYPTIAN_NATIONAL_ID" in types and types & {"CREDIT_CARD", "EGYPTIAN_IBAN", "BANK_ACCOUNT"}:
        corr.append(("IDENTITY_FRAUD_KIT", 20))        # ID + financial = ready-made fraud kit
    if CRED in classes and classes & {PERS, HIGH}:
        corr.append(("CREDENTIAL_WITH_PII", 10))       # login + identity = account takeover
    if sum(1 for f in real if f.cls == PERS) >= 10:
        corr.append(("BULK_PII_EXPOSURE", 20))         # looks like a customer-list dump
    total = sum(s for _, s in breakdown.values()) + sum(s for _, s in corr)
    return total, breakdown, corr


def apply_policy(total: int, findings: list[Finding]) -> tuple[str, str]:
    if total >= 81:
        action, level = "BLOCK", "CRITICAL"
    elif total >= 51:
        action, level = "BLOCK", "HIGH"
    elif total >= 21:
        action, level = "ALERT", "MEDIUM"
    else:
        action, level = "ALLOW", "LOW"
    # Hard rule: a leaked credential is never "just an alert"
    if action != "BLOCK" and any(f.force_block for f in findings):
        action, level = "BLOCK", "HIGH"
    return action, level


def redact(text: str, findings: list[Finding]) -> str:
    out = text
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        if f.sensitive:
            out = out[:f.start] + f.masked + out[f.end:]
    return out


def analyze(text: str, source: str = "console", page_starts: list[int] | None = None,
            ocr: bool = False) -> Result:
    norm = normalize(text)
    findings = resolve_overlaps(detect(norm))
    for f in findings:
        base = 0
        if page_starts:                       # PDF: page number + line inside that page
            f.page = bisect_right(page_starts, f.start)
            base = page_starts[f.page - 1]
        f.line = norm.count("\n", base, f.start) + 1
    total, breakdown, corr = calculate_risk(findings)
    action, level = apply_policy(total, findings)
    return Result(uuid.uuid4().hex[:8], source, findings, breakdown, corr, total, level, action,
                  redact(text, findings), ocr)


# ─────────────────────────────── SOC logging / SIEM ─────────────────────────────
def setup_logger(path: str = LOG_FILE) -> logging.Logger:
    lg = logging.getLogger("dlp")
    if not lg.handlers:
        h = logging.FileHandler(path, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        lg.addHandler(h)
        lg.setLevel(logging.INFO)
        lg.propagate = False
    return lg


def top_class(r: Result) -> str:
    cl = [f.cls for f in r.findings if f.score > 0]
    return max(cl, key=RANK.get) if cl else "NONE"


def write_log(r: Result) -> None:
    lg = setup_logger()
    lvl = {"LOW": logging.INFO, "MEDIUM": logging.WARNING,
           "HIGH": logging.ERROR, "CRITICAL": logging.CRITICAL}[r.level]
    for f in r.findings:
        if f.score == 0:
            continue
        lg.log(lvl, f"EVENT=DLP_FINDING SCAN={r.scan_id} SOURCE={r.source} "
                    f"{'PAGE=' + str(f.page) + ' ' if f.page else ''}LINE={f.line} "
                    f"TYPE={f.type} CLASSIFICATION={f.cls} FINDING_SCORE={f.score} "
                    f"RISK={r.total} ACTION={r.action} VALUE={f.masked} FP={f.fp}")
    corr = ",".join(n for n, _ in r.correlations) or "NONE"
    lg.log(lvl, f"EVENT=DLP_VERDICT SCAN={r.scan_id} SOURCE={r.source} "
                f"FINDINGS={sum(1 for f in r.findings if f.score > 0)} CLASSIFICATION={top_class(r)} "
                f"RISK={r.total} LEVEL={r.level} ACTION={r.action} CORRELATIONS={corr}"
                f"{' OCR=true' if r.ocr else ''}")


def siem_event(r: Result) -> dict:
    return {
        "@timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "event": {"id": r.scan_id, "kind": "alert" if r.action != "ALLOW" else "event",
                  "category": ["data_loss_prevention"], "action": r.action,
                  "severity": {"LOW": 1, "MEDIUM": 4, "HIGH": 7, "CRITICAL": 10}[r.level]},
        "host": {"name": socket.gethostname()},
        "rule": {"name": "CyberGuardX-MiniDLP", "version": "1.0"},
        "dlp": {
            "source": r.source, "ocr": r.ocr, "risk_score": r.total, "risk_level": r.level, "action": r.action,
            "top_classification": top_class(r),
            "correlations": [{"rule": n, "score": s} for n, s in r.correlations],
            "findings": [{"type": f.type, "classification": f.cls, "score": f.score,
                          "masked_value": f.masked, "fingerprint": f.fp, "line": f.line, "page": f.page or None,
                          "validation": f.note} for f in r.findings if f.score > 0],
        },
    }


def write_siem(r: Result) -> dict:
    ev = siem_event(r)
    with open(SIEM_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return ev


# ─────────────────────────────────── Console UI ─────────────────────────────────
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(txt: str, code: str) -> str:
    return f"\033[{code}m{txt}\033[0m" if USE_COLOR else txt


def render(r: Result) -> None:
    col = {"ALLOW": "92", "ALERT": "93", "BLOCK": "91"}[r.action]
    bar = "═" * 78
    print(c(bar, "96"))
    print(c(f" CyberGuardX Mini-DLP   scan={r.scan_id}   source={r.source}", "96;1"))
    print(c(bar, "96"))
    if r.ocr:
        print(c(" ℹ Text extracted from an image via OCR - digits may be misread; verify manually.\n", "93"))
    if r.findings:
        print(f" {'#':<3}{'TYPE':<31}{'CLASS':<21}{'SCORE':<6}{'LOC':<8}VALUE (masked)")
        print(" " + "─" * 76)
        for i, f in enumerate(r.findings, 1):
            tag = c(f"{f.score:<6}", "93" if f.score else "90")
            loc = f"p{f.page}:{f.line}" if f.page else str(f.line)
            print(f" {i:<3}{f.type:<31}{f.cls:<21}{tag}{loc:<8}{f.masked}")
            print(c(f"    ↳ {f.note}", "90"))
    else:
        print(" No sensitive data found.")
    print(" " + "─" * 76)
    for t, (n, s) in r.breakdown.items():
        if s:
            print(f"   {t:<34} x{n:<3} → +{s}")
    for name, s in r.correlations:
        print(c(f"   ⚠ correlation: {name:<22} → +{s}", "95"))
    print(f"\n RISK SCORE : {c(str(r.total), col + ';1')}   LEVEL: {c(r.level, col)}")
    print(f" ACTION     : {c(r.action, col + ';1')}")
    if r.findings:
        print(c("\n Redacted preview (what is safe to show/store):", "90"))
        for ln in r.redacted.splitlines():
            print("   " + ln)
    print()


# ───────────────────────────────── Files & demo ─────────────────────────────────
DEMO_TEXT = """Customer Name: Ahmed Mohamed
Email: ahmed@example.com
Phone: 01012345678
National ID: 29801011234567
Credit Card: 4111111111111111
Password: Admin@123
Salary: 15000 EGP"""


def read_pdf(path: Path):
    """Extract text from a PDF. Returns (text, page_start_offsets) or None. Needs: pip install pypdf"""
    try:
        from pypdf import PdfReader
    except ImportError:
        print(f"[skip] {path}: PDF support needs pypdf  ->  pip install pypdf")
        return None
    try:
        reader = PdfReader(str(path))
        if reader.is_encrypted and not reader.decrypt(""):
            print(f"[skip] {path}: password-protected PDF")
            return None
        parts, starts, pos = [], [], 0
        for page in reader.pages:
            t = unicodedata.normalize("NFKC", page.extract_text() or "")  # Arabic presentation forms
            starts.append(pos)
            parts.append(t)
            pos += len(t) + 1
    except Exception as exc:
        print(f"[skip] {path}: cannot read PDF ({exc.__class__.__name__})")
        return None
    text = "\n".join(parts)
    if not text.strip():
        print(f"[skip] {path}: no extractable text (scanned image? it would need OCR)")
        return None
    return text, starts


IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp")


def read_image(path: Path) -> str | None:
    """OPTIONAL: OCR an image. Needs  pip install pytesseract pillow  +  the Tesseract program."""
    try:
        import pytesseract
        from PIL import Image
    except ImportError:
        print(f"[skip] {path}: image scanning needs  pip install pytesseract pillow")
        return None
    if not shutil.which("tesseract"):                       # Windows: look in the usual install folders
        for cand in (os.environ.get("TESSERACT_CMD", ""),
                     r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                     r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
                     os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe")):
            if cand and os.path.isfile(cand):
                pytesseract.pytesseract.tesseract_cmd = cand
                break
    try:
        langs = pytesseract.get_languages(config="")
    except Exception:
        print(f"[skip] {path}: Tesseract OCR program is not installed / not in PATH")
        return None
    lang = "eng+ara" if "ara" in langs else "eng"
    try:
        img = Image.open(path).convert("L")                 # grayscale helps OCR
        if img.width < 1500:                                 # upscale small screenshots
            img = img.resize((img.width * 2, img.height * 2))
        text = pytesseract.image_to_string(img, lang=lang)
    except Exception as exc:
        print(f"[skip] {path}: cannot OCR image ({exc.__class__.__name__})")
        return None
    text = unicodedata.normalize("NFKC", text)
    if not text.strip():
        print(f"[skip] {path}: no text recognised in the image")
        return None
    return text


def collect_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.suffix.lower() in (".txt", ".csv", ".pdf") + IMAGE_EXTS)
        elif p.is_file() and p.suffix.lower() in (".txt", ".csv", ".pdf") + IMAGE_EXTS:
            files.append(p)
        else:
            print(f"[skip] {p}: not a supported file (.txt .csv .pdf or image) or folder")
    return files


def emit(r: Result, show_json: bool = False) -> None:
    render(r)
    write_log(r)
    ev = write_siem(r)
    if show_json:
        print(json.dumps(ev, indent=2, ensure_ascii=False))


# ─────────────────────────────────── Self-test ──────────────────────────────────
def _test_iban() -> str:
    bban = "1234567890123456789012345"
    check = 98 - int("".join(str(int(ch, 36)) for ch in bban + "EG00")) % 97
    return f"EG{check:02d}{bban}"


def selftest() -> int:
    cases = [  # name, text, expected action, type that must be present (or None)
        ("Mandatory scenario", DEMO_TEXT, "BLOCK", "CREDIT_CARD"),
        ("Clean text", "Meeting at 10am tomorrow, see you there.", "ALLOW", None),
        ("Email only", "Contact: student@example.com", "ALLOW", "EMAIL"),
        ("Valid National ID alone", "ID 29801011234567", "ALERT", "EGYPTIAN_NATIONAL_ID"),
        ("ID + phone + email", "29801011234567 01012345678 a@b.com", "BLOCK", "EMAIL"),
        ("Impossible ID (month 13)", "29813011234567", "ALLOW", "EGYPTIAN_NATIONAL_ID_SUSPECTED"),
        ("Card failing Luhn", "4111111111111112", "ALLOW", "CREDIT_CARD_SUSPECTED"),
        ("Phone with +20 and spaces", "call +20 101 234 5678", "ALLOW", "EGYPTIAN_MOBILE"),
        ("Arabic keywords + Arabic digits",
         "الرقم القومي: ٢٩٨٠١٠١١٢٣٤٥٦٧ - كلمة السر: Pass@2026", "BLOCK", "PASSWORD"),
        ("Password alone (hard rule)", "password: hunter2", "BLOCK", "PASSWORD"),
        ("Valid Egyptian IBAN", f"IBAN {_test_iban()}", "ALERT", "EGYPTIAN_IBAN"),
        ("Bulk customer list", "\n".join(f"u{i}@example.com" for i in range(12)), "ALERT", "EMAIL"),
        ("Label without value", "Please send your National ID later", "ALLOW", "KEYWORD_NATIONAL_ID"),
    ]
    failed = 0
    print(f"{'TEST':<34}{'RISK':<6}{'ACTION':<8}RESULT")
    print("─" * 60)
    for name, text, want, need in cases:
        r = analyze(text, "selftest")
        ok = r.action == want and (need is None or any(f.type == need for f in r.findings))
        failed += not ok
        print(f"{name:<34}{r.total:<6}{r.action:<8}{'PASS' if ok else 'FAIL (want ' + want + ')'}")
    print("─" * 60)
    print("ALL TESTS PASSED" if not failed else f"{failed} TEST(S) FAILED")
    return 1 if failed else 0


def scan_file(p: Path, show_json: bool = False) -> None:
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            print(f"[skip] {p}: larger than {MAX_FILE_BYTES // 1024 // 1024} MB")
            return
        if p.suffix.lower() == ".pdf":
            got = read_pdf(p)
            if got:
                emit(analyze(got[0], str(p), got[1]), show_json)
        elif p.suffix.lower() in IMAGE_EXTS:
            text = read_image(p)
            if text:
                emit(analyze(text, str(p), ocr=True), show_json)
        else:
            emit(analyze(p.read_text(encoding="utf-8-sig", errors="replace"), str(p)), show_json)
    except OSError as exc:
        print(f"[skip] {p}: {exc.__class__.__name__}")


def watch(folder: str, interval: float, show_json: bool = False) -> None:
    """Active mode: poll a folder, scan every new or modified .txt/.csv/.pdf file."""
    root = Path(folder)
    if not root.is_dir():
        print(f"[error] {folder} is not a folder")
        return
    seen: dict[Path, float] = {}
    print(c(f"[WATCH] monitoring {root.resolve()} every {interval}s  (Ctrl+C to stop)\n", "96;1"))
    try:
        while True:
            for p in collect_files([str(root)]):
                try:
                    mtime = p.stat().st_mtime
                except OSError:
                    continue
                if seen.get(p) != mtime:
                    seen[p] = mtime
                    time.sleep(0.3)               # let the writer finish the file
                    print(c(f"[WATCH] new/changed file: {p.name}", "96"))
                    scan_file(p, show_json)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(c("\n[WATCH] stopped.", "96"))


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="CyberGuardX Mini-DLP (Egyptian PII)")
    ap.add_argument("--text", help="scan a text string")
    ap.add_argument("--file", nargs="+", help=".txt/.csv/.pdf/image files or folders to scan")
    ap.add_argument("--watch", metavar="FOLDER", help="active mode: keep monitoring a folder")
    ap.add_argument("--interval", type=float, default=2.0, help="watch polling seconds (default 2)")
    ap.add_argument("--selftest", action="store_true", help="run built-in test cases")
    ap.add_argument("--json", action="store_true", help="print the SIEM-ready JSON alert")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if args.file:
        for p in collect_files(args.file):
            scan_file(p, args.json)
    elif args.watch:
        watch(args.watch, args.interval, args.json)
    elif args.text:
        emit(analyze(args.text), args.json)
    else:
        print(c("Running the mandatory test scenario (synthetic data)...\n", "90"))
        emit(analyze(DEMO_TEXT, "demo_scenario"), args.json)


if __name__ == "__main__":
    main()
