#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PROFILER — ctOS Personal Intelligence Terminal  (v1.0.0)

A personal profile & records database. Stores ONLY data about
consenting / known contacts collected with permission. All OSINT uses
lawful public sources only (ip-api.com, RDAP, crt.sh, DNS, Nominatim).

License intent: MIT. Single-file, Python 3 stdlib only.

Usage:
    profiler                     interactive app
    profiler <subcommand> ...    CLI (see --help)
"""
import base64
import csv
import datetime
import difflib
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zlib

VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Paths & constants
# --------------------------------------------------------------------------
BASE = os.path.join(os.path.expanduser("~"), ".profiler")
PROFILES_DIR = os.path.join(BASE, "profiles")
PHOTOS_DIR = os.path.join(BASE, "photos")
BACKUP_DIR = os.path.join(BASE, "backups")
CONFIG_PATH = os.path.join(BASE, "config.json")
KEY_PATH = os.path.join(BASE, ".key")
EXPORT_PATH = os.path.join(BASE, "profiles-export.json")
GDRIVE_REMOTE = "gdrive:profiler"

IS_ANDROID = "ANDROID_ROOT" in os.environ

MAGIC = b"PROF1"
PBKDF2_ITERS = 200000

BANNER = """
  PROFILER  -  ctOS Personal Intelligence Terminal  v%s
""" % VERSION

RECORD_TYPES = ["note", "meeting", "call", "message", "transaction",
                "sighting", "file", "location", "osint", "other"]
RELATIONS = ["ally", "target", "contact", "family", "work", "unknown"]
THREATS = ["none", "low", "medium", "high"]
STATUSES = ["active", "archived", "unknown"]

FIELD_ALIASES = {
    "name": "name",
    "alias": "aliases", "aliases": "aliases", "aka": "aliases", "nickname": "aliases",
    "phone": "phone", "phones": "phone", "num": "phone", "number": "phone", "tel": "phone",
    "email": "email", "mail": "email", "emails": "email",
    "address": "address", "addr": "address",
    "occupation": "occupation", "job": "occupation", "work": "occupation", "profession": "occupation",
    "employer": "employer", "company": "employer", "org": "employer",
    "dob": "dob", "bday": "dob", "birthday": "dob", "birthdate": "dob",
    "status": "status",
    "threat": "threat", "risk": "threat",
    "relation": "relation", "rel": "relation", "relationship": "relation",
    "tags": "tags", "tag": "tags",
    "notes": "notes", "note": "notes", "comment": "notes",
    "created_at": "created_at", "updated_at": "updated_at",
}

CATEGORY_ALIASES = dict(FIELD_ALIASES)
CATEGORY_ALIASES.update({
    "photo": "photos", "photos": "photos", "pic": "photos", "pics": "photos",
    "img": "photos", "image": "photos", "images": "photos",
    "location": "locations", "locations": "locations", "loc": "locations",
    "gps": "locations", "map": "locations",
    "record": "records", "records": "records", "rec": "records",
    "timeline": "records", "history": "records",
    "link": "links", "links": "links", "connection": "links", "connections": "links",
    "reminder": "reminders", "reminders": "reminders", "rem": "reminders", "todo": "reminders",
})

RECORD_ALIASES = {
    "note": "note", "notes": "note", "comment": "note",
    "meeting": "meeting", "meet": "meeting",
    "call": "call", "calllog": "call",
    "message": "message", "msg": "message", "sms": "message",
    "transaction": "transaction", "tx": "transaction", "txn": "transaction", "payment": "transaction",
    "sighting": "sighting", "seen": "sighting", "spot": "sighting",
    "file": "file", "attachment": "file",
    "location": "location", "loc": "location",
    "osint": "osint",
    "other": "other", "misc": "other",
}

RELATION_ALIASES = dict((r, r) for r in RELATIONS)
RELATION_ALIASES.update({"friend": "contact", "associate": "contact", "family": "family",
                         "work": "work", "colleague": "work", "boss": "work",
                         "ally": "ally", "target": "target", "unknown": "unknown"})

THREAT_ALIASES = dict((t, t) for t in THREATS)

COMMANDS = [
    "profiles", "list", "ls", "all", "profile", "show", "new", "add", "create",
    "edit", "record", "link", "graph", "network", "connections", "osint",
    "photo", "view", "pics", "map", "locate", "gps", "loc", "remind",
    "reminders", "todo", "backup", "save", "export", "import", "delete",
    "del", "rm", "remove", "stats", "status", "encrypt", "lock", "unlock",
    "sync", "search", "manage", "help", "show-field", "open-location", "exit",
    "quit", "q", "menu", "back", "ask", "ai", "assistant", "who", "who-at",
    "websearch", "searchweb", "web", "fetch", "geturl",
]

# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------
def out(msg=""):
    print(msg)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_dirs():
    for d in (BASE, PROFILES_DIR, PHOTOS_DIR, BACKUP_DIR):
        if not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)


def slugify(name):
    s = unicodedata.normalize("NFKD", str(name))
    s = s.encode("ascii", "ignore").decode("ascii", "ignore")
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return s or ""


def unique_id(name):
    base = slugify(name) or "profile"
    pid = base
    i = 2
    while os.path.exists(os.path.join(PROFILES_DIR, pid + ".json")):
        pid = "%s-%d" % (base, i)
        i += 1
    return pid


def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def is_cancel(s):
    return s.strip().lower() in ("c", "cancel", "q", "quit", "exit", "abort")


def prompt(label, default=None):
    if default not in (None, ""):
        r = input("%s [%s]: " % (label, default)).strip()
        return r if r else default
    r = input(label + ": ").strip()
    return r if r else ""


def confirm(q):
    r = input("%s (y/N): " % q).strip().lower()
    return r in ("y", "yes")


def open_file(path):
    try:
        if os.name == "nt":
            os.startfile(path)
        elif IS_ANDROID:
            subprocess.Popen(["termux-open", path])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as e:
        print("Could not open: %s" % e)


def open_url(url):
    open_file(url)


# --------------------------------------------------------------------------
# Encryption (stdlib only: PBKDF2-HMAC-SHA256 + HMAC-SHA256 CTR + tag)
# --------------------------------------------------------------------------
def get_key():
    ensure_dirs()
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = os.urandom(32)
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def _keystream(mk, ek, nonce, length):
    out = b""
    c = 0
    while len(out) < length:
        out += hmac.new(mk, ek + nonce + c.to_bytes(8, "big"), hashlib.sha256).digest()
        c += 1
    return out[:length]


def encrypt_blob(data):
    key = get_key()
    salt = os.urandom(16)
    nonce = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", key, salt, PBKDF2_ITERS, dklen=64)
    ek, mk = dk[:32], dk[32:]
    ks = _keystream(mk, ek, nonce, len(data))
    ct = bytes(a ^ b for a, b in zip(data, ks))
    tag = hmac.new(mk, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(MAGIC + salt + nonce + ct + tag).decode("ascii")


def decrypt_blob(b64):
    key = get_key()
    raw = base64.b64decode(b64)
    if raw[:5] != MAGIC:
        raise ValueError("bad encrypted blob")
    salt, nonce = raw[5:21], raw[21:37]
    body, tag = raw[37:-32], raw[-32:]
    dk = hashlib.pbkdf2_hmac("sha256", key, salt, PBKDF2_ITERS, dklen=64)
    ek, mk = dk[:32], dk[32:]
    expect = hmac.new(mk, nonce + body, hashlib.sha256).digest()
    if not hmac.compare_digest(expect, tag):
        raise ValueError("integrity check failed (wrong key or corrupted data)")
    ks = _keystream(mk, ek, nonce, len(body))
    return bytes(a ^ b for a, b in zip(body, ks))


def _encryption_enabled():
    return bool(get_config().get("encryption"))


def get_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def set_config(**kw):
    ensure_dirs()
    cfg = get_config()
    cfg.update(kw)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


# --------------------------------------------------------------------------
# Profile storage
# --------------------------------------------------------------------------
def list_pids():
    if not os.path.isdir(PROFILES_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(PROFILES_DIR) if f.endswith(".json"))


def load(pid):
    path = os.path.join(PROFILES_DIR, pid + ".json")
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    try:
        return json.loads(raw)
    except Exception:
        return json.loads(decrypt_blob(raw.strip()).decode("utf-8"))


def save(pid, data):
    ensure_dirs()
    data["updated_at"] = now_iso()
    raw = json.dumps(data, indent=2, ensure_ascii=False)
    if _encryption_enabled():
        raw = encrypt_blob(raw.encode("utf-8"))
    path = os.path.join(PROFILES_DIR, pid + ".json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(raw)
    os.replace(tmp, path)


def ensure_shape(p):
    defaults = {"aliases": [], "tags": [], "records": [], "links": [],
                "photos": [], "locations": [], "reminders": []}
    for k, d in defaults.items():
        p.setdefault(k, list(d))
    for k in ("phone", "email", "address", "occupation", "employer", "dob", "notes"):
        p.setdefault(k, "")
    p.setdefault("status", "active")
    p.setdefault("threat", "none")
    p.setdefault("relation", "unknown")
    p.setdefault("name", "")
    p.setdefault("id", unique_id(p.get("name") or "profile"))
    p.setdefault("created_at", now_iso())
    p.setdefault("updated_at", now_iso())
    return p


def new_profile(name, **fields):
    pid = unique_id(name)
    p = {
        "id": pid, "name": name, "aliases": [], "phone": "", "email": "",
        "address": "", "occupation": "", "employer": "", "dob": "",
        "status": "active", "threat": "none", "relation": "unknown",
        "tags": [], "notes": "", "records": [], "links": [],
        "photos": [], "locations": [], "reminders": [],
    }
    p["created_at"] = p["updated_at"] = now_iso()
    for k, v in fields.items():
        if v in (None, True, False, ""):
            continue
        set_field(p, k, v)
    save(pid, p)
    return pid


def set_field(p, field, value, silent=False):
    if value is None or value is True or value is False:
        return
    v = str(value)
    if field == "aliases":
        p["aliases"] = [x.strip() for x in v.split(",") if x.strip()]
    elif field == "tags":
        p["tags"] = [x.strip() for x in v.split(",") if x.strip()]
    elif field == "dob":
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", v) and not silent:
            print("Note: '%s' doesn't look like YYYY-MM-DD" % v)
        p["dob"] = v
    elif field == "threat":
        vt = v.lower()
        if vt not in THREATS and not silent:
            print("Note: threat '%s' not in %s" % (v, THREATS))
        p["threat"] = vt
    elif field == "relation":
        vr = v.lower()
        if vr not in RELATIONS and not silent:
            print("Note: relation '%s' not in %s" % (v, RELATIONS))
        p["relation"] = vr
    else:
        p[field] = v


def numbered_profiles(status=None, tag=None):
    rows = []
    for pid in list_pids():
        p = load(pid)
        if status and p.get("status") != status:
            continue
        if tag and tag not in p.get("tags", []):
            continue
        rows.append((pid, p["name"]))
    rows.sort(key=lambda r: r[1].lower())
    return [(i, pid, name) for i, (pid, name) in enumerate(rows, 1)]


def find_profiles(q):
    q = q.strip().lower()
    if not q:
        return []
    pids = list_pids()
    for pid in pids:
        if pid == q:
            return [pid]
    exact = []
    for pid in pids:
        p = load(pid)
        if p["name"].lower() == q or any(a.lower() == q for a in p["aliases"]):
            exact.append(pid)
    if exact:
        return exact
    partial = []
    for pid in pids:
        p = load(pid)
        if q in pid or q in p["name"].lower() or any(q in a.lower() for a in p["aliases"]):
            partial.append(pid)
    if partial:
        return partial
    fuzzy = []
    for pid in pids:
        p = load(pid)
        cands = [p["name"].lower(), pid] + [a.lower() for a in p["aliases"]]
        if any(difflib.SequenceMatcher(None, q, c).ratio() >= 0.6 for c in cands):
            fuzzy.append(pid)
    return fuzzy


def resolve_profile(q, interactive=True):
    q = (q or "").strip()
    if not q:
        return None
    if q.isdigit() and interactive:
        rows = numbered_profiles()
        n = int(q)
        if 1 <= n <= len(rows):
            return rows[n - 1][1]
    cands = find_profiles(q)
    if len(cands) == 1:
        return cands[0]
    if len(cands) > 1:
        if interactive:
            print("Multiple matches for '%s':" % q)
            for i, pid in enumerate(cands, 1):
                print("  %d. %s" % (i, load(pid)["name"]))
            r = prompt("Pick number", "")
            if r and r.isdigit() and 1 <= int(r) <= len(cands):
                return cands[int(r) - 1]
        else:
            print("Ambiguous: multiple matches for '%s': %s" % (q, ", ".join(cands)))
        return None
    print("No profile found for '%s'." % q)
    return None


def choose_profile(label="Choose profile"):
    rows = numbered_profiles()
    if not rows:
        print("No profiles in database yet.")
        return None
    for n, pid, name in rows:
        print("  %d. %s" % (n, name))
    r = prompt(label + " (number or name)")
    if not r:
        return None
    if r.isdigit():
        n = int(r)
        if 1 <= n <= len(rows):
            return rows[n - 1][1]
        print("Invalid number.")
        return None
    return resolve_profile(r, True)


# --------------------------------------------------------------------------
# Category helpers (for show / display / removal)
# --------------------------------------------------------------------------
def link_target_name(tid):
    try:
        return load(tid)["name"]
    except Exception:
        return tid


def photo_ts(path):
    base = os.path.splitext(os.path.basename(path))[0]
    m = re.search(r"-(\d+)$", base)
    if m:
        try:
            return datetime.datetime.fromtimestamp(int(m.group(1)) / 1000).strftime("%Y-%m-%d %H:%M")
        except Exception:
            return ""
    return ""


def category_items(p, cat):
    if cat == "name":
        return [p["name"]] if p["name"] else []
    if cat == "aliases":
        return list(p.get("aliases", []))
    if cat in ("phone", "email", "address", "occupation", "employer", "dob",
               "status", "threat", "relation", "notes"):
        return [p.get(cat)] if p.get(cat) else []
    if cat == "tags":
        return list(p.get("tags", []))
    if cat == "records":
        return ["[%s] %s - %s" % (r.get("type", "other"), r.get("ts", ""), r.get("content", ""))
                for r in p.get("records", [])]
    if cat == "links":
        return ["%s (%s)" % (link_target_name(lk.get("target", "")), lk.get("type", "unknown"))
                for lk in p.get("links", [])]
    if cat == "photos":
        return ["%s [%s]" % (os.path.basename(x), photo_ts(x)) for x in p.get("photos", [])]
    if cat == "locations":
        return ["%s (%s, %s) %s" % (x.get("place") or "unknown", x.get("lat", ""), x.get("lon", ""), x.get("ts", ""))
                for x in p.get("locations", [])]
    if cat == "reminders":
        return ["%s %s %s" % ("[x]" if x.get("done") else "[ ]", x.get("due", ""), x.get("content", ""))
                for x in p.get("reminders", [])]
    return []


def display_profile(p):
    print("\n%s" % p["name"])
    print("=" * len(p["name"]))
    print("  ID: %s" % p["id"])
    rows = [
        ("Aliases", ", ".join(p["aliases"]) if p["aliases"] else ""),
        ("Phone", p["phone"]), ("Email", p["email"]), ("Address", p["address"]),
        ("Occupation", p["occupation"]), ("Employer", p["employer"]),
        ("DOB", p["dob"]), ("Status", p["status"]), ("Threat", p["threat"]),
        ("Relation", p["relation"]),
        ("Tags", ", ".join(p["tags"]) if p["tags"] else ""),
    ]
    for k, v in rows:
        if v:
            print("  %s: %s" % (k, v))
    if p["notes"]:
        print("  Notes: %s" % p["notes"])
    print("  Created: %s   Updated: %s" % (p["created_at"], p["updated_at"]))
    for cat, label in (("records", "Records"), ("links", "Links"), ("photos", "Photos"),
                       ("locations", "Locations"), ("reminders", "Reminders")):
        items = category_items(p, cat)
        if not items:
            continue
        print("  %s:" % label)
        for i, it in enumerate(items, 1):
            print("    %d. %s" % (i, it))


def cmd_show_field(cat, pid, nums=None):
    p = load(pid)
    items = category_items(p, cat)
    print("\n%s - %s" % (p["name"], cat))
    if not items:
        print("  (empty)")
        return
    for i, it in enumerate(items, 1):
        if nums and i not in nums:
            continue
        print("  %d. %s" % (i, it))


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------
def norm_field(w):
    if not w:
        return None
    return FIELD_ALIASES.get(w.lower().replace("_", "-")) or FIELD_ALIASES.get(w.lower())


def norm_cat(w):
    if not w:
        return None
    wl = w.lower().replace("_", "-")
    if wl in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[wl]
    return CATEGORY_ALIASES.get(w.lower())


def norm_record_type(w):
    if not w:
        return None
    return RECORD_ALIASES.get(w.lower().replace("_", "-")) or RECORD_ALIASES.get(w.lower())


def norm_relation(w):
    if not w:
        return None
    wl = w.lower().replace("_", "-")
    return RELATION_ALIASES.get(wl) or RELATION_ALIASES.get(w.lower())


def parse_nums(text):
    nums = []
    for part in re.split(r"[,/\s]+", (text or "").strip()):
        if part.isdigit():
            nums.append(int(part))
    return nums


def _is_field_token(t):
    if re.match(r"^--[\w-]+", t):
        return True
    m = re.match(r"^([\w-]+):(.*)$", t)
    if m and (norm_field(m.group(1)) or norm_cat(m.group(1))):
        return True
    return False


def parse_kv(tokens):
    """Parse 'phone: X', '--phone X', 'phone=X'. Returns (fields, positionals)."""
    fields = {}
    positionals = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        m = re.match(r"^--([\w-]+)(?:=(.*))?$", t)
        if m:
            key = m.group(1)
            f = norm_field(key) or norm_cat(key) or key.lower()
            if m.group(2) is not None:
                fields[f] = m.group(2)
                i += 1
                continue
            vals = []
            while i + 1 < len(tokens) and not _is_field_token(tokens[i + 1]):
                vals.append(tokens[i + 1])
                i += 1
            fields[f] = " ".join(vals).strip() if vals else True
            i += 1
            continue
        m2 = re.match(r"^([\w-]+):(.*)$", t)
        if m2:
            key, inline = m2.group(1), m2.group(2)
            f = norm_field(key) or norm_cat(key)
            if f:
                if inline:
                    fields[f] = inline
                    i += 1
                    continue
                vals = []
                while i + 1 < len(tokens) and not _is_field_token(tokens[i + 1]):
                    vals.append(tokens[i + 1])
                    i += 1
                fields[f] = " ".join(vals).strip()
                i += 1
                continue
        m3 = re.match(r"^([\w-]+)=(.*)$", t)
        if m3:
            f = norm_field(m3.group(1)) or norm_cat(m3.group(1))
            if f:
                fields[f] = m3.group(2)
                i += 1
                continue
        positionals.append(t)
        i += 1
    return fields, positionals


def parse_flags(tokens):
    """Generic '--key value' parser. Returns (flags dict, positionals)."""
    flags = {}
    pos = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        m = re.match(r"^--([\w-]+)=(.*)$", t)
        if m:
            flags[m.group(1).lower()] = m.group(2)
            i += 1
            continue
        m = re.match(r"^--?([\w-]+)$", t)
        if m:
            key = m.group(1).lower()
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            if nxt and (not nxt.startswith("-") or re.match(r"^-\d", nxt)):
                flags[key] = nxt
                i += 2
            else:
                flags[key] = True
                i += 1
            continue
        pos.append(t)
        i += 1
    return flags, pos


def split_commands(text):
    parts = re.split(r"\s*;\s*|\s+(?:then|and)\s+", text.strip())
    return [p.strip() for p in parts if p.strip()]


# --------------------------------------------------------------------------
# CRUD commands
# --------------------------------------------------------------------------
def cmd_list(status=None, tag=None):
    rows = numbered_profiles(status=status, tag=tag)
    if not rows:
        print("No profiles.")
        return
    for n, pid, name in rows:
        print("  %d. %s" % (n, name))
    print("Total: %d profile(s)." % len(rows))


def cmd_show(pid):
    display_profile(load(pid))


def cmd_search(q):
    q = (q or "").lower()
    if not q:
        print("Usage: search <query>")
        return
    hits = 0
    for pid in list_pids():
        p = load(pid)
        blob = json.dumps(p, ensure_ascii=False).lower()
        if q in blob:
            hits += 1
            print("\n%s  [%s]" % (p["name"], pid))
            for r in p.get("records", []):
                if q in r.get("content", "").lower():
                    print("    rec: %s" % r["content"])
    if not hits:
        print("No matches for '%s'." % q)
    else:
        print("\n%d profile(s) matched." % hits)


def apply_edit(pid, field, value, interactive=True):
    if not field:
        if interactive:
            field = prompt("Field to edit")
        if not field:
            return
    f = norm_field(field)
    if not f:
        print("Unknown field '%s'." % field)
        return
    if value is None or value == "":
        if interactive:
            value = prompt("New %s" % f)
        if not value:
            return
    p = load(pid)
    set_field(p, f, value)
    save(pid, p)
    print("%s.%s = %s" % (p["name"], f, value))


def cmd_delete_smart(toks, ctx, interactive=True):
    if not toks:
        if ctx:
            delete_profile(ctx, interactive)
            return "menu"
        if interactive:
            cmd_list()
            r = prompt("Delete profile (number or name) [Enter to cancel]")
            if r:
                pid = resolve_profile(r, True)
                if pid:
                    delete_profile(pid, True)
        else:
            print("Usage: delete <profile>")
        return "menu"
    w0 = toks[0].lower()
    cat = norm_cat(w0)
    if cat in ("records", "photos", "locations", "reminders", "links"):
        pid = ctx
        nums_text = " ".join(toks[1:])
        if ctx is None and len(toks) >= 2 and not re.fullmatch(r"[\d,\s/]+", toks[1]):
            pid = resolve_profile(toks[1], interactive)
            nums_text = " ".join(toks[2:])
        elif ctx is None:
            pid = choose_profile("Remove from") if interactive else None
            nums_text = " ".join(toks[1:])
        if not pid:
            if not interactive:
                print("Specify a profile: remove %s <name> <nums>" % cat)
            return "menu"
        nums = parse_nums(nums_text)
        if not nums and interactive:
            items = category_items(load(pid), cat)
            if not items:
                print("Nothing to remove.")
                return "menu"
            for i, it in enumerate(items, 1):
                print("  %d. %s" % (i, it))
            nums = parse_nums(prompt("Numbers to remove (comma-sep)") or "")
        if nums:
            remove_items(pid, cat, nums)
        return "menu"
    pid = resolve_profile(" ".join(toks), interactive)
    if pid:
        delete_profile(pid, interactive)
    return "menu"


def remove_items(pid, cat, nums):
    p = load(pid)
    key = cat
    items = p.get(key, [])
    sel = [items[i - 1] for i in nums if 1 <= i <= len(items)]
    if not sel:
        print("Nothing to remove.")
        return
    for i in sorted(set(nums), reverse=True):
        if 1 <= i <= len(items):
            items.pop(i - 1)
    if cat == "photos":
        for it in sel:
            if os.path.exists(it):
                try:
                    os.remove(it)
                except OSError:
                    pass
    p[key] = items
    save(pid, p)
    print("Removed %d %s from %s." % (len(sel), cat, p["name"]))


def delete_profile(pid, interactive=True):
    p = load(pid)
    if interactive and not confirm("Delete profile '%s' (all data)?" % p["name"]):
        print("Cancelled.")
        return
    path = os.path.join(PROFILES_DIR, pid + ".json")
    try:
        os.remove(path)
        print("Deleted profile '%s'." % p["name"])
    except OSError as e:
        print("Error: %s" % e)


# --------------------------------------------------------------------------
# Records, links, graph
# --------------------------------------------------------------------------
def add_record(pid, rtype, content):
    rtype = norm_record_type(rtype) or "other"
    p = load(pid)
    p["records"].append({
        "id": "r%d" % int(time.time() * 1000),
        "ts": now_iso(),
        "type": rtype,
        "content": content,
    })
    save(pid, p)
    return p


def link_profiles(a, b, rtype):
    pa, pb = load(a), load(b)
    if not any(l.get("target") == b for l in pa.get("links", [])):
        pa["links"].append({"target": b, "type": rtype, "ts": now_iso()})
    if not any(l.get("target") == a for l in pb.get("links", [])):
        pb["links"].append({"target": a, "type": rtype, "ts": now_iso()})
    save(a, pa)
    save(b, pb)
    print("Linked %s <-> %s (%s)" % (pa["name"], pb["name"], rtype))


def cmd_graph():
    pids = list_pids()
    if not pids:
        print("No profiles.")
        return
    shown = 0
    for pid in pids:
        p = load(pid)
        for lk in p.get("links", []):
            print("%s --[%s]--> %s" % (p["name"], lk.get("type", "unknown"), link_target_name(lk.get("target"))))
            shown += 1
    if not shown:
        print("No links yet.")


# --------------------------------------------------------------------------
# Photos
# --------------------------------------------------------------------------
def cmd_photo_add(pid, path):
    if not os.path.exists(path):
        print("File not found: %s" % path)
        return
    ext = os.path.splitext(path)[1] or ".jpg"
    dst = os.path.join(PHOTOS_DIR, "%s-%d%s" % (pid, int(time.time() * 1000), ext))
    ensure_dirs()
    shutil.copy2(path, dst)
    p = load(pid)
    p["photos"].append(dst)
    save(pid, p)
    add_record(pid, "file", "Photo added: %s" % os.path.basename(dst))
    print("Photo saved: %s" % dst)


def cmd_photo_camera(pid):
    cam = shutil.which("termux-camera-photo")
    if not cam:
        print("termux-camera-photo not found. Install termux-api package + Termux:API app.")
        return
    dst = os.path.join(PHOTOS_DIR, "%s-%d.jpg" % (pid, int(time.time() * 1000)))
    ensure_dirs()
    try:
        subprocess.run([cam, dst], check=True, timeout=30)
    except Exception as e:
        print("Camera failed: %s" % e)
        return
    if os.path.exists(dst):
        p = load(pid)
        p["photos"].append(dst)
        save(pid, p)
        add_record(pid, "file", "Photo captured: %s" % os.path.basename(dst))
        print("Photo captured: %s" % dst)
    else:
        print("Camera produced no image.")


def cmd_view(pid, nums=None):
    p = load(pid)
    photos = p.get("photos", [])
    if not photos:
        print("No photos for %s." % p["name"])
        return
    sel = [photos[i - 1] for i in nums if 1 <= i <= len(photos)] if nums else photos
    if not sel:
        print("No photos match those numbers.")
        return
    for f in sel:
        print("Opening %s" % os.path.basename(f))
        open_file(f)


# --------------------------------------------------------------------------
# Locations & GPS
# --------------------------------------------------------------------------
def maps_link(lat, lon):
    return "https://www.google.com/maps?q=%s,%s" % (lat, lon)


def http_get_json(url, timeout=15):
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ProfilerOSINT/1.0 (lawful public sources only)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None


def reverse_geocode(lat, lon):
    url = "https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=%s&lon=%s" % (lat, lon)
    data = http_get_json(url, timeout=15)
    if data and data.get("display_name"):
        return data["display_name"]
    return None


def try_termux_location(provider, request="once"):
    try:
        out = subprocess.run(["termux-location", "-r", request, "-p", provider],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and out.stdout.strip():
            data = json.loads(out.stdout)
            if data.get("latitude") is not None and data.get("longitude") is not None:
                return {"lat": data["latitude"], "lon": data["longitude"],
                        "accuracy": data.get("accuracy"), "provider": provider}
    except Exception:
        pass
    return None


def ip_location():
    data = http_get_json("http://ip-api.com/json/", timeout=10)
    if data and data.get("status") == "success":
        return data
    return None


def add_location(pid, lat, lon, place=""):
    p = load(pid)
    link = maps_link(lat, lon)
    entry = {"ts": now_iso(), "lat": str(lat), "lon": str(lon),
             "place": place or "", "map": link}
    p["locations"].append(entry)
    save(pid, p)
    add_record(pid, "location", "Location logged: %s (%s, %s) %s" % (place or "unknown", lat, lon, link))
    print("Location logged: %s (%s, %s)" % (place or "unknown", lat, lon))
    print("Map: %s" % link)


def gps_location(pid, manual=True):
    loc = None
    cached = try_termux_location("passive", request="last")
    if cached:
        loc = cached
        print("[last] cached position acquired.")
    else:
        for prov in ("gps", "network", "passive"):
            loc = try_termux_location(prov)
            if loc:
                print("[%s] position acquired." % prov)
                break
    if not loc:
        iloc = ip_location()
        if iloc:
            loc = {"lat": iloc.get("lat"), "lon": iloc.get("lon"),
                   "place": iloc.get("city"), "provider": "ip"}
            print("[ip] position from ip-api.com (%s) - ISP location, not device GPS." % (iloc.get("city") or ""))
            print("      For real GPS: grant Termux location permission (Settings > Apps > Termux > Permissions).")
        elif manual:
            print("GPS / network / IP all unavailable.")
            lat = prompt("Latitude (Enter to cancel)")
            lon = prompt("Longitude")
            if not lat or not lon or is_cancel(lat) or is_cancel(lon):
                return
            loc = {"lat": lat, "lon": lon, "place": "", "provider": "manual"}
    if not loc:
        print("No position obtained.")
        return
    lat, lon = loc["lat"], loc["lon"]
    place = loc.get("place") or ""
    if not place:
        place = reverse_geocode(lat, lon) or ""
        if not place and manual:
            place = prompt("Place name (Enter to skip)")
    add_location(pid, lat, lon, place or "")


# --------------------------------------------------------------------------
# Reminders
# --------------------------------------------------------------------------
def cmd_remind(pid, content="", due=""):
    if not content:
        content = prompt("Reminder content")
        if not content:
            return
    if not due:
        due = prompt("Due date (YYYY-MM-DD) [Enter for today]") or datetime.date.today().isoformat()
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", due):
        print("Invalid date '%s' (expected YYYY-MM-DD)." % due)
        return
    p = load(pid)
    p["reminders"].append({"ts": now_iso(), "due": due, "content": content, "done": False})
    save(pid, p)
    print("Reminder set for %s: %s" % (load(pid)["name"], content))


def cmd_reminders():
    today = datetime.date.today().isoformat()
    rows = []
    for pid in list_pids():
        p = load(pid)
        for r in p.get("reminders", []):
            if not r.get("done"):
                rows.append((r.get("due", ""), pid, r.get("content", "")))
    if not rows:
        print("No upcoming reminders.")
        return
    for due, pid, content in sorted(rows):
        flag = ""
        if due == today:
            flag = "  <-- TODAY"
        elif due and due < today:
            flag = "  <-- OVERDUE"
        print("%s  %-30s %s%s" % (due, content, load(pid)["name"], flag))


# --------------------------------------------------------------------------
# Backup / export / import
# --------------------------------------------------------------------------
def cmd_backup():
    ensure_dirs()
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(BACKUP_DIR, "profiles-" + ts)
    shutil.copytree(PROFILES_DIR, dest)
    print("Backup saved: %s" % dest)


def cmd_export(fmt="json", out_path=None):
    pids = list_pids()
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        header = ["id", "name", "aliases", "phone", "email", "address", "occupation",
                  "employer", "dob", "status", "threat", "relation", "tags", "notes",
                  "records", "links", "photos", "locations", "reminders",
                  "created_at", "updated_at"]
        w.writerow(header)
        for pid in pids:
            p = load(pid)
            row = [p.get("id"), p.get("name"), ";".join(p.get("aliases", [])),
                   p.get("phone"), p.get("email"), p.get("address"),
                   p.get("occupation"), p.get("employer"), p.get("dob"),
                   p.get("status"), p.get("threat"), p.get("relation"),
                   ";".join(p.get("tags", [])), p.get("notes"),
                   len(p.get("records", [])), len(p.get("links", [])),
                   len(p.get("photos", [])), len(p.get("locations", [])),
                   len(p.get("reminders", [])), p.get("created_at"), p.get("updated_at")]
            w.writerow([str(x) if x is not None else "" for x in row])
        dest = out_path or os.path.join(BASE, "profiles-export.csv")
        ensure_dirs()
        with open(dest, "w", newline="", encoding="utf-8") as f:
            f.write("\ufeff" + buf.getvalue())
    else:
        data = {"exported_at": now_iso(), "count": len(pids),
                "profiles": [load(pid) for pid in pids]}
        dest = out_path or EXPORT_PATH
        ensure_dirs()
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    print("Exported %d profile(s) to %s" % (len(pids), dest))


def merge_profiles(cur, raw):
    for k in ("aliases", "tags"):
        for v in raw.get(k, []):
            if v not in cur.get(k, []):
                cur[k].append(v)
    for k in ("name", "phone", "email", "address", "occupation", "employer",
              "dob", "status", "threat", "relation", "notes"):
        if raw.get(k) and not cur.get(k):
            cur[k] = raw[k]
    for k, key in (("records", "id"), ("links", "target"), ("locations", "ts"),
                   ("reminders", "ts"), ("photos", None)):
        for item in raw.get(k, []):
            if key is None:
                if item not in cur.get(k, []):
                    cur[k].append(item)
            else:
                if not any(x.get(key) == item.get(key) for x in cur.get(k, [])):
                    cur[k].append(item)
    cur["updated_at"] = now_iso()


def cmd_import(path, interactive=True):
    if not os.path.exists(path):
        print("File not found: %s" % path)
        return
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "profiles" in data:
        profs = data["profiles"]
    elif isinstance(data, list):
        profs = data
    elif isinstance(data, dict):
        profs = [data]
    else:
        print("Unrecognized import format.")
        return
    created = updated = 0
    for raw in profs:
        if not isinstance(raw, dict):
            continue
        ensure_shape(raw)
        pid = raw.get("id") or unique_id(raw.get("name") or "profile")
        raw["id"] = pid
        if os.path.exists(os.path.join(PROFILES_DIR, pid + ".json")):
            cur = load(pid)
            merge_profiles(cur, raw)
            save(pid, cur)
            updated += 1
        else:
            save(pid, raw)
            created += 1
    print("Import done: %d created, %d updated." % (created, updated))


def cmd_stats():
    pids = list_pids()
    n_rec = n_lnk = n_ph = n_loc = n_rem = 0
    for pid in pids:
        p = load(pid)
        n_rec += len(p.get("records", []))
        n_lnk += len(p.get("links", []))
        n_ph += len(p.get("photos", []))
        n_loc += len(p.get("locations", []))
        n_rem += len(p.get("reminders", []))
    prof_size = sum(os.path.getsize(os.path.join(PROFILES_DIR, f))
                    for f in os.listdir(PROFILES_DIR)) if os.path.isdir(PROFILES_DIR) else 0
    photo_size = sum(os.path.getsize(os.path.join(PHOTOS_DIR, f))
                     for f in os.listdir(PHOTOS_DIR)) if os.path.isdir(PHOTOS_DIR) else 0
    print("Profiles:        %d" % len(pids))
    print("Records:         %d" % n_rec)
    print("Links:           %d" % n_lnk)
    print("Photos:          %d" % n_ph)
    print("Locations:       %d" % n_loc)
    print("Reminders:       %d" % n_rem)
    print("Profiles size:   %.1f KB" % (prof_size / 1024.0))
    print("Photos size:     %.1f KB" % (photo_size / 1024.0))
    print("Encryption:      %s" % ("on" if _encryption_enabled() else "off"))


def cmd_encrypt(mode):
    ensure_dirs()
    get_key()
    current = _encryption_enabled()
    new = (mode == "on")
    if current == new:
        print("Encryption is already %s." % ("on" if current else "off"))
        return
    pids = list_pids()
    set_config(encryption=new)
    for pid in pids:
        try:
            data = load(pid)
            save(pid, data)
        except Exception as e:
            print("Skipped %s: %s" % (pid, e))
    print("Encryption %s. Re-encoded %d profile(s)." % ("on" if new else "off", len(pids)))


def cmd_sync(mode=None, interactive=True):
    if not shutil.which("rclone"):
        print("rclone is not installed. Install with:  pkg install rclone")
        print("Then configure:  rclone config  (remote 'gdrive', folder 'profiler').")
        return
    if mode not in ("push", "pull", "check"):
        if interactive:
            mode = prompt("Sync mode (push/pull/check)")
        if mode not in ("push", "pull", "check"):
            print("Usage: sync push|pull|check")
            return
    local = PROFILES_DIR
    remote = GDRIVE_REMOTE + "/profiles"
    if mode == "push":
        subprocess.run(["rclone", "sync", local, remote])
        print("Pushed to Google Drive.")
    elif mode == "pull":
        subprocess.run(["rclone", "sync", remote, local])
        print("Pulled from Google Drive.")
    elif mode == "check":
        subprocess.run(["rclone", "lsl", GDRIVE_REMOTE])


# --------------------------------------------------------------------------
# OSINT (lawful public sources only — no keys required except HIBP, optional)
# --------------------------------------------------------------------------
OSINT_UA = "ProfilerOSINT/1.0 (personal record-keeping tool; lawful public sources only)"

SOCIAL_PLATFORMS = {
    "GitHub": "https://github.com/%s",
    "Twitter/X": "https://x.com/%s",
    "Reddit": "https://www.reddit.com/user/%s",
    "Instagram": "https://www.instagram.com/%s",
    "Facebook": "https://www.facebook.com/%s",
    "LinkedIn": "https://www.linkedin.com/in/%s",
    "YouTube": "https://www.youtube.com/@%s",
    "TikTok": "https://www.tiktok.com/@%s",
    "Pinterest": "https://www.pinterest.com/%s",
    "Telegram": "https://t.me/%s",
    "Twitch": "https://www.twitch.tv/%s",
    "Steam": "https://steamcommunity.com/id/%s",
    "Spotify": "https://open.spotify.com/user/%s",
    "Mastodon": "https://mastodon.social/@%s",
    "SoundCloud": "https://soundcloud.com/%s",
    "GitLab": "https://gitlab.com/%s",
    "HackerNews": "https://news.ycombinator.com/user?id=%s",
    "Keybase": "https://keybase.io/%s",
    "Flickr": "https://www.flickr.com/people/%s/",
    "VK": "https://vk.com/%s",
}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_get(url, timeout=12):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": OSINT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        return None


def http_status(url, timeout=7):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": OSINT_UA})
        opener = urllib.request.build_opener(_NoRedirectHandler)
        with opener.open(req, timeout=timeout) as r:
            return r.getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def classify_target(t):
    t = t.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):
        return "ip"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", t):
        return "email"
    return "domain"


def clean_username(s):
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9_.-]", "", s).strip("._-")
    return s if 2 <= len(s) <= 30 else ""


def extract_domains(p):
    doms = []
    for e in (p.get("email") or "").split(","):
        em = e.strip()
        if "@" in em:
            doms.append(em.split("@")[1].lower())
    blob = " ".join([p.get("employer") or "", p.get("occupation") or "", p.get("notes") or ""])
    for m in re.findall(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", blob.lower()):
        doms.append(m)
    seen = set()
    out = []
    for d in doms:
        if d not in seen and "." in d:
            seen.add(d)
            out.append(d)
    return out


def profile_targets(p):
    usernames, emails, phones, names = [], [], [], []
    for nm in [p.get("name") or ""] + list(p.get("aliases") or []):
        nm = nm.strip()
        if nm and nm not in names:
            names.append(nm)
    for em in (p.get("email") or "").split(","):
        em = em.strip()
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", em) and em not in emails:
            emails.append(em)
            cu = clean_username(em.split("@")[0])
            if cu and cu not in usernames:
                usernames.append(cu)
    for ph in (p.get("phone") or "").split(","):
        ph = ph.strip()
        if ph and ph not in phones:
            phones.append(ph)
    for a in p.get("aliases") or []:
        cu = clean_username(a)
        if cu and cu not in usernames:
            usernames.append(cu)
    return {
        "usernames": usernames[:10],
        "emails": emails,
        "phones": phones,
        "domains": extract_domains(p),
        "names": names[:3],
    }


def osint_username(username):
    lines = []
    for platform, tpl in SOCIAL_PLATFORMS.items():
        url = tpl % username
        st = http_status(url, timeout=6)
        if st == 200:
            lines.append("[+] %s: %s" % (platform, url))
        elif st in (301, 302, 303, 307, 308):
            lines.append("[~] %s: %s (redirect - likely present)" % (platform, url))
        elif st in (403, 429):
            lines.append("[?] %s: %s (rate-limited/blocked - unverified)" % (platform, url))
    return [("Username recon: %s" % username, lines or ["(no public profiles found)"])]


def osint_web(name):
    q = urllib.parse.quote(name)
    url = "https://api.duckduckgo.com/?q=%s&format=json&no_html=1&no_redirect=1" % q
    data = http_get_json(url, timeout=12)
    lines = []
    if data:
        head = data.get("Heading") or ""
        abstract = data.get("AbstractText") or ""
        aurl = data.get("AbstractURL") or ""
        if head and abstract:
            lines.append("%s: %s  (%s)" % (head, abstract[:300], aurl))
        for r in (data.get("RelatedTopics") or [])[:6]:
            if isinstance(r, dict) and r.get("Text"):
                lines.append(r["Text"][:220])
    return [("Web presence: %s" % name, lines or ["(no public abstract found)"])]


def osint_wikipedia(name):
    q = urllib.parse.quote(name)
    url = ("https://en.wikipedia.org/w/api.php?action=query&list=search"
           "&srsearch=%s&format=json&srlimit=5" % q)
    data = http_get_json(url, timeout=12)
    if not data:
        return [("Wikipedia", ["search failed"])]
    hits = (data.get("query") or {}).get("search") or []
    lines = []
    for h in hits[:5]:
        snippet = re.sub(r"<[^>]+>", "", h.get("snippet") or "")
        title = h.get("title") or ""
        page = "https://en.wikipedia.org/wiki/%s" % urllib.parse.quote(title.replace(" ", "_"))
        lines.append("%s - %s  %s" % (title, snippet[:200], page))
    return [("Wikipedia", lines or ["(no results)"])]


def osint_news(name):
    q = urllib.parse.quote(name)
    url = ("https://news.google.com/rss/search?q=%s&hl=en&gl=US&ceid=US:en" % q)
    text = http_get(url, timeout=15)
    if not text:
        return [("News headlines", ["search failed"])]
    items = re.findall(r"<item>.*?</item>", text, re.S)
    lines = []
    for it in items[:10]:
        t = re.search(r"<title>(.*?)</title>", it, re.S)
        l = re.search(r"<link>(.*?)</link>", it, re.S)
        title = re.sub(r"<!\[CDATA\[|\]\]>", "", t.group(1)).strip() if t else ""
        link = l.group(1).strip() if l else ""
        if title:
            lines.append("%s  %s" % (title, link))
    return [("News headlines (Google News)", lines or ["(none found)"])]


def _hibp_key():
    key = os.environ.get("HIBP_API_KEY") or ""
    if not key:
        try:
            with open(os.path.join(BASE, "hibp.key")) as f:
                key = f.read().strip()
        except Exception:
            key = ""
    return key


def osint_hibp(email):
    key = _hibp_key()
    if not key:
        return [("Breach check (HIBP)",
                 ["No API key. Put a free key in HIBP_API_KEY or ~/.profiler/hibp.key to enable."])]
    url = "https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=true" % urllib.parse.quote(email)
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": OSINT_UA, "hibp-api-key": key, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.getcode() == 200:
                data = json.loads(r.read().decode("utf-8", "replace"))
                names = sorted(set(b.get("Name", "") for b in data))
                return [("Breach check (HIBP)",
                         ["PWNED in %d breach(es): %s" % (len(names), ", ".join(names))])]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return [("Breach check (HIBP)", ["No known public breaches for this email."])]
        return [("Breach check (HIBP)", ["API error %s" % e.code])]
    except Exception as ex:
        return [("Breach check (HIBP)", ["lookup failed: %s" % ex])]
    return [("Breach check (HIBP)", ["unknown result"])]


def osint_phone(phone):
    digits = re.sub(r"[^\d]", "", phone)
    lines = ["Input: %s" % phone]
    if len(digits) == 10 and digits.startswith("0"):
        lines.append("10-digit national number detected.")
    elif len(digits) == 11 and digits.startswith("01"):
        lines.append("Bangladesh mobile format detected (national 11-digit).")
    elif len(digits) == 13 and digits.startswith("880"):
        lines.append("Bangladesh international format (+880 ...).")
    else:
        lines.append("Format not recognized (digits: %d)." % len(digits))
    lines.append("Note: carrier/identity lookup needs a keyed API (numverify etc.) - skipped.")
    return [("Phone analysis", lines)]



def osint_ip(ip):
    data = http_get_json("http://ip-api.com/json/" + ip)
    if not data or data.get("status") != "success":
        return [("IP lookup", ["lookup failed for %s" % ip])]
    lines = [
        "IP: %s" % data.get("query"),
        "Country: %s (%s)" % (data.get("country"), data.get("countryCode")),
        "Region: %s" % data.get("regionName"),
        "City: %s" % data.get("city"),
        "ISP: %s" % data.get("isp"),
        "Org: %s" % data.get("org"),
        "AS: %s" % data.get("as"),
        "Coords: %s, %s" % (data.get("lat"), data.get("lon")),
        "Hosting: %s" % data.get("hosting"),
        "Timezone: %s" % data.get("timezone"),
    ]
    return [("IP intelligence", lines)]


def osint_domain(domain):
    res = []
    try:
        host, aliases, addrs = socket.gethostbyname_ex(domain)
        res.append(("DNS resolution", [
            "Hostname: %s" % host,
            "Aliases: %s" % (", ".join(aliases) or "-"),
            "Addresses: %s" % (", ".join(addrs) or "-"),
        ]))
    except Exception as e:
        res.append(("DNS resolution", ["failed: %s" % e]))
    rdap = http_get_json("https://rdap.org/domain/" + domain, timeout=20)
    if rdap:
        lines = []
        for e in rdap.get("entities", []):
            v = e.get("vcardArray")
            if v and len(v) > 1:
                for item in v[1]:
                    if isinstance(item, (list, tuple)) and len(item) > 3 and item[0] == "fn":
                        lines.append("Entity: %s" % item[3])
        for ev in rdap.get("events", []):
            lines.append("%s: %s" % (ev.get("eventAction", "event"), ev.get("eventDate", "")))
        if not lines:
            lines.append("(no public entity details)")
        res.append(("RDAP registration", lines))
    else:
        res.append(("RDAP registration", ["lookup failed"]))
    return res


def osint_subdomains(domain):
    url = "https://crt.sh/?q=%%25.%s&output=json" % domain
    data = http_get_json(url, timeout=10)
    if not data or not isinstance(data, list):
        return [("Subdomains (crt.sh)", ["lookup failed"])]
    subs = set()
    for e in data:
        for part in (e.get("name_value") or "").split("\n"):
            part = part.strip()
            if part and "*" not in part:
                subs.add(part)
    subs = sorted(subs)
    out = subs[:50]
    if len(subs) > 50:
        out.append("... (%d total)" % len(subs))
    return [("Subdomains (crt.sh)", out or ["(none found)"])]


def osint_email(email):
    m = re.match(r"^([^@\s]+)@([^@\s]+)$", email)
    if not m:
        return [("Email validation", ["invalid email format"])]
    dom = m.group(2)
    lines = ["Format: valid", "Domain: %s" % dom]
    try:
        host, aliases, addrs = socket.gethostbyname_ex(dom)
        lines.append("Domain resolves: %s" % (", ".join(addrs) or "-"))
    except Exception as e:
        lines.append("Domain resolution failed: %s" % e)
    return [("Email intelligence", lines)]


def run_osint_report(pid, results):
    p = load(pid)
    for title, lines in results:
        print("\n[%s]" % title)
        for ln in lines:
            print("  %s" % ln)
        if lines:
            body = "[%s]\n%s" % (title, "\n".join("- %s" % ln for ln in lines))
            add_record(pid, "osint", body)
    print("\nResults appended to %s timeline." % p["name"])


def cmd_osint(pid, target=None, interactive=True):
    p = load(pid)
    if target:
        kind = classify_target(target)
        print("Running OSINT for %s (%s)..." % (target, kind))
        if kind == "ip":
            results = osint_ip(target)
        elif kind == "email":
            results = osint_email(target)
        else:
            results = osint_domain(target) + osint_subdomains(target)
        run_osint_report(pid, results)
        return

    print("Auto-enriching %s from profile data (public sources only)..." % p["name"])
    tgts = profile_targets(p)
    results = []
    seen_usernames = set()
    for u in tgts["usernames"]:
        results += osint_username(u)
        seen_usernames.add(u)
    for nm in tgts["names"]:
        results += osint_web(nm)
        results += osint_wikipedia(nm)
        results += osint_news(nm)
    for em in tgts["emails"]:
        results += osint_email(em)
        results += osint_hibp(em)
    for ph in tgts["phones"]:
        results += osint_phone(ph)
    for dm in tgts["domains"]:
        results += osint_domain(dm)
        results += osint_subdomains(dm)
    # --- Cascade: also enrich on any discovered usernames as new targets ---
    for u in sorted(seen_usernames):
        results += osint_web(u)
        results += osint_wikipedia(u)
        results += osint_news(u)
    if not results:
        print("Nothing to enrich - add some data to this profile first (name, aliases, email, phone).")
        return
    run_osint_report(pid, results)


# --------------------------------------------------------------------------


def html_to_text(html):
    html = re.sub(r"<script.*?</script>", " ", html, flags=re.S | re.I)
    html = re.sub(r"<style.*?</style>", " ", html, flags=re.S | re.I)
    html = re.sub(r"<[^>]+>", " ", html)
    for ent, ch in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                    ("&#39;", "'"), ("&quot;", '"'), ("&hellip;", "..."), ("&mdash;", "-")):
        html = html.replace(ent, ch)
    text = re.sub(r"[ \t]+", " ", html)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


BROWSER_UA = ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")


def http_get_bytes(url, timeout=15, ua=None):
    req = urllib.request.Request(
        url, headers={"User-Agent": ua or BROWSER_UA,
                      "Accept-Encoding": "gzip, deflate",
                      "Accept": "text/html,application/xhtml+xml,application/json,*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        enc = (r.headers.get("Content-Encoding") or "").lower()
        if enc == "gzip":
            data = gzip.decompress(data)
        elif enc == "deflate":
            try:
                data = zlib.decompress(data)
            except Exception:
                pass
        charset = r.headers.get_content_charset() or "utf-8"
        return data, charset


def http_get_text(url, timeout=15, ua=None):
    try:
        data, charset = http_get_bytes(url, timeout, ua)
        return data.decode(charset, "replace")
    except Exception:
        return None


def web_search(query, n=5):
    q = urllib.parse.quote(query)
    results = []
    patterns = [
        ("https://html.duckduckgo.com/html/?q=%s" % q,
         r'class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>'),
        ("https://html.duckduckgo.com/html/?q=%s" % q,
         r'href="([^"]+)"[^>]*class="result__a"[^>]*>(.*?)</a>'),
        ("https://lite.duckduckgo.com/lite/?q=%s" % q,
         r'class="result-link"[^>]*href="([^"]+)"[^>]*>(.*?)</a>'),
    ]
    for url, pat in patterns:
        for attempt in range(2):
            html = http_get_text(url, timeout=12)
            if html:
                for m in re.finditer(pat, html, re.S):
                    href = urllib.parse.unquote(m.group(1))
                    title = re.sub(r"<[^>]+>", "", m.group(2)).strip()
                    if title and href.startswith("http"):
                        results.append((title, href))
                    if len(results) >= n:
                        break
            if results:
                break
            time.sleep(1.5)
        if results:
            break
    lines = ["%d. %s  %s" % (i, t, h) for i, (t, h) in enumerate(results[:n], 1)]
    if not lines:
        for _, alt in (osint_web(query) + osint_news(query)):
            for ln in alt:
                if ln and "(none" not in ln and "no public" not in ln:
                    lines.append(ln)
    return [("Web search: %s" % query, lines or ["(no results)"])]


def fetch_url(url, max_chars=1200):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    text = http_get_text(url, timeout=15)
    if not text:
        return [("Fetch", ["failed to fetch %s" % url])]
    return [("Fetch: %s" % url, [html_to_text(text)[:max_chars] or "(empty page)"])]


def fetch_url(url, max_chars=1200):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    html = http_get(url, timeout=15)
    if not html:
        return [("Fetch", ["failed to fetch %s" % url])]
    text = html_to_text(html)
    return [("Fetch: %s" % url, [text[:max_chars] or "(empty page)"])]


def cmd_websearch(q):
    q = (q or "").strip()
    if not q:
        print("Usage: websearch <query>")
        return
    for title, lines in web_search(q, 5):
        print("\n[%s]" % title)
        for ln in lines:
            print("  %s" % ln)


def cmd_fetch(url):
    url = (url or "").strip()
    if not url:
        print("Usage: fetch <url>")
        return
    for title, lines in fetch_url(url):
        print("\n[%s]" % title)
        for ln in lines:
            print("  %s" % ln)



    low = tool_cmd.strip().lower()
    m = re.match(r"^(websearch|searchweb|web)\s+(.+)$", low)
    if m:
        return web_search(m.group(2).strip(), 5)
    m = re.match(r"^(fetch|geturl)\s+(.+)$", low)
    if m:
        return fetch_url(m.group(2).strip())
    return None





def action_to_command(a):
    if not isinstance(a, dict):
        return None
    act = (a.get("action") or a.get("type") or "").lower()
    name = a.get("name") or a.get("profile") or a.get("query") or ""
    if act in ("create_profile", "add_profile", "new"):
        flds = " ".join("%s: %s" % (k.replace("_", "-"), v) for k, v in (a.get("fields") or {}).items())
        return "new %s %s" % (name, flds)
    if act in ("add_record", "record"):
        return "record %s --type %s --content %s" % (name, a.get("type") or "note", a.get("content") or "")
    if act in ("link", "connect"):
        return "link %s %s --type %s" % (name, a.get("target"), a.get("link_type") or "ally")
    if act in ("remind", "reminder"):
        return "remind %s --content %s --due %s" % (name, a.get("content") or "", a.get("due") or "")
    if act in ("locate", "location", "gps"):
        return "locate %s" % name
    if act in ("show", "view", "query"):
        if a.get("category"):
            return "show %s %s" % (a["category"], name)
        return "show %s" % name
    if act == "osint":
        return "osint %s" % name
    if act == "edit":
        return "edit %s.%s %s" % (name, a.get("field"), a.get("value") or "")
    if act in ("search", "find"):
        return "search %s" % (a.get("query") or name)
    return None


def extract_command(reply):
    if not reply:
        return None
    r = reply.strip().strip("`").strip()
    r = re.sub(r"^(ai|assistant|command|cmd)[:\s]*", "", r, flags=re.I)
    m = re.search(r"\{.*\}", r, re.S)
    if m:
        try:
            cmd = action_to_command(json.loads(m.group(0)))
            if cmd:
                return cmd
        except Exception:
            pass
    m = re.search(r"`([^`]+)`", r)
    if m:
        r = m.group(1).strip()
    toks = r.split()
    if toks and toks[0].lower() in COMMANDS:
        return r
    return None


def profile_names_in(text):
    low = text.lower()
    found = []
    for pid in list_pids():
        p = load(pid)
        matched = False
        for cand in [p["name"]] + list(p["aliases"]):
            idx = low.find(cand.lower())
            if idx != -1:
                found.append((idx, 2, p["name"]))
                matched = True
                break
        if matched:
            continue
        first = (p["name"].split()[0] if p["name"] else "").lower()
        if len(first) >= 2:
            m = re.search(r"\b%s'?s?\b" % re.escape(first), low)
            if m:
                found.append((m.start(), 1, p["name"]))
    found.sort()
    return [n for _, _, n in found]


def profile_name_in(text):
    names = profile_names_in(text)
    return names[0] if names else None


def extract_new_name(t):
    m = re.search(r"\b(?:profile\s+)?for\s+([A-Za-z][\w .'-]{1,40}?)(?:,|\s+(?:phone|email|works|job|tags|at)|\s*$)", t, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"\b(?:named|called)\s+([A-Za-z][\w .'-]{1,40}?)(?:,|\s+(?:phone|email|works|job|tags|at)|\s*$)", t, re.I)
    if m:
        return m.group(1).strip()
    m = re.search(r"\b(?:add|create|new)\s+(?:a\s+)?(?:profile\s+)?(?:for\s+)?([A-Za-z][\w .'-]{1,40}?)(?:,|\s+(?:phone|email|works|job|tags|at)|\s*$)", t, re.I)
    if m:
        return m.group(1).strip()
    return None


def understand_create(t):
    name = extract_new_name(t)
    if not name:
        return None
    fields = {}
    m = re.search(r"\bphone[:\s]*([0-9+\-()\s]{7,18})", t, re.I)
    if m:
        fields["phone"] = m.group(1).strip()
    m = re.search(r"\bemail[:\s]*([\w.+-]+@[\w.-]+\.\w+)", t, re.I)
    if m:
        fields["email"] = m.group(1).strip()
    m = re.search(r"\b(?:occupation|profession|job)[:\s]*([A-Za-z][^,.]*?)(?=,|$)", t, re.I)
    if m:
        fields["occupation"] = m.group(1).strip()
    m = re.search(r"\bworks?\s+as\s+([A-Za-z][^,.]*?)(?=,|$)", t, re.I)
    if m:
        fields["occupation"] = m.group(1).strip()
    m = re.search(r"\b(?:works?\s+(?:at|for)|employer|company)[:\s]*([A-Za-z0-9][\w &.'-]{1,40}?)(?=,|$)", t, re.I)
    if m:
        fields["employer"] = m.group(1).strip()
    m = re.search(r"\btags?[:\s]*([a-zA-Z0-9, _-]+)", t, re.I)
    if m:
        fields["tags"] = ",".join(x.strip() for x in m.group(1).split(",") if x.strip())
    m = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", t)
    if m:
        fields["dob"] = m.group(1)
    parts = ["%s: %s" % (k, v) for k, v in fields.items()]
    return "new %s %s" % (name, " ".join(parts))


def understand_reminder(t):
    name = profile_name_in(t) or extract_new_name(t)
    content = None
    m = re.search(r"\b(?:to|about)\s+(.+?)(?:\s*,\s*(?:tomorrow|today|next week)|(?:\s+on\s+\d{4}-\d{2}-\d{2})|$)", t, re.I)
    if m:
        content = m.group(1).strip()
    if not content:
        content = t.strip(" .")
    due = ""
    if re.search(r"\btomorrow\b", t):
        due = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
    elif re.search(r"\btoday\b", t):
        due = datetime.date.today().isoformat()
    else:
        m = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", t)
        if m:
            due = m.group(1)
    if name:
        return "remind %s --content \"%s\"%s" % (name, content, (" --due " + due) if due else "")
    return None


def understand_link(t):
    names = profile_names_in(t)
    m = re.search(r"\bas\s+([a-z]+)\b", t, re.I)
    rtype = norm_relation(m.group(1)) or "ally" if m else "ally"
    if len(names) >= 2:
        return "link %s %s --type %s" % (names[0], names[1], rtype)
    return None


def understand_show(t):
    cats = {"phone": ["phone", "number", "num"], "email": ["email", "mail"],
            "records": ["records", "record", "timeline", "history"],
            "photos": ["photos", "pics", "pictures", "images"],
            "locations": ["locations", "location", "places", "gps"],
            "reminders": ["reminders", "reminder"],
            "links": ["links", "connections"], "tags": ["tags"], "notes": ["notes"]}
    cat = None
    for c, aliases in cats.items():
        for a in aliases:
            if re.search(r"\b%s\b" % a, t, re.I):
                cat = c
                break
        if cat:
            break
    name = profile_name_in(t)
    if name and cat:
        return "show %s %s" % (cat, name)
    if name:
        return "show %s" % name
    if not cat:
        cand = find_profiles(t.strip(" ?.!")[:40])
        if len(cand) == 1:
            return "show " + cand[0]
    return None


def understand_record(t):
    name = profile_name_in(t)
    rtype = None
    for alias, canon in RECORD_ALIASES.items():
        if re.search(r"\b%s\b" % alias, t, re.I):
            rtype = canon
            break
    content = None
    m = re.search(r":\s*(.+)$", t)
    if m:
        content = m.group(1).strip()
    if not content:
        m = re.search(r"\babout\s+(.+?)(?:\.|$)", t, re.I)
        if m:
            content = m.group(1).strip()
    if name and rtype:
        return "record %s --type %s --content \"%s\"" % (name, rtype, content or t.strip(" ."))
    return None


def understand_location(t):
    name = profile_name_in(t)
    if name and re.search(r"\blocation\b", t, re.I):
        return "locate " + name
    return None


def understand(text):
    t = text.strip()
    if not t:
        return None
    low = t.lower()
    if re.search(r"\b(web search|search the web|search online|look it up|lookup|google it|google)\b", low) or \
       (re.search(r"\b(search|look)\b", low) and re.search(r"\b(web|online|internet|google|news)\b", low)):
        m = re.search(r"\b(?:search|look up|google)\s+(?:for\s+|on\s+|the\s+web\s+for\s+)?(.+?)(?:\?|$)", t, re.I)
        if m:
            return "websearch " + m.group(1).strip()
    m = re.search(r"(https?://[^\s]+)", t)
    if m and re.search(r"\b(fetch|open|visit|get|read)\b", low):
        return "fetch " + m.group(1)
    if re.search(r"\b(what is|whats|who is|who was|when was)\b", low):
        m = re.search(r"\b(?:what is|whats|who is|who was|when was)\s+(.+?)(?:\?|$)", t, re.I)
        if m:
            return "websearch " + m.group(1).strip()
    if re.search(r"\b(remind|reminder)\b", low):
        return understand_reminder(t)
    if re.search(r"\blocation\b", low) and re.search(r"\b(log|save|track|add|record|set)\b", low):
        return understand_location(t)
    if re.search(r"\blink\b|\bconnect\b", low):
        return understand_link(t)
    if re.search(r"\b(meeting|call|message|sighting|transaction|osint|note|record)\b", low) and \
       re.search(r"\b(add|log|note|record|save)\b", low):
        return understand_record(t)
    if re.search(r"\b(add|create|new)\b.*\bprofile\b", low) or \
       re.search(r"\bnew\b", low):
        return understand_create(t)
    if re.search(r"\b(show|display|view|what are|give me)\b", low):
        return understand_show(t)
    if re.search(r"\bwho do i know\b|\bwho knows\b|\bwho at\b", low):
        m = re.search(r"\bat\s+([A-Za-z0-9][\w &.'-]{1,60}?)(?:\?|\s*$)", t, re.I)
        if m:
            return "who-at " + m.group(1).strip()
    if re.search(r"\bosint\b|\bfind info\b|\bfetch info\b|\bintel\b", low):
        name = profile_name_in(t)
        if name:
            return "osint " + name
    cand = find_profiles(t.strip(" ?.!")[:40])
    if len(cand) == 1:
        return "show " + cand[0]
    return None


def cmd_who(q):
    q = (q or "").strip()
    if not q:
        return
    ql = q.lower()
    hits = []
    for pid in list_pids():
        p = load(pid)
        blob = " ".join([p.get("name", ""), p.get("employer", ""), p.get("occupation", ""),
                         " ".join(p.get("tags", [])), " ".join(p.get("aliases", []))]).lower()
        if ql in blob:
            hits.append(p)
    if not hits:
        print("No profiles match '%s'." % q)
    else:
        for p in hits:
            print("  %s  [%s] %s" % (p["name"], p.get("employer") or p.get("occupation") or "-",
                                     ", ".join(p.get("tags", []))))


def cmd_ask(text, interactive=True):
    if not text and interactive:
        text = prompt("Ask")
    if not text:
        return "menu"
    cfg = ai_load_config()
    if cfg.get("enabled") and cfg.get("base_url"):
        ai_agent(text, interactive)
        return "menu"
    cmd = understand(text)
    if cmd:
        print("PROFILER> %s" % cmd)
        run_command(cmd, interactive=interactive)
        return "menu"
    print("I couldn't understand that. Try e.g. 'add a profile for John, phone 01711', "
          "'search the web for X', or 'show me John's records'.")
    return "menu"


def ai_chat():
    print("Type 'exit' to leave.")
    while True:
        try:
            t = input("you> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return "menu"
        if not t:
            continue
        if t.lower() in ("exit", "quit", "q"):
            return "menu"
        try:
            cmd_ask(t, True)
        except KeyboardInterrupt:
            continue
        except Exception as e:
            print("Error: %s" % e)


# --------------------------------------------------------------------------
# Contact auto-extraction from found profiles
# --------------------------------------------------------------------------
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}(?!\d)"
)
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
AGE_RE = re.compile(r"(?i)\b(?:age|born|dob|birthday|bday)[:\s-]*(\d{1,3})\b")
YEAR_RE = re.compile(r"\b(19\d{2}|20\d{2})\b")


def _looks_like_phone(raw):
    num = re.sub(r"[^\d+]", "", raw)
    if not (7 <= len(num) <= 15):
        return None
    if len(num) >= 10 and num.startswith("1") and not num.startswith("+1"):
        return None
    has_country = bool(re.match(r"^(?:\+|00)\d{1,3}\s?\d", num))
    has_sep = bool(re.search(r"[)(\s.-]", raw))
    if has_country or has_sep:
        return num
    if 10 <= len(num) <= 11 and num[0] in "23456789":
        return num
    return None


def extract_contacts_from_text(text):
    phones, emails, ages, years, locs = set(), set(), set(), set(), set()
    if not text:
        return phones, emails, ages, years, locs
    for m in PHONE_RE.finditer(text):
        raw = m.group(0)
        num = _looks_like_phone(raw)
        if num:
            phones.add(num)
    for m in EMAIL_RE.finditer(text):
        em = m.group(0).lower()
        if re.search(r"\.(png|jpe?g|gif|svg|webp|css|js|json)$", em):
            continue
        if "@" in em and re.match(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$", em):
            emails.add(em)
    for m in AGE_RE.finditer(text):
        try:
            a = int(m.group(1))
            if 13 <= a <= 110:
                ages.add(a)
        except Exception:
            pass
    for m in YEAR_RE.finditer(text):
        try:
            y = int(m.group(1))
            if 1940 <= y <= 2020:
                years.add(y)
        except Exception:
            pass
    for kw in ("Dhaka", "Chittagong", "Sylhet", "Khulna", "Rajshahi", "Barisal",
               "Rangpur", "Mymensingh", "Comilla", "Bangladesh", "New York", "London",
               "Los Angeles", "Toronto", "Dubai", "Karachi", "Lahore", "Delhi", "Mumbai"):
        if kw.lower() in (text or "").lower():
            locs.add(kw)
    return phones, emails, ages, years, locs


def osint_extract_from_profile(username):
    phones, emails, ages, years, locs = set(), set(), set(), set(), set()
    seen_urls = set()
    for platform, tpl in SOCIAL_PLATFORMS.items():
        url = tpl % username
        if url in seen_urls:
            continue
        seen_urls.add(url)
        st = http_status(url, timeout=5)
        if st != 200:
            continue
        page = http_get(url, timeout=8)
        if not page:
            continue
        p, e, a, y, l = extract_contacts_from_text(page)
        phones |= p
        emails |= e
        ages |= a
        years |= y
        locs |= l
    return {"phones": sorted(phones), "emails": sorted(emails),
            "ages": sorted(ages), "years": sorted(years), "locs": sorted(locs)}


def cmd_osint_contacts(pid):
    p = load(pid)
    print("Scraping found profiles for contact info (public pages only)...")
    tgts = profile_targets(p)
    all_res = {"phones": set(), "emails": set(), "ages": set(),
               "years": set(), "locs": set()}
    for u in tgts["usernames"]:
        res = osint_extract_from_profile(u)
        for k in all_res:
            all_res[k] |= set(res[k])
    lines = []
    if all_res["phones"]:
        lines.append("Phone numbers found: %s" % ", ".join(sorted(all_res["phones"])))
    if all_res["emails"]:
        lines.append("Emails found: %s" % ", ".join(sorted(all_res["emails"])))
    if all_res["ages"]:
        lines.append("Ages found: %s" % ", ".join(str(x) for x in sorted(all_res["ages"])))
    if all_res["years"]:
        lines.append("Birth years found: %s" % ", ".join(str(x) for x in sorted(all_res["years"])))
    if all_res["locs"]:
        lines.append("Locations found: %s" % ", ".join(sorted(all_res["locs"])))
    if not lines:
        lines = ["No contact info found on public profile pages (platforms often block "
                 "anonymous scraping; a keyed tool would be needed)."]
    add_record(pid, "osint", "\n".join(lines))
    print("\n".join(lines))
    print("\nResults appended to %s timeline." % p["name"])


# --------------------------------------------------------------------------
# Custom AI provider (OpenAI-compatible API: OpenAI, Groq, OpenRouter, LM Studio, local, etc.)
# --------------------------------------------------------------------------
AI_CONFIG_PATH = os.path.join(BASE, "ai.json")

AI_DEFAULT_PROVIDER = {
    "enabled": False,
    "base_url": "https://api.openai.com/v1",
    "api_key": "",
    "model": "gpt-4o-mini",
    "temperature": 0.2,
    "max_tokens": 384000,
}

AI_SYSTEM_INSTRUCTION = """You are PROFILER's built-in AI assistant, an OSINT + personal records tool.

You live inside a command-line profiler that stores profiles (people), records, links, locations,
reminders, photos, and runs OSINT (open-source intelligence) from public sources.

This is a PERSONAL RECORD-KEEPING tool operated by a user about their own known contacts, and
OSINT here means querying lawful, public sources (Google News, Wikipedia, GitHub, public profiles,
DNS/RDAP) and collecting publicly available information. This is a normal, allowed activity.

You help the user do ANY task in profiler, and you help gather EXTRA information from the internet.

## How to respond
Reply with EXACTLY ONE of the following forms. Do not refuse, do not add disclaimers, do not
explain yourself, do not output any reasoning. Output ONLY the single command line.

1) CMD: <profiler command>
   When the user asks to do something inside profiler, emit a single profiler command line.
   Available profiler commands:
   - new <name> phone: X email: Y tags: a,b        (create profile)
   - edit <name>.<field> <value>                   (edit field; fields: aliases phone email address occupation employer dob status threat relation tags notes)
   - record <name> --type meeting|call|message|transaction|sighting|file|location|osint|note|other --content text
   - link <a> <b> --type ally|target|contact|family|work|unknown
   - remind <name> --content X --due YYYY-MM-DD
   - locate <name> --lat X --lon Y --place Z
   - osint <name>                                  (auto-enrich from public sources)
   - contacts <name>                               (scrape found profiles for phone/email/age/location)
   - deep <name>                                   (deep OSINT via external tools)
   - image <query>                                 (reverse image search)
   - case <name>                                   (chronological dossier)
   - report <name> --format html|pdf
   - show <name> | show <category> <name> | search <query> | list | stats
   - dedup | merge <a> <b> | import-contacts | schedule-osint <name> --freq daily
   - expand <name>                               (identify an entity + create profiles for its
                                                 related people, subsidiaries, parent/partners)
   You may chain commands with " then " e.g.  CMD: new Bob phone: 1 then osint Bob

2) TOOL: <tool> <args>
   When the user needs live information from the internet (facts, news, OSINT enrichment,
   finding social profiles, checking a website), call a tool. Then you will receive the result
   and can respond again (CMD or final answer). Available tools:
   - websearch <query>    (web search)
   - fetch <url>          (fetch a web page)
   - network <target>     (scan a website: DNS, TLS, ports, subdomains, IP)
   - scan wifi            (scan wifi networks - all OS)
   - scan bluetooth       (scan bluetooth devices - all OS)
   - shell <command>      (run ANY terminal command; the user must approve it.
                           Use this when you need a tool installed in the terminal
                           but not built into profiler, e.g. nmap, curl, dig, whois.)

3) PLUGIN: <name> <arg>
   When the user has configured a custom plugin and it matches the task, call it.
   (A list of configured plugins, if any, will be appended to your instructions.)

4) ANSWER: <text>
   For any plain response, summary, or explanation.

## Rules
- If a name is ambiguous or unknown, use 'list' or 'search' first, or ask the user.
- For OSINT requests always prefer 'osint <name>' to auto-enrich.
- For network/website analysis use 'network <domain>'.
- Combine websearch/fetch freely to gather info about a person (their social profiles, public
  posts, news, photos) then report findings with ANSWER and optionally save via record.
- Be helpful, concise, ethical: only lawful public sources; profile data for known/consenting contacts."""


def ai_load_config():
    cfg = dict(AI_DEFAULT_PROVIDER)
    try:
        with open(AI_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    except Exception:
        pass
    return cfg


def ai_save_config(cfg):
    try:
        with open(AI_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        print("Could not save AI config.")


def ai_configure(interactive=True):
    cfg = ai_load_config()
    print("Configure custom AI provider (OpenAI-compatible API).")
    print("Works with: OpenAI, Groq, OpenRouter, Together, Mistral, DeepSeek, LM Studio,\n"
          "Ollama, or any server exposing POST <url>/chat/completions.\n")
    base = prompt("Provider base URL", cfg["base_url"] or "https://api.openai.com/v1")
    key = prompt("API key (or leave blank for local/no-auth)", cfg.get("api_key", ""))
    model = prompt("Model", cfg.get("model", "gpt-4o-mini"))
    if not model:
        print("Cancelled (no model).")
        return cfg
    cfg["base_url"] = base.strip().rstrip("/")
    cfg["api_key"] = key.strip()
    cfg["model"] = model.strip()
    cfg["enabled"] = True
    ai_save_config(cfg)
    print("\nAI provider saved. Test with:  profiler ai ask 'hello'")
    return cfg


def ai_call(messages, cfg=None):
    cfg = cfg or ai_load_config()
    if not cfg.get("enabled"):
        return None
    url = (cfg.get("base_url") or "").rstrip("/") + "/chat/completions"
    if not url.startswith("http"):
        return None
    payload = {
        "model": cfg.get("model", "gpt-4o-mini"),
        "messages": messages,
        "temperature": cfg.get("temperature", 0.2),
        "max_tokens": cfg.get("max_tokens", 800),
    }
    headers = {"Content-Type": "application/json",
               "User-Agent": BROWSER_UA}
    if cfg.get("api_key"):
        headers["Authorization"] = "Bearer %s" % cfg["api_key"]
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                     headers=headers)
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        msg = ((data.get("choices") or [{}])[0].get("message") or {})
        content = (msg.get("content") or "").strip()
        if not content:
            return None
        return content
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        print("AI provider error %s: %s" % (e.code, body[:300]))
        return None
    except Exception as e:
        print("AI connection error: %s" % e)
        return None


def ai_run_tool(tool_cmd, interactive=True):
    low = tool_cmd.strip().lower()
    m = re.match(r"^(websearch|searchweb|web|ddg)\s+(.+)$", low)
    if m:
        return web_search(m.group(2).strip(), 6)
    m = re.match(r"^(fetch|geturl|open)\s+(\S.+)$", low)
    if m:
        return fetch_url(m.group(2).strip())
    m = re.match(r"^network\s+deep\s+(.+)$", low)
    if m:
        lines = scan_website_deep(m.group(1).strip())
        return [("Deep network scan: %s" % m.group(1).strip(), lines)]
    m = re.match(r"^network\s+(.+)$", low)
    if m:
        lines = scan_website(m.group(1).strip())
        return [("Network scan: %s" % m.group(1).strip(), lines)]
    m = re.match(r"^scan\s+(wifi|wlan)$", low)
    if m:
        return [("WiFi scan", scan_wifi())]
    m = re.match(r"^scan\s+(bluetooth|bt|ble)$", low)
    if m:
        return [("Bluetooth scan", scan_bluetooth())]
    m = re.match(r"^shell\s+(.+)$", low)
    if m:
        out = ai_run_shell(m.group(1).strip(), interactive)
        return [("Shell command result", out.splitlines())]
    return None


def ai_agent(user_text, interactive=True):
    cfg = ai_load_config()
    if not cfg.get("enabled") or not cfg.get("base_url"):
        print("AI provider not configured. Run:  profiler ai config")
        return "menu"
    system_prompt = AI_SYSTEM_INSTRUCTION
    plugin_desc = ai_plugin_descriptions()
    if plugin_desc:
        system_prompt += "\n\n" + plugin_desc
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_text}]
    for _ in range(10):
        reply = ai_call(messages, cfg)
        if not reply:
            if len(messages) == 2:
                messages.append({"role": "user",
                                 "content": "Answer directly now. Do NOT output any reasoning "
                                            "or disclaimers. Reply with exactly one of: "
                                            "CMD: ... | TOOL: ... | PLUGIN: ... | ANSWER: ..."})
                continue
            print("AI> (no response from model)")
            return "menu"
        m_cmd = re.search(r"^\s*CMD:\s*(.+)$", reply, re.M | re.I)
        if m_cmd:
            cmdline = m_cmd.group(1).strip()
            print("PROFILER> %s" % cmdline)
            run_command(cmdline, interactive=interactive)
            messages.append({"role": "user",
                             "content": "I executed that command. Now give your final summary or answer."})
            continue
        m_plugin = re.search(r"^\s*PLUGIN:\s*(.+)$", reply, re.M | re.I)
        if m_plugin:
            pcmd = m_plugin.group(1).strip()
            parts = shlex.split(pcmd)
            if parts:
                pname = parts[0]
                parg = " ".join(parts[1:])
                print("PLUGIN> %s" % pcmd)
                out = plugin_exec(pname, parg, verbose=False)
                if out is None:
                    out = "plugin '%s' not found" % pname
                messages.append({"role": "user",
                                 "content": "Plugin result:\n%s" % str(out)[:3000]})
                continue
        m_tool = re.search(r"^\s*TOOL:\s*(.+)$", reply, re.M | re.I)
        if m_tool:
            tool_cmd = m_tool.group(1).strip()
            print("TOOL> %s" % tool_cmd)
            results = ai_run_tool(tool_cmd, interactive)
            if not results:
                messages.append({"role": "user",
                                 "content": "Tool result: tool failed or no results"})
                continue
            text_blob = "\n".join(ln for _, lines in results for ln in lines)
            messages.append({"role": "user",
                             "content": "Tool result:\n%s" % text_blob[:3000]})
            continue
        answer = reply
        m_ans = re.search(r"^\s*ANSWER:\s*(.+)$", reply, re.M | re.I)
        if m_ans:
            answer = m_ans.group(1).strip()
        print("AI> %s" % answer)
        return "menu"
    print("AI> (session complete)")
    return "menu"


def ai_chat_interactive():
    cfg = ai_load_config()
    if not cfg.get("enabled") or not cfg.get("base_url"):
        print("AI provider not configured. Run:  profiler ai config")
        return "menu"
    print("PROFILER AI chat. Type 'exit' to leave.")
    while True:
        try:
            t = input("you> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return "menu"
        if not t:
            continue
        if t.lower() in ("exit", "quit", "q", "bye"):
            return "menu"
        try:
            ai_agent(t, True)
        except KeyboardInterrupt:
            continue
        except Exception as e:
            print("Error: %s" % e)


def cmd_ai(args, interactive=True):
    if not args:
        ai_chat_interactive()
        return
    sub = args[0].lower()
    if sub in ("config", "setup", "configure"):
        ai_configure(interactive)
    elif sub in ("status", "info", "show"):
        cfg = ai_load_config()
        print("AI provider: %s" % ("configured" if cfg.get("enabled") and cfg.get("base_url")
                                   else "not configured"))
        print("  base_url : %s" % cfg.get("base_url", ""))
        print("  model    : %s" % cfg.get("model", ""))
        print("  api_key  : %s" % ("set" if cfg.get("api_key") else "none"))
    elif sub in ("on", "enable"):
        cfg = ai_load_config()
        cfg["enabled"] = True
        ai_save_config(cfg)
        print("AI enabled.")
    elif sub in ("off", "disable"):
        cfg = ai_load_config()
        cfg["enabled"] = False
        ai_save_config(cfg)
        print("AI disabled.")
    elif sub in ("ask", "query", "chat"):
        text = " ".join(args[1:]).strip()
        if not text:
            if interactive:
                text = prompt("Ask AI")
            if not text:
                return
        ai_agent(text, interactive)
    elif sub in ("help", "-h", "--help"):
        print("profiler ai [config|status|on|off|ask <text>]")
    else:
        ai_agent(" ".join(args), interactive)


# --------------------------------------------------------------------------
# Entity expansion: from a single name/word -> related people, companies, subs
# --------------------------------------------------------------------------
def ai_extract_entities(name, interactive=True):
    """Ask the AI to identify an entity and its related people/companies/subs.
    Returns a list of dicts: {name, type, relation, note, tags}
    Uses the built-in parser fallback if AI not configured."""
    cfg = ai_load_config()
    if cfg.get("enabled") and cfg.get("base_url"):
        prompt_text = (
            "Research this name: '%s'. It may be a company, a person, a book, a place, "
            "an event, or anything else.\n\n"
            "Identify it, then list its most important related entities as JSON only, in this exact format:\n"
            "{\"type\": \"company|person|book|place|event|other\", \"entities\": [\n"
            "  {\"name\": \"...\", \"type\": \"company|person|subsidiary|parent|partner|founder|director|employee|related\", "
            "\"relation\": \"short how it relates\", \"note\": \"short fact\"},\n"
            "  ...\n]}\n\n"
            "Include the main entity itself as the first item with type 'main'. "
            "Include major people (founders, directors, key figures), subsidiaries, "
            "parent companies, and closely related entities. 5-15 items. "
            "Use websearch/fetch if needed. Output ONLY the JSON, nothing else."
        ) % name
        for _ in range(6):
            reply = ai_call([{"role": "system",
                              "content": "You extract structured JSON entity lists from research. "
                                         "You may call websearch/fetch tools but ALWAYS end with the "
                                         "JSON only. No markdown, no extra text."},
                             {"role": "user", "content": prompt_text}], cfg)
            if not reply:
                continue
            m = re.search(r"\{.*\}", reply, re.S)
            if not m:
                continue
            try:
                data = json.loads(m.group(0))
                ents = data.get("entities") or []
                if ents:
                    return data.get("type", "other"), ents
            except Exception:
                continue
    # fallback: minimal
    return "other", [{"name": name, "type": "main", "relation": "main entity",
                      "note": "identified entity"}]


def cmd_expand(name, interactive=True):
    """Expand a single name/word into a network of related profiles."""
    print("Expanding '%s' - identifying entity and related people/companies..." % name)
    etype, ents = ai_extract_entities(name, interactive)
    if not ents:
        print("Could not identify any related entities.")
        return

    print("Identified as: %s" % etype)
    print("Found %d related entit(ies):" % len(ents))

    # Create the main entity profile first
    main = ents[0]
    main_pid = None
    # Check if a profile already exists with this name
    for pid in list_pids():
        p = load(pid)
        if p["name"].lower() == main["name"].lower():
            main_pid = pid
            break
    if not main_pid:
        fields = {"occupation": "company" if etype == "company" else etype,
                  "tags": [etype, "main"],
                  "notes": main.get("note", "")}
        main_pid = new_profile(main["name"], **fields)
        print("  [+] Created main: %s (ID: %s)" % (main["name"], main_pid))
    else:
        print("  [=] Main already exists: %s (ID: %s)" % (main["name"], main_pid))

    # Create related profiles
    created = []
    for e in ents[1:]:
        ename = e.get("name", "").strip()
        if not ename:
            continue
        etype_e = e.get("type", "related")
        rel = e.get("relation", "")
        note = e.get("note", "")
        pid = None
        for ep in list_pids():
            epd = load(ep)
            if epd["name"].lower() == ename.lower():
                pid = ep
                break
        if pid:
            created.append((pid, ename, etype_e, rel))
            print("  [=] Exists: %s (ID: %s, %s)" % (ename, pid, etype_e))
            continue
        fields = {"tags": [etype_e, etype],
                  "notes": note}
        if etype_e in ("person", "founder", "director", "employee", "ceo"):
            fields["occupation"] = rel or etype_e
            if etype_e == "founder":
                fields["relation"] = "ally"
        elif etype_e in ("subsidiary", "child", "division"):
            fields["employer"] = name
            fields["relation"] = "work"
        elif etype_e in ("parent", "holding"):
            fields["relation"] = "work"
        pid = new_profile(ename, **fields)
        created.append((pid, ename, etype_e, rel))
        print("  [+] Created: %s (ID: %s, %s) - %s" % (ename, pid, etype_e, rel))

    # Link main to all related profiles
    print("\nLinking profiles...")
    for pid, ename, etype_e, rel in created:
        if pid == main_pid:
            continue
        link_type = "work"
        if etype_e in ("founder", "ceo", "director", "owner"):
            link_type = "ally"
        elif etype_e in ("family", "relative"):
            link_type = "family"
        elif etype_e in ("partner", "collaborator", "customer", "supplier"):
            link_type = "contact"
        else:
            link_type = "work"
        link_profiles(main_pid, pid, link_type)

    # Add an OSINT note to the main profile
    note_lines = ["Expanded entity: %s (%s)" % (name, etype),
                  "Related entities identified:"] + [
        "  - %s (%s): %s" % (e["name"], e.get("type", "related"), e.get("relation", ""))
        for e in ents[1:]
    ]
    add_record(main_pid, "osint", "\n".join(note_lines))

    print("\nExpansion complete. %d profile(s) created/used, %d linked." %
          (len(created) + 1, len(created)))
    print("Run 'profiler graph' to see the network, or 'profiler osint <name>' to enrich any profile.")


def tool_available(tool):
    return shutil.which(tool) is not None


# --------------------------------------------------------------------------
# Network scanning: website / wifi / bluetooth profiling
# --------------------------------------------------------------------------
def clean_domain(t):
    t = (t or "").strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = re.sub(r"^www\.", "", t)
    t = t.split("/")[0].split(":")[0].split("?")[0]
    return t


def http_headers(url, timeout=12):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": OSINT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            hdrs = dict(r.getheaders())
            return r.getcode(), hdrs
        return None, {}
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)
    except Exception as e:
        return None, {"error": str(e)}


def tls_certificate(domain, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
        return cert
    except Exception as e:
        return {"error": str(e)}


# --------------------------------------------------------------------------
# Tech fingerprinting (technique adapted from nuclei / Wappalyzer:
# match HTTP response headers, body, cookies, and meta tags against
# known signatures to detect the CMS/server/framework.)
# --------------------------------------------------------------------------
TECH_FINGERPRINTS = [
    # (name, header, header_value_regex, body_regex, meta_regex)
    ("WordPress", "x-powered-by", None, r"wp-content|wp-includes|wp-admin", r"generator[^>]*WordPress"),
    ("Drupal", None, None, r"/sites/default/files|drupal-settings|drupal.js", r"generator[^>]*Drupal"),
    ("Joomla", None, None, r"/media/jui/|com_content|joomla", r"generator[^>]*Joomla"),
    ("Shopify", "x-shopid", None, None, None),
    ("WooCommerce", None, None, r"/wp-content/plugins/woocommerce|woocommerce", None),
    ("Magento", "x-magento-cache", None, None, None),
    ("PrestaShop", "x-prestashop", None, None, None),
    ("Laravel", None, None, r"laravel_session|cookie\(['\"]laravel", None),
    ("Symfony", None, None, r"_sf2_attributes|symfony", None),
    ("Django", "x-frame-options", "SAMEORIGIN", r"csrfmiddlewaretoken|django", None),
    ("Rails", "x-powered-by", r"Phusion|Passenger|Rails", r"csrf-param.*authenticity_token", None),
    ("ASP.NET", "x-aspnet-version", None, None, None),
    ("ASP.NET MVC", "x-aspnetmvc-version", None, None, None),
    ("Node.js", "x-powered-by", "Express", r"express", None),
    ("Express", "x-powered-by", "Express", None, None),
    ("Next.js", "x-powered-by", "Next.js", r"__NEXT_DATA__|_next/", None),
    ("Nuxt", None, None, r"__NUXT__|_nuxt/", None),
    ("Vue.js", None, None, r"vue\.js|Vue\.[a-z]|__VUE__", None),
    ("React", None, None, r"react(\.min)?\.js|__react|data-reactroot", None),
    ("Angular", None, None, r"ng-app|angular(\.min)?\.js|ng-version", None),
    ("Gatsby", None, None, r"___gatsby|gatsby-", None),
    ("nginx", "server", r"^nginx", None, None),
    ("Apache", "server", r"^Apache", None, None),
    ("LiteSpeed", "server", r"^LiteSpeed", None, None),
    ("IIS", "server", r"^Microsoft-IIS", None, None),
    ("Cloudflare", "server", r"cloudflare", r"cloudflare", None),
    ("Cloudflare", "cf-ray", None, None, None),
    ("Google", "server", r"^gws|^GFE", None, None),
    ("OpenResty", "server", r"openresty", None, None),
    ("Caddy", "server", r"^Caddy", None, None),
    ("PHP", "x-powered-by", r"^PHP", r"\.php\b", None),
    ("Java", "x-powered-by", r"Java", None, None),
    ("Java", "server", r"^Apache-Coyote", None, None),
    ("Tomcat", "server", r"^Apache-Coyote", None, None),
    ("JBoss", "x-powered-by", r"JBoss", None, None),
    ("WebLogic", "server", r"WebLogic", None, None),
    ("GitHub Pages", "server", r"GitHub.com", None, None),
    ("Heroku", "via", r"heroku", None, None),
    ("Varnish", "via", r"^varnish", None, None),
    ("Squid", "server", r"^squid", None, None),
    ("CouchDB", "server", r"CouchDB", None, None),
    ("Perl", "server", r"^Apache.*Perl", None, None),
    ("Ruby", "x-powered-by", r"^Ruby", None, None),
    ("Python", "server", r"^Python|^Werkzeug|^gunicorn|^CherryPy", None, None),
    ("gunicorn", "server", r"^gunicorn", None, None),
    ("Flask", "server", r"^Werkzeug", None, None),
]


def fingerprint_tech(headers, body):
    """Detect technologies from HTTP headers + body (nuclei/wappalyzer style)."""
    found = []
    if not headers:
        headers = {}
    headers = {k.lower(): v for k, v in headers.items()}
    body_lower = (body or "").lower()
    for name, hdr, hdr_re, body_re, meta_re in TECH_FINGERPRINTS:
        hit = False
        if hdr and hdr in headers:
            val = headers[hdr]
            if hdr_re:
                if re.search(hdr_re, val, re.I):
                    hit = True
            else:
                hit = True
        if not hit and body_re and re.search(body_re, body_lower):
            hit = True
        if not hit and meta_re and re.search(meta_re, body_lower):
            hit = True
        if hit and name not in found:
            found.append(name)
    return found


def http_get_with_tech(domain):
    """Fetch page + headers, return (status, headers, body) for fingerprinting."""
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request("%s://%s/" % (scheme, domain),
                                         headers={"User-Agent": OSINT_UA})
            with urllib.request.urlopen(req, timeout=12) as r:
                body = r.read().decode("utf-8", "replace")[:20000]
                return r.getcode(), dict(r.getheaders()), body
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8", "replace")[:20000]
            except Exception:
                body = ""
            return e.code, dict(e.headers), body
        except Exception:
            continue
    return None, {}, ""


def port_scan(domain, ports=(21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 8888)):
    """Concurrent port scan (threaded, like naabu's approach)."""
    import threading
    open_ports = []
    lock = threading.Lock()

    def _scan(p):
        try:
            with socket.create_connection((domain, p), timeout=1.5):
                with lock:
                    open_ports.append(p)
        except Exception:
            pass

    threads = [threading.Thread(target=_scan, args=(p,)) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sorted(open_ports)


# --------------------------------------------------------------------------
# Borrowed open-source security tools (detected if installed):
#   naabu (projectdiscovery)  - fast port scanner
#   nmap                     - network mapper / service detection
#   httpx (projectdiscovery) - HTTP probing / tech detection
#   subfinder                - passive subdomain enumeration
#   theHarvester             - emails, subdomains, names OSINT
#   maigret                  - username dossier from 3000+ sites
# Each falls back gracefully when not installed. Install via:
#   pip3 install theHarvester  (or)  go install .../naabu@latest  etc.
# --------------------------------------------------------------------------
SECURITY_TOOLS = {
    "naabu": {
        "desc": "Fast port scanner (projectdiscovery)",
        "scan": lambda d, out: out.append(
            run_tool_capture(["naabu", "-host", d, "-silent", "-top-ports", "100"], timeout=120)
            .strip() or "naabu: no open ports found"),
    },
    "nmap": {
        "desc": "Network mapper / service detection",
        "scan": lambda d, out: out.append(
            run_tool_capture(["nmap", "-sV", "--top-ports", "50", "-T4", d], timeout=300)
            .strip() or "nmap: no results"),
    },
    "httpx": {
        "desc": "HTTP toolkit / tech & header probing (projectdiscovery)",
        "scan": lambda d, out: out.append(
            run_tool_capture(["httpx", "-u", "https://" + d, "-sc", "-title", "-tech-detect",
                              "-web-server", "-silent"], timeout=120)
            .strip() or "httpx: no results"),
    },
    "subfinder": {
        "desc": "Passive subdomain enumeration (projectdiscovery)",
        "scan": lambda d, out: out.append(
            run_tool_capture(["subfinder", "-silent", "-d", d], timeout=180)
            .strip() or "subfinder: no subdomains found"),
    },
    "theHarvester": {
        "desc": "Emails, subdomains, names OSINT",
        "scan": lambda d, out: out.append(
            run_tool_capture(["theHarvester", "-d", d, "-b", "all", "-l", "200"], timeout=300)
            .strip() or "theHarvester: no results"),
    },
    "maigret": {
        "desc": "Username dossier from 3000+ sites",
        "scan": lambda d, out: out.append(
            run_tool_capture(["maigret", d, "-a"], timeout=300)
            .strip() or "maigret: no results"),
    },
}


def security_tools_scan(target):
    """Run all installed open-source security tools against a target."""
    domain = clean_domain(target)
    lines = []
    for name, info in SECURITY_TOOLS.items():
        if tool_available(name):
            print("  [%s] running %s..." % (name, info["desc"]))
            out_lines = []
            try:
                info["scan"](domain, out_lines)
            except Exception as e:
                out_lines.append("%s error: %s" % (name, e))
            for ln in (out_lines[0] or "").splitlines()[:30]:
                lines.append("[%s] %s" % (name, ln))
        else:
            lines.append("[%s] not installed (%s). Install it to enable." % (name, info["desc"]))
    return lines


def security_tools_status():
    print("Borrowed open-source security tools:")
    for name, info in SECURITY_TOOLS.items():
        status = "INSTALLED" if tool_available(name) else "not installed"
        print("  %-14s %-10s %s" % (name, status, info["desc"]))


def security_tools_install(name=None):
    """Install a borrowed security tool (best-effort, cross-platform)."""
    import shlex
    pip_map = {
        "theHarvester": ["pip3", "install", "theHarvester"],
        "maigret": ["pip3", "install", "maigret"],
    }
    go_map = {
        "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    }
    apt_map = {
        "nmap": ["apt", "install", "-y", "nmap"],
        "subfinder": ["apt", "install", "-y", "subfinder"],
        "maigret": ["pip3", "install", "maigret"],
    }
    if name:
        if name in pip_map:
            print("Installing %s via pip3..." % name)
            print(run_tool_capture(pip_map[name], timeout=300))
        elif name in go_map:
            print("Installing %s via go (needs Go installed)..." % name)
            print(run_tool_capture(shlex.split(go_map[name]), timeout=600))
        elif name in apt_map:
            print("Installing %s via apt (needs root/sudo)..." % name)
            cmd = apt_map[name]
            if tool_available("sudo"):
                cmd = ["sudo"] + cmd
            print(run_tool_capture(cmd, timeout=300))
        else:
            print("No known install method for %s. See the tool's GitHub repo." % name)
        return
    # Install all
    for n in list(pip_map) + list(go_map) + list(apt_map):
        if not tool_available(n):
            print("\n--- Installing %s ---" % n)
            security_tools_install(n)


def scan_website(target):
    domain = clean_domain(target)
    lines = []
    lines.append("Target: %s" % target)
    lines.append("Domain: %s" % domain)

    # DNS resolution
    try:
        host, aliases, addrs = socket.gethostbyname_ex(domain)
        lines.append("DNS: %s" % (", ".join(addrs) or "-"))
        if aliases:
            lines.append("Aliases: %s" % ", ".join(aliases))
    except Exception as e:
        lines.append("DNS: failed (%s)" % e)

    # HTTP headers + tech fingerprinting
    code, hdrs, body = http_get_with_tech(domain)
    if hdrs:
        scheme = "https" if code else "http"
        lines.append("HTTP (%s): status %s" % (scheme, code))
        for k in ("server", "x-powered-by", "content-type", "strict-transport-security",
                  "set-cookie", "via", "x-aspnet-version", "x-generator"):
            if hdrs.get(k):
                lines.append("  %s: %s" % (k, hdrs[k][:120]))
        tech = fingerprint_tech(hdrs, body)
        if tech:
            lines.append("  Technologies detected: %s" % ", ".join(tech))

    # TLS certificate
    cert = tls_certificate(domain)
    if cert and not cert.get("error"):
        subj = cert.get("subject", ())
        for item in subj:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                k, v = item[0], item[1]
                if k == "commonName":
                    lines.append("TLS CN: %s" % v)
        san = cert.get("subjectAltName", ())
        if san:
            lines.append("TLS SAN: %s" % ", ".join(v for _, v in san[:8]))
        for k in ("notBefore", "notAfter"):
            if cert.get(k):
                lines.append("TLS %s: %s" % (k.replace("not", "valid from"), cert[k]))
        issuer = cert.get("issuer", ())
        for item in issuer:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                k, v = item[0], item[1]
                if k == "organizationName":
                    lines.append("TLS issuer: %s" % v)
    else:
        lines.append("TLS: %s" % cert.get("error", "no certificate"))

    # IP intelligence
    try:
        ip = socket.gethostbyname(domain)
        lines.append("IP: %s" % ip)
        geo = http_get_json("http://ip-api.com/json/" + ip)
        if geo and geo.get("status") == "success":
            lines.append("IP country: %s, region: %s, city: %s" % (
                geo.get("country"), geo.get("regionName"), geo.get("city")))
            lines.append("IP ISP: %s / %s" % (geo.get("isp"), geo.get("org")))
            lines.append("IP AS: %s" % geo.get("as"))
    except Exception:
        pass

    # Port scan (quick)
    ports = port_scan(domain)
    if ports:
        lines.append("Open ports: %s" % ", ".join(str(p) for p in ports))
    else:
        lines.append("Open ports: none found (common list)")

    # Subdomains
    sub = osint_subdomains(domain)
    if sub:
        sub_lines = sub[0][1]
        if sub_lines and sub_lines[0] != "lookup failed":
            lines.append("Subdomains: %s" % (", ".join(sub_lines[:15]) or "none"))

    return lines


def scan_website_deep(target):
    """Full scan: base website scan + borrowed open-source security tools."""
    domain = clean_domain(target)
    lines = scan_website(domain)
    lines.append("")
    lines.append("-- Borrowed open-source security tools --")
    lines.extend(security_tools_scan(domain))
    return lines


def scan_wifi():
    lines = []
    # Android / Termux
    if tool_available("termux-wifi-scaninfo"):
        print("  [wifi] scanning networks (termux-wifi-scaninfo)...")
        out = run_tool_capture(["termux-wifi-scaninfo"], timeout=20)
        try:
            nets = json.loads(out)
            if not nets:
                lines.append("No wifi networks found.")
            for n in nets[:20]:
                ssid = n.get("ssid") or "(hidden)"
                bssid = n.get("bssid", "")
                rssi = n.get("rssi", "")
                freq = n.get("frequency", "")
                lines.append("WiFi: %s | BSSID %s | RSSI %s dBm | %s MHz" % (ssid, bssid, rssi, freq))
            return lines
        except Exception:
            lines.append("Wifi scan: could not parse output.")
            return lines
    # Windows
    if os.name == "nt" and tool_available("netsh"):
        print("  [wifi] scanning via netsh (Windows)...")
        out = run_tool_capture(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=30)
        lines.append(out.strip() or "netsh: no wifi networks found")
        return lines
    # Linux / others: try nmcli, then iw, then iwlist
    if tool_available("nmcli"):
        print("  [wifi] scanning via nmcli (NetworkManager)...")
        out = run_tool_capture(["nmcli", "-f", "SSID,SIGNAL,SECURITY", "dev", "wifi", "list"], timeout=30)
        lines.append(out.strip() or "nmcli: no wifi networks found")
        return lines
    if tool_available("iw"):
        print("  [wifi] scanning via iw (needs root)...")
        out = run_tool_capture(["iw", "dev"], timeout=10)
        dev = ""
        for ln in out.splitlines():
            if "Interface" in ln:
                dev = ln.split()[-1]
                break
        if dev:
            out2 = run_tool_capture(["iw", "dev", dev, "scan"], timeout=30)
            found = [ln.strip() for ln in out2.splitlines() if "SSID:" in ln]
            lines.append("\n".join("WiFi: %s" % s.split("SSID:")[-1].strip() for s in found[:20]) or "no SSIDs found")
        else:
            lines.append("iw: no wireless interface found")
        return lines
    if tool_available("iwlist"):
        print("  [wifi] scanning via iwlist (legacy)...")
        out = run_tool_capture(["iwlist", "scan"], timeout=40)
        ssids = re.findall(r'ESSID:"([^"]*)"', out)
        lines.append("\n".join("WiFi: %s" % s for s in ssids[:20]) or "iwlist: no networks found")
        return lines
    lines.append("WiFi scanning: no compatible tool found.")
    lines.append("Install nmcli (NetworkManager), iw, or iwlist on Linux; use netsh on Windows; termux-api on Android.")
    return lines


def scan_bluetooth():
    lines = []
    # Android / Termux
    if tool_available("termux-bluetooth-scaninfo"):
        print("  [bluetooth] scanning devices (termux-bluetooth-scaninfo)...")
        out = run_tool_capture(["termux-bluetooth-scaninfo"], timeout=30)
        try:
            devs = json.loads(out)
            if not devs:
                lines.append("No bluetooth devices found.")
            for d in devs[:20]:
                name = d.get("name") or "(unknown)"
                mac = d.get("address", "")
                lines.append("BT: %s | %s" % (name, mac))
            return lines
        except Exception:
            lines.append("Bluetooth scan: could not parse output.")
            return lines
    # Windows
    if os.name == "nt" and tool_available("powershell"):
        print("  [bluetooth] scanning via PowerShell (Windows)...")
        ps = ("Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -eq 'OK'} | "
              "Select-Object FriendlyName | Format-Table -HideTableHeaders")
        out = run_tool_capture(["powershell", "-NoProfile", "-Command", ps], timeout=30)
        lines.append(out.strip() or "powershell: no bluetooth devices found")
        return lines
    # Linux / macOS: bluetoothctl
    if tool_available("bluetoothctl"):
        print("  [bluetooth] scanning via bluetoothctl...")
        run_tool_capture(["bluetoothctl", "--timeout", "8", "scan", "on"], timeout=15)
        out = run_tool_capture(["bluetoothctl", "devices"], timeout=15)
        found = [ln.strip() for ln in out.splitlines() if "Device" in ln]
        lines.append("\n".join(found[:20]) or "bluetoothctl: no devices found")
        return lines
    lines.append("Bluetooth scanning: no compatible tool found.")
    lines.append("Install bluetoothctl (bluez) on Linux, use PowerShell on Windows, termux-api on Android.")
    return lines


def cmd_network(args, interactive=True):
    if not args:
        print("Usage: profiler network <domain/url> | network --wifi | network --bluetooth | "
              "network --deep <domain> | network --tools")
        return
    if args[0].lower() in ("--tools", "tools", "status"):
        security_tools_status()
        return
    if args[0].lower() in ("--install", "-i", "install"):
        security_tools_install(args[1] if len(args) > 1 else None)
        return
    if args[0].lower() in ("--deep", "-d", "deep"):
        target = " ".join(args[1:]).strip()
        if not target:
            print("Usage: profiler network --deep <domain>")
            return
        print("Deep network scan (with borrowed security tools): %s" % target)
        lines = scan_website_deep(target)
        print("\n".join("  " + ln for ln in lines))
        if interactive:
            r = prompt("Save as a profile? (name or Enter to skip)")
            if r:
                pid = new_profile(r, tags=["network", "deep-scan"], notes="\n".join(lines))
                add_record(pid, "osint", "\n".join(lines))
                print("Saved to profile %s" % pid)
        return
    if args[0].lower() in ("--wifi", "-w", "wifi"):
        lines = scan_wifi()
        for ln in lines:
            print("  " + ln)
        if interactive:
            r = prompt("Save as a profile? (name or Enter to skip)")
            if r:
                pid = new_profile(r, tags=["network", "wifi"], notes="\n".join(lines))
                add_record(pid, "osint", "\n".join(lines))
                print("Saved to profile %s" % pid)
        return
    if args[0].lower() in ("--bluetooth", "-b", "bluetooth", "bt"):
        lines = scan_bluetooth()
        for ln in lines:
            print("  " + ln)
        if interactive:
            r = prompt("Save as a profile? (name or Enter to skip)")
            if r:
                pid = new_profile(r, tags=["network", "bluetooth"], notes="\n".join(lines))
                add_record(pid, "osint", "\n".join(lines))
                print("Saved to profile %s" % pid)
        return

    target = " ".join(args)
    print("Scanning network target: %s ..." % target)
    lines = scan_website(target)
    print("\n".join("  " + ln for ln in lines))

    if interactive:
        r = prompt("Save as a profile? (name or Enter to skip)")
        if r:
            pid = new_profile(r, tags=["network", "website"], notes="\n".join(lines))
            add_record(pid, "osint", "\n".join(lines))
            print("Saved to profile %s" % pid)


# --------------------------------------------------------------------------
# Custom plugin system: user-defined tools, usable by the AI
# --------------------------------------------------------------------------
PLUGIN_CONFIG = os.path.join(BASE, "plugins.json")


def plugin_load():
    try:
        with open(PLUGIN_CONFIG, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def plugin_save(plugins):
    try:
        with open(PLUGIN_CONFIG, "w", encoding="utf-8") as f:
            json.dump(plugins, f, indent=2)
    except Exception:
        print("Could not save plugins.")


def plugin_add(interactive=True):
    plugins = plugin_load()
    print("Add a custom plugin/tool (usable by you AND the AI).")
    print("Types: command (local CLI tool), url (HTTP endpoint), python (inline script).\n")
    name = prompt("Plugin name (unique, e.g. mytool)")
    if not name:
        print("Cancelled.")
        return
    ptype = prompt("Type (command/url/python)", "command").strip().lower()
    if ptype not in ("command", "url", "python"):
        print("Invalid type. Use command, url, or python.")
        return
    desc = prompt("Description (what it does / when to use)")
    if ptype == "command":
        cmdline = prompt("Command (e.g. /path/tool --flag {arg}) - use {arg} as input placeholder")
        if not cmdline:
            print("Cancelled.")
            return
        plugin = {"name": name, "type": ptype, "command": cmdline,
                  "description": desc, "timeout": 120}
    elif ptype == "url":
        url = prompt("URL (use {arg} as placeholder, e.g. https://api.x.com/?q={arg})")
        method = prompt("Method (GET/POST)", "GET").upper()
        headers = prompt("Extra headers (JSON, optional)")
        hdr = {}
        try:
            hdr = json.loads(headers) if headers else {}
        except Exception:
            print("Invalid JSON headers - ignoring.")
        plugin = {"name": name, "type": ptype, "url": url, "method": method,
                  "headers": hdr, "description": desc}
    else:
        script = prompt("Python code (function run(arg) -> str)")
        if not script:
            print("Cancelled.")
            return
        plugin = {"name": name, "type": ptype, "code": script, "description": desc}

    auth = prompt("Auth info (optional, e.g. 'Bearer TOKEN' or 'key=VALUE')")
    if auth:
        plugin["auth"] = auth
    plugins.append(plugin)
    plugin_save(plugins)
    print("\nPlugin '%s' added. Available to you and the AI." % name)


def plugin_list():
    plugins = plugin_load()
    if not plugins:
        print("No plugins configured.")
        return
    print("Configured plugins (%d):" % len(plugins))
    for p in plugins:
        print("  - %s (%s): %s" % (p.get("name"), p.get("type"), p.get("description") or ""))


def plugin_remove(name, interactive=True):
    plugins = plugin_load()
    before = len(plugins)
    plugins = [p for p in plugins if p.get("name", "").lower() != name.lower()]
    if len(plugins) == before:
        print("Plugin '%s' not found." % name)
        return
    plugin_save(plugins)
    print("Removed plugin '%s'." % name)


def plugin_run(p, arg=""):
    """Run a plugin and return its text output."""
    try:
        if p["type"] == "command":
            cmd = p.get("command", "").replace("{arg}", arg or "")
            return run_tool_capture(shlex.split(cmd), timeout=p.get("timeout", 120))
        elif p["type"] == "url":
            url = p.get("url", "").replace("{arg}", urllib.parse.quote(arg or "") if arg else "")
            headers = {"User-Agent": OSINT_UA, "Content-Type": "application/json"}
            headers.update(p.get("headers") or {})
            if p.get("auth"):
                if p["auth"].startswith("Bearer"):
                    headers["Authorization"] = p["auth"]
                elif "=" in p["auth"]:
                    k, _, v = p["auth"].partition("=")
                    headers[k.strip()] = v.strip()
            method = p.get("method", "GET")
            req = urllib.request.Request(url, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=p.get("timeout", 120)) as r:
                return r.read().decode("utf-8", "replace")[:8000]
        elif p["type"] == "python":
            code = p.get("code", "")
            ns = {"arg": arg}
            try:
                exec(code, ns)
                if callable(ns.get("run")):
                    return str(ns["run"](arg))[:8000]
                return "(python plugin has no run(arg))"
            except Exception as e:
                return "python plugin error: %s" % e
    except Exception as e:
        return "plugin error: %s" % e
    return "(no output)"


def plugin_exec(name, arg="", verbose=True):
    plugins = plugin_load()
    p = next((x for x in plugins if x.get("name", "").lower() == name.lower()), None)
    if not p:
        if verbose:
            print("Plugin '%s' not found." % name)
        return None
    out = plugin_run(p, arg)
    if verbose:
        print("Plugin %s output:\n%s" % (name, out[:2000]))
    return out


def ai_plugin_descriptions():
    plugins = plugin_load()
    if not plugins:
        return ""
    lines = ["Custom plugins available (call with PLUGIN: <name> arg):"]
    for p in plugins:
        lines.append("  - %s (%s): %s" % (p.get("name"), p.get("type"),
                                          p.get("description") or "custom tool"))
    return "\n".join(lines)


def cmd_plugin(args, interactive=True):
    if not args:
        print("Usage: profiler plugin [add|list|remove|run]")
        plugin_list()
        return
    sub = args[0].lower()
    if sub in ("add", "new", "create"):
        plugin_add(interactive)
    elif sub in ("list", "ls", "show"):
        plugin_list()
    elif sub in ("remove", "rm", "del", "delete"):
        if len(args) < 2:
            print("Usage: profiler plugin remove <name>")
            return
        plugin_remove(args[1], interactive)
    elif sub in ("run", "exec", "call"):
        if len(args) < 2:
            print("Usage: profiler plugin run <name> [arg]")
            return
        plugin_exec(args[1], " ".join(args[2:]))
    elif sub in ("help", "-h"):
        print("profiler plugin [add|list|remove <name>|run <name> <arg>]")
    else:
        plugin_exec(args[0], " ".join(args[1:]))


# --------------------------------------------------------------------------
# Shell access: run any terminal command (user-confirmed)
# --------------------------------------------------------------------------
def cmd_shell(args, interactive=True):
    if not args:
        print("Usage: profiler shell <command>")
        return
    cmd = " ".join(args)
    if interactive:
        r = input("Run shell command?\n  %s\n(y/N): " % cmd).strip().lower()
        if r not in ("y", "yes"):
            print("Cancelled.")
            return
    print("$ %s" % cmd)
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        print((out.stdout or "") + (out.stderr or "") or "(no output)")
    except Exception as e:
        print("shell error: %s" % e)


def ai_run_shell(cmd, interactive=True):
    """Run a shell command for the AI (with user confirmation)."""
    if interactive:
        r = input("AI wants to run shell command:\n  $ %s\nAllow? (y/N): " % cmd).strip().lower()
        if r not in ("y", "yes"):
            return "AI shell command rejected by user."
    print("$ %s" % cmd)
    try:
        out = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        return (out.stdout or "") + (out.stderr or "") or "(no output)"
    except Exception as e:
        return "shell error: %s" % e


def run_tool_capture(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return "tool error: %s" % e


def osint_deep_username(username):
    lines = []
    if tool_available("sherlock"):
        print("  [sherlock] running...")
        out = run_tool_capture(["sherlock", "--timeout", "5", username], timeout=300)
        hits = [ln.strip() for ln in out.splitlines()
                if "[-]" not in ln and ("[+]" in ln or "username" in ln.lower())]
        lines.extend(hits[:40] or ["(no hits)"])
    else:
        lines.append("sherlock not installed (pip3 install sherlock-project)")
    return [("Deep username recon (sherlock): %s" % username, lines)]


def osint_deep_email(email):
    lines = []
    if tool_available("holehe"):
        print("  [holehe] running...")
        out = run_tool_capture(["holehe", email], timeout=180)
        lines.extend([ln.strip() for ln in out.splitlines() if ln.strip()][:30])
    else:
        lines.append("holehe not installed (pip3 install holehe)")
    return [("Deep email check (holehe): %s" % email, lines)]


def osint_deep_domain(domain):
    lines = []
    if tool_available("subfinder"):
        print("  [subfinder] running...")
        out = run_tool_capture(["subfinder", "-silent", "-d", domain], timeout=180)
        subs = [ln.strip() for ln in out.splitlines() if ln.strip()]
        lines.extend(subs[:50] or ["(no subdomains found)"])
    else:
        lines.append("subfinder not installed (see https://github.com/projectdiscovery/subfinder)")
    return [("Deep subdomain enum (subfinder): %s" % domain, lines)]


def osint_deep_phone(phone):
    lines = []
    if tool_available("phoneinfoga"):
        print("  [phoneinfoga] running...")
        out = run_tool_capture(["phoneinfoga", "scan", "-n", phone], timeout=180)
        lines.extend([ln.strip() for ln in out.splitlines() if ln.strip()][:30])
    else:
        lines.append("phoneinfoga not installed (see https://github.com/sundowndev/phoneinfoga)")
    return [("Deep phone lookup (phoneinfoga): %s" % phone, lines)]


def cmd_osint_deep(pid):
    p = load(pid)
    print("Deep OSINT for %s (uses external tools if installed)..." % p["name"])
    tgts = profile_targets(p)
    results = []
    for u in tgts["usernames"]:
        results += osint_deep_username(u)
    for em in tgts["emails"]:
        results += osint_deep_email(em)
    for dm in tgts["domains"]:
        results += osint_deep_domain(dm)
    for ph in tgts["phones"]:
        results += osint_deep_phone(ph)
    if not results:
        print("Nothing to deep-enrich.")
        return
    run_osint_report(pid, results)
    print("\nDeep results appended to %s timeline." % p["name"])


# --------------------------------------------------------------------------
# Reverse image search
# --------------------------------------------------------------------------
def cmd_image_search(query, pid=None):
    q = urllib.parse.quote(query)
    url = ("https://www.bing.com/images/search?q=%s&form=HDRSC2" % q)
    page = http_get(url, timeout=15)
    if not page:
        print("Image search failed (network blocked?).")
        return
    urls = re.findall(r'm="(https?://[^"]+)"', page)
    seen = set()
    lines = []
    for u in urls:
        u = u.replace("&amp;", "&").replace("\\u0026", "&")
        if u in seen:
            continue
        seen.add(u)
        lines.append(u)
    if not lines:
        print("No image results.")
        return
    print("Image search results for '%s':" % query)
    for i, u in enumerate(lines[:10], 1):
        print("  %d. %s" % (i, u))
    if pid:
        body = "Image search for '%s':\n%s" % (query, "\n".join(lines[:10]))
        add_record(pid, "osint", body)
        print("\nSaved to timeline.")


# --------------------------------------------------------------------------
# Case / timeline view (merged chronological dossier)
# --------------------------------------------------------------------------
def cmd_case(pid):
    p = load(pid)
    items = []
    for r in p.get("records", []):
        items.append((r.get("ts") or "", r.get("type", ""), r.get("content", "")))
    for loc in p.get("locations", []):
        items.append((loc.get("ts") or "", "location",
                      "Location: %s (%s, %s) %s" % (
                          loc.get("place", ""), loc.get("lat", ""),
                          loc.get("lon", ""), loc.get("map", ""))))
    for rm in p.get("reminders", []):
        items.append((rm.get("ts") or "", "reminder",
                      "Reminder: %s (due %s%s)" % (
                          rm.get("content", ""), rm.get("due", ""),
                          "" if rm.get("done") else " [pending]")))
    items.sort(key=lambda x: x[0])
    print("\nCASE FILE: %s  (ID: %s)" % (p["name"], p["id"]))
    print("=" * 50)
    print("  %s" % p.get("occupation", ""))
    print("  Phone: %s   Email: %s   Address: %s" % (
        p.get("phone", ""), p.get("email", ""), p.get("address", "")))
    print("  Tags: %s" % ", ".join(p.get("tags", [])))
    print("-" * 50)
    if not items:
        print("  (no timeline entries)")
    for ts, typ, content in items:
        if ts:
            print("  [%s] %s" % (ts[:16], typ))
        else:
            print("  [--] %s" % typ)
        for ln in content.splitlines():
            print("      %s" % ln[:180])
    print("=" * 50)


# --------------------------------------------------------------------------
# HTML/PDF report generation
# --------------------------------------------------------------------------
def cmd_report(pid, fmt="html", out_path=None):
    p = load(pid)
    esc = lambda s: (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    html = []
    html.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
    html.append("<title>%s - PROFILER Dossier</title>" % esc(p["name"]))
    html.append("<style>body{font-family:sans-serif;margin:40px;color:#222}"
                "h1{border-bottom:3px solid #333}table{border-collapse:collapse;width:100%}"
                "th,td{border:1px solid #999;padding:6px;text-align:left}th{background:#eee}"
                ".meta{background:#f6f6f6;padding:10px}</style></head><body>")
    html.append("<h1>%s</h1>" % esc(p["name"]))
    html.append("<div class='meta'><b>ID:</b> %s<br>" % esc(p["id"]))
    for f in ("occupation", "employer", "phone", "email", "address", "dob",
              "status", "threat", "relation"):
        if p.get(f):
            html.append("<b>%s:</b> %s<br>" % (f.title(), esc(str(p.get(f)))))
    html.append("<b>Tags:</b> %s</div>" % esc(", ".join(p.get("tags", []))))
    if p.get("aliases"):
        html.append("<p><b>Aliases:</b> %s</p>" % esc(", ".join(p["aliases"])))
    if p.get("notes"):
        html.append("<p><b>Notes:</b> %s</p>" % esc(p["notes"]))

    html.append("<h2>Records</h2><table><tr><th>When</th><th>Type</th><th>Content</th></tr>")
    for r in sorted(p.get("records", []), key=lambda r: r.get("ts") or ""):
        html.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc((r.get("ts") or "")[:16]), esc(r.get("type", "")),
            esc(r.get("content", "")).replace("\n", "<br>")))
    html.append("</table>")

    if p.get("links"):
        html.append("<h2>Links</h2><table><tr><th>Profile</th><th>Type</th></tr>")
        for ln in p["links"]:
            html.append("<tr><td>%s</td><td>%s</td></tr>" % (
                esc(ln.get("target", "")), esc(ln.get("type", ""))))
        html.append("</table>")

    if p.get("locations"):
        html.append("<h2>Locations</h2><table><tr><th>Place</th><th>Coords</th><th>Map</th></tr>")
        for loc in p["locations"]:
            html.append("<tr><td>%s</td><td>%s,%s</td><td><a href='%s'>map</a></td></tr>" % (
                esc(loc.get("place", "")), esc(loc.get("lat", "")),
                esc(loc.get("lon", "")), esc(loc.get("map", ""))))
        html.append("</table>")

    if p.get("reminders"):
        html.append("<h2>Reminders</h2><table><tr><th>Due</th><th>Content</th></tr>")
        for rm in p["reminders"]:
            html.append("<tr><td>%s</td><td>%s</td></tr>" % (
                esc(rm.get("due", "")), esc(rm.get("content", ""))))
        html.append("</table>")
    html.append("</body></html>")
    content = "\n".join(html)

    if not out_path:
        d = os.path.join(BASE, "reports")
        os.makedirs(d, exist_ok=True)
        out_path = os.path.join(d, "%s.%s" % (p["id"], fmt))
    if fmt == "pdf":
        pdf = None
        if tool_available("wkhtmltopdf"):
            pdf = run_tool_capture(["wkhtmltopdf", "-q", "-", out_path],
                                   timeout=120)
        elif tool_available("pandoc"):
            with open(out_path + ".html", "w", encoding="utf-8") as f:
                f.write(content)
            run_tool_capture(["pandoc", out_path + ".html", "-o", out_path], timeout=120)
            os.remove(out_path + ".html")
        if not pdf and not os.path.exists(out_path):
            print("PDF converter not installed. Saved HTML instead: %s" % out_path + ".html")
            with open(out_path + ".html", "w", encoding="utf-8") as f:
                f.write(content)
            return
    else:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(content)
    print("Report saved: %s" % out_path)


# --------------------------------------------------------------------------
# Phone contacts import (termux-contact-list)
# --------------------------------------------------------------------------
def cmd_import_contacts():
    if not tool_available("termux-contact-list"):
        print("termux-contact-list not found. Install termux-api package.")
        return
    print("Fetching contacts from phone...")
    out = run_tool_capture(["termux-contact-list"], timeout=30)
    try:
        data = json.loads(out)
    except Exception:
        print("Could not parse contacts. Is termux-api installed and permitted?")
        return
    created = 0
    for c in data:
        name = c.get("name") or ""
        if not name.strip():
            continue
        pid = unique_id(name)
        p = load(pid)
        if p:
            continue
        new_p = {
            "id": pid, "name": name, "aliases": [], "phone": "", "email": "",
            "address": "", "occupation": "", "employer": "", "dob": "",
            "status": "active", "threat": "none", "relation": "contact",
            "tags": [], "notes": "", "records": [], "links": [],
            "photos": [], "locations": [], "reminders": [],
        }
        for ph in c.get("numbers", []):
            num = ph.get("number") or ""
            if num:
                new_p["phone"] = num
                break
        for em in c.get("emails", []):
            if em.get("email"):
                new_p["email"] = em["email"]
                break
        new_p["created_at"] = new_p["updated_at"] = now_iso()
        save(pid, new_p)
        created += 1
    print("Imported %d contact(s)." % created)


# --------------------------------------------------------------------------
# Recurring OSINT + change log
# --------------------------------------------------------------------------
OSINT_STATE = os.path.join(BASE, "osint-state.json")


def _osint_state():
    try:
        with open(OSINT_STATE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _osint_save_state(st):
    try:
        with open(OSINT_STATE, "w", encoding="utf-8") as f:
            json.dump(st, f)
    except Exception:
        pass


def cmd_osint_schedule(pid, freq="daily"):
    st = _osint_state()
    st["next"] = {}
    import datetime
    today = datetime.date.today().isoformat()
    if freq in ("daily", "weekly", "monthly"):
        st["next"][pid] = {"freq": freq, "last": today}
    _osint_save_state(st)
    print("Recurring OSINT scheduled: %s (%s)." % (freq, pid))
    print("Run 'profiler osint --due' to process any that are due.")


def cmd_osint_due(interactive=True):
    st = _osint_state()
    import datetime
    today = datetime.date.today()
    due = []
    for pid, info in st.get("next", {}).items():
        last = info.get("last") or ""
        freq = info.get("freq", "daily")
        days = {"daily": 1, "weekly": 7, "monthly": 30}.get(freq, 1)
        try:
            last_d = datetime.date.fromisoformat(last)
        except Exception:
            last_d = today - datetime.timedelta(days=days + 1)
        if (today - last_d).days >= days:
            due.append(pid)
    if not due:
        print("No OSINT runs are due.")
        return
    for pid in due:
        print("Running due OSINT for %s..." % pid)
        # capture previous record count for change log
        prev = len(load(pid).get("records", []))
        cmd_osint(pid, None, interactive)
        after = len(load(pid).get("records", []))
        st["next"][pid]["last"] = today.isoformat()
        _osint_save_state(st)
        log = _osint_state().get("log", [])
        log.append({"pid": pid, "ts": now_iso(), "added": after - prev})
        st2 = _osint_state()
        st2["log"] = log
        _osint_save_state(st2)
        print("  -> %d new record(s)." % (after - prev))


def cmd_osint_changelog():
    st = _osint_state()
    log = st.get("log", [])
    if not log:
        print("No OSINT change log yet.")
        return
    print("OSINT change log (most recent first):")
    for e in reversed(log[-20:]):
        print("  %s  %s  +%d records" % (e.get("ts", ""), e.get("pid", ""),
                                         e.get("added", 0)))


# --------------------------------------------------------------------------
# Smart dedup / merge
# --------------------------------------------------------------------------
def profile_signature(p):
    sigs = set()
    for em in (p.get("email") or "").split(","):
        em = em.strip().lower()
        if "@" in em:
            sigs.add("email:" + em)
    for ph in (p.get("phone") or "").split(","):
        ph = re.sub(r"[^\d]", "", ph)
        if len(ph) >= 7:
            sigs.add("phone:" + ph)
    for a in p.get("aliases", []):
        cu = clean_username(a)
        if cu:
            sigs.add("alias:" + cu)
    nm = (p.get("name") or "").strip().lower()
    if nm:
        sigs.add("name:" + nm)
    return sigs


def find_duplicates():
    sig_map = {}
    for pid in list_pids():
        p = load(pid)
        for s in profile_signature(p):
            sig_map.setdefault(s, []).append(pid)
    dupes = []
    seen_pairs = set()
    for s, pids in sig_map.items():
        pids = sorted(set(pids))
        for i in range(len(pids)):
            for j in range(i + 1, len(pids)):
                a, b = pids[i], pids[j]
                pair = (min(a, b), max(a, b))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    dupes.append((a, b, s))
    return dupes


def cmd_dedup(interactive=True):
    dupes = find_duplicates()
    if not dupes:
        print("No duplicates detected.")
        return
    print("Potential duplicates (sharing email/phone/alias/name):")
    for a, b, s in dupes:
        pa, pb = load(a), load(b)
        print("  %s  <->  %s   (shared: %s)" % (pa["name"], pb["name"], s))
    if interactive:
        r = prompt("Merge all into first? [y/N]")
        if r.lower() in ("y", "yes"):
            done = set()
            for a, b, s in dupes:
                if a in done or b in done:
                    continue
                cmd_merge(a, b)
                done.add(a)
                done.add(b)
            print("Merged duplicates.")


def cmd_merge(a, b, interactive=False):
    pa, pb = load(a), load(b)
    if not pa or not pb:
        print("One of the profiles not found.")
        return
    main, other = (a, b) if len(pa.get("records", [])) >= len(pb.get("records", [])) else (b, a)
    pm, po = load(main), load(other)
    for r in po.get("records", []):
        if r not in pm.get("records", []):
            pm["records"].append(r)
    for loc in po.get("locations", []):
        if loc not in pm.get("locations", []):
            pm["locations"].append(loc)
    for rm in po.get("reminders", []):
        if rm not in pm.get("reminders", []):
            pm["reminders"].append(rm)
    for ph in po.get("links", []):
        if ph not in pm.get("links", []):
            pm["links"].append(ph)
    for t in po.get("tags", []):
        if t not in pm.get("tags", []):
            pm["tags"].append(t)
    if not pm.get("phone") and po.get("phone"):
        pm["phone"] = po["phone"]
    if not pm.get("email") and po.get("email"):
        pm["email"] = po["email"]
    for a_ in po.get("aliases", []):
        if a_ not in pm.get("aliases", []):
            pm["aliases"].append(a_)
    pm["updated_at"] = now_iso()
    save(main, pm)
    delete_profile(other, False)
    print("Merged '%s' into '%s'." % (po["name"], pm["name"]))


# --------------------------------------------------------------------------
# Command engine
# --------------------------------------------------------------------------
def print_commands():
    out(BANNER)
    print("  profiles / list / ls / all              list all profiles (numbered)")
    print("  profile <name> / show <name>            open profile (view/edit/delete)")
    print("  show <cat> <name> [nums]                show a category")
    print("  new <name> phone: X email: Y tags: a,b  create profile")
    print("  edit <name>.<field> <value>             edit a field")
    print("  record <name> [--type X] [--content T]  add timeline record")
    print("  link <a> <b> [--type ally]              connect two profiles")
    print("  graph / network / connections           relationship graph")
    print("  osint <name> [--target ip|domain|email]   auto-enrich + single-target scan")
    print("  contacts <name>                        scrape found profiles for contact info")
    print("  deep <name>                            deep OSINT (sherlock/holehe/subfinder/phoneinfoga)")
    print("  image <query>                          reverse image search (Bing)")
    print("  case <name>                            chronological dossier view")
    print("  report <name> [--format html|pdf]      generate dossier report")
    print("  schedule-osint <name> [--freq daily|weekly|monthly]  recurring OSINT")
    print("  osint-due                              run due scheduled OSINT")
    print("  osint-log                              OSINT change log")
    print("  dedup / find-dupes                     detect duplicate profiles")
    print("  expand <name>                          identify + build related network (company/persons/subs)")
    print("  network <domain>                       scan website: DNS, TLS, ports, subdomains, IP")
    print("  network --wifi | --bluetooth           scan wifi/bluetooth networks (Termux)")
    print("  plugin [add|list|remove|run]           custom plugin system (usable by AI)")
    print("  merge <a> <b>                          merge two profiles")
    print("  import-contacts                        import phone contacts (termux-api)")
    print("  photo <name> [--file P | --camera]      add photo  |  <name> 1,3 = view")
    print("  view <name> [nums]                      view photos")
    print("  map <name> [nums]                       open locations in Google Maps")
    print("  locate <name> [--lat --lon --place | --gps]   log location")
    print("  remind <name> [--content X] [--due YYYY-MM-DD]")
    print("  reminders / todo                        upcoming reminders")
    print("  backup / save                           local backup")
    print("  export [--format json|csv] [--out F]    export")
    print("  import <file.json>                      import")
    print("  delete / del / rm <name>                delete profile")
    print("  rm record 1,3 / remove ph 2 / del loc 1 ...  remove items by number")
    print("  stats / status                          storage stats")
    print("  encrypt on|off / lock / unlock")
    print("  sync push|pull|check")
    print("  search <query>                          full-text search")
    print("  ask / ai <text>                         natural language assistant (built-in parser)")
    print("  ai config / ai status / ai on|off       custom AI provider (OpenAI-compatible API)")
    print("  websearch <query>                       search the web (DuckDuckGo)")
    print("  fetch <url>                             fetch a web page")
    print("  who <query>                             find profiles by employer/tag/name")
    print("  manage <name>                           interactive manage session")
    print("  help                                     show this help")
    print("  exit / quit / q                         exit")
    print("  Chain with: then  ;  and")


def run_command(text, ctx=None, interactive=True):
    if not text.strip():
        return "menu"
    parts = split_commands(text)
    last = "menu"
    for part in parts:
        last = run_one(part, ctx=ctx, interactive=interactive)
        if last in ("exit", "quit"):
            return last
    return last


def run_one(cmd, ctx=None, interactive=True):
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    if not toks:
        return "menu"
    w0 = toks[0].lower()
    rest = toks[1:]

    if w0 in ("exit", "quit", "q", "bye", "leave"):
        return "exit"
    if w0 in ("back", "menu", "home", "b", "main"):
        return "menu"
    if w0 in ("help", "?"):
        print_commands()
        return "menu"

    if w0 in ("profiles", "list", "ls", "all"):
        flags, _ = parse_flags(rest)
        cmd_list(status=flags.get("status"), tag=flags.get("tag"))
        return "menu"
    if w0 == "show":
        return cmd_show_smart(rest, ctx, interactive)
    if w0 == "profile":
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_manage(pid)
        return "menu"
    if w0 in ("new", "create", "add"):
        return cmd_add_smart(rest, ctx, interactive)
    if w0 == "edit":
        return cmd_edit_smart(rest, ctx, interactive)
    if w0 in ("record", "rec"):
        return cmd_record_smart(rest, ctx, interactive)
    if w0 in ("link", "connect"):
        return cmd_link_smart(rest, interactive)
    if w0 in ("graph", "network", "connections"):
        cmd_graph()
        return "menu"
    if w0 == "osint":
        return cmd_osint_smart(rest, ctx, interactive)
    if w0 in ("contacts", "scrape-contacts"):
        if not rest:
            print("Usage: contacts <query>")
            return "menu"
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_osint_contacts(pid)
        return "menu"
    if w0 in ("deep", "deep-osint"):
        if not rest:
            print("Usage: deep <query>")
            return "menu"
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_osint_deep(pid)
        return "menu"
    if w0 in ("image", "imgsearch", "img"):
        cmd_image_search(" ".join(rest), ctx)
        return "menu"
    if w0 == "case":
        if not rest:
            print("Usage: case <query>")
            return "menu"
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_case(pid)
        return "menu"
    if w0 == "report":
        flags, pos = parse_flags(rest)
        if not pos:
            print("Usage: report <query> [--format html|pdf]")
            return "menu"
        pid = resolve_profile(" ".join(pos), interactive)
        if pid:
            cmd_report(pid, fmt=(flags.get("format") or "html").lower(),
                       out_path=flags.get("out"))
        return "menu"
    if w0 in ("import-contacts", "contacts-import"):
        cmd_import_contacts()
        return "menu"
    if w0 in ("schedule-osint", "osint-schedule"):
        flags, pos = parse_flags(rest)
        if not pos:
            print("Usage: schedule-osint <query> [--freq daily|weekly|monthly]")
            return "menu"
        pid = resolve_profile(" ".join(pos), interactive)
        if pid:
            cmd_osint_schedule(pid, flags.get("freq") or "daily")
        return "menu"
    if w0 in ("osint-due", "osint-check"):
        cmd_osint_due(interactive)
        return "menu"
    if w0 in ("osint-log", "osint-changelog"):
        cmd_osint_changelog()
        return "menu"
    if w0 in ("dedup", "find-dupes"):
        cmd_dedup(interactive)
        return "menu"
    if w0 in ("expand", "explore"):
        if not rest:
            print("Usage: expand <name or word>")
            return "menu"
        cmd_expand(" ".join(rest), interactive)
        return "menu"
    if w0 in ("network", "scan"):
        cmd_network(rest, interactive)
        return "menu"
    if w0 in ("plugin", "plugins"):
        cmd_plugin(rest, interactive)
        return "menu"
    if w0 in ("shell", "sh", "terminal", "run"):
        cmd_shell(rest, interactive)
        return "menu"
    if w0 == "merge":
        if len(rest) < 2:
            print("Usage: merge <profileA> <profileB>")
            return "menu"
        pa = resolve_profile(rest[0], interactive)
        pb = resolve_profile(rest[1], interactive)
        if pa and pb and pa != pb:
            cmd_merge(pa, pb)
        return "menu"
    if w0 in ("photo", "pic"):
        return cmd_photo_smart(rest, ctx, interactive)
    if w0 in ("view", "pics", "photos"):
        return cmd_view_smart(rest, ctx, interactive)
    if w0 in ("map", "open-location"):
        return cmd_map_smart(rest, ctx, interactive)
    if w0 in ("locate", "gps", "loc", "track"):
        return cmd_locate_smart(rest, ctx, interactive)
    if w0 == "remind":
        return cmd_remind_smart(rest, ctx, interactive)
    if w0 in ("reminders", "todo", "tasks"):
        cmd_reminders()
        return "menu"
    if w0 in ("backup", "save"):
        cmd_backup()
        return "menu"
    if w0 == "export":
        flags, _ = parse_flags(rest)
        cmd_export(fmt=flags.get("format", "json"), out_path=flags.get("out"))
        return "menu"
    if w0 == "import":
        path = " ".join(rest) if rest else None
        if not path:
            if interactive:
                path = prompt("Import file")
            if not path:
                return "menu"
        cmd_import(path, interactive)
        return "menu"
    if w0 in ("delete", "del", "rm", "remove"):
        return cmd_delete_smart(rest, ctx, interactive)
    if w0 in ("stats", "status"):
        cmd_stats()
        return "menu"
    if w0 == "encrypt":
        mode = " ".join(rest).lower()
        if mode not in ("on", "off"):
            mode = "on" if not _encryption_enabled() else "off"
        cmd_encrypt(mode)
        return "menu"
    if w0 in ("lock", "unlock"):
        cmd_encrypt("on" if w0 == "lock" else "off")
        return "menu"
    if w0 == "sync":
        flags, pos = parse_flags(rest)
        cmd_sync(pos[0] if pos else None, interactive)
        return "menu"
    if w0 == "search":
        cmd_search(" ".join(rest))
        return "menu"
    if w0 in ("who", "who-at", "find-at"):
        cmd_who(" ".join(rest))
        return "menu"
    if w0 in ("websearch", "searchweb", "web"):
        cmd_websearch(" ".join(rest))
        return "menu"
    if w0 in ("fetch", "geturl"):
        cmd_fetch(" ".join(rest))
        return "menu"
    if w0 in ("ask", "ai", "assistant", "brain"):
        if w0 == "ai":
            cmd_ai(rest, interactive)
            return "menu"
        if rest:
            return cmd_ask(" ".join(rest), interactive)
        if interactive:
            return ai_chat()
        print("Usage: ask <natural language text>")
        return "menu"
    if w0 == "manage":
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_manage(pid)
        return "menu"
    if w0 == "show-field":
        return cmd_show_field_smart(rest, interactive)

    pid = resolve_profile(" ".join(toks), interactive)
    if pid:
        cmd_manage(pid)
        return "menu"
    print("Unknown command: %s  (try 'help')" % w0)
    return "menu"


def cmd_show_smart(toks, ctx, interactive):
    if not toks:
        if ctx:
            display_profile(load(ctx))
            return "menu"
        print("Usage: show <name>  |  show <category> <name> [nums]")
        return "menu"
    t0 = toks[0].lower()
    cat = norm_cat(t0)
    if cat:
        pid = ctx
        nums = []
        if len(toks) >= 2 and re.fullmatch(r"[\d,\s/]+", toks[1]):
            nums = parse_nums(" ".join(toks[1:]))
        elif len(toks) >= 2:
            name = toks[1]
            nums = parse_nums(" ".join(toks[2:]))
            pid = resolve_profile(name, interactive) if name else ctx
        if not pid and interactive:
            pid = choose_profile("Show %s for" % cat)
        if pid:
            cmd_show_field(cat, pid, nums)
        return "menu"
    pid = resolve_profile(" ".join(toks), interactive)
    if pid:
        display_profile(load(pid))
    return "menu"


def cmd_show_field_smart(toks, interactive):
    if len(toks) < 2:
        print("Usage: show-field <category> <name> [--numbers 1,3]")
        return "menu"
    flags, pos = parse_flags(toks[2:])
    cat = norm_cat(toks[0])
    if not cat:
        print("Unknown category: %s" % toks[0])
        return "menu"
    pid = resolve_profile(toks[1], interactive)
    if pid:
        nums = parse_nums(str(flags.get("numbers", "")))
        cmd_show_field(cat, pid, nums)
    return "menu"


def cmd_add_smart(toks, ctx, interactive):
    low = [t.lower() for t in toks]
    if low and low[0] == "add" and len(toks) > 1 and low[1] in ("photo", "pic", "image", "camera", "record", "rec", "link", "reminder", "remind", "todo"):
        if low[1] in ("record", "rec"):
            return run_one("record " + " ".join(toks[2:]), ctx=ctx, interactive=interactive)
        if low[1] in ("reminder", "remind", "todo"):
            return run_one("remind " + " ".join(toks[2:]), ctx=ctx, interactive=interactive)
        if low[1] in ("link",):
            return run_one("link " + " ".join(toks[2:]), ctx=ctx, interactive=interactive)
        return run_one("photo " + " ".join(toks[2:]), ctx=ctx, interactive=interactive)
    fields, pos = parse_kv(toks[1:] if low and low[0] in ("new", "create", "add") else toks)
    name = fields.pop("name", None) or " ".join(pos).strip()
    if not name:
        if interactive:
            add_profile_form()
            return "menu"
        print("Usage: new <name> phone: X email: Y tags: a,b")
        return "menu"
    pid = new_profile(name, **fields)
    print("Profile '%s' created.  ID: %s" % (name, pid))
    return "menu"


def cmd_edit_smart(toks, ctx, interactive):
    if not toks:
        if interactive:
            pid = ctx or choose_profile("Edit")
            if not pid:
                return "menu"
            field = prompt("Field to edit")
            value = prompt("New value")
            apply_edit(pid, field, value, interactive)
        else:
            print("Usage: edit <profile> <field> <value>  |  --field X [--value Y]")
        return "menu"
    text = " ".join(toks)
    m = re.match(r"^([^\s.]+)\.([\w-]+)(?:\s+(.*))?$", text)
    if m:
        pid = resolve_profile(m.group(1), interactive)
        if pid:
            apply_edit(pid, norm_field(m.group(2)) or m.group(2), m.group(3), interactive)
        return "menu"
    m = re.match(r"^([^\s/]+)/([\w-]+)$", text)
    if m:
        pid = resolve_profile(m.group(1), interactive)
        if pid:
            apply_edit(pid, norm_field(m.group(2)) or m.group(2), None, interactive)
        return "menu"
    f = norm_field(toks[0])
    if f:
        value = " ".join(toks[1:]) or None
        pid = ctx
        if not pid:
            if interactive:
                pid = choose_profile("Edit %s for" % f)
            if not pid:
                return "menu"
        apply_edit(pid, f, value, interactive)
        return "menu"
    pid = resolve_profile(toks[0], interactive)
    if not pid:
        return "menu"
    if len(toks) == 1:
        field = prompt("Field to edit") if interactive else None
        value = prompt("New value") if interactive else None
        apply_edit(pid, field, value, interactive)
    elif len(toks) == 2:
        apply_edit(pid, norm_field(toks[1]) or toks[1], None, interactive)
    else:
        apply_edit(pid, norm_field(toks[1]) or toks[1], " ".join(toks[2:]), interactive)
    return "menu"


def cmd_record_smart(toks, ctx, interactive):
    flags, pos = parse_flags(toks)
    rtype = flags.get("type")
    content = flags.get("content")
    pid = ctx
    if ctx is None:
        if pos:
            pid = resolve_profile(pos[0], interactive)
            if not pid:
                return "menu"
            pos = pos[1:]
        else:
            pid = choose_profile("Add record to") if interactive else None
            if not pid:
                return "menu"
    if pos:
        t = norm_record_type(pos[0])
        if t or pos[0].lower() in RECORD_ALIASES:
            rtype = t or rtype
            content = " ".join(pos[1:]) or content
        else:
            if not content:
                content = " ".join(pos)
    if not rtype and interactive:
        rtype = prompt("Record type", "note")
    if not content and interactive:
        content = prompt("Content")
    if not content:
        print("Empty record not saved.")
        return "menu"
    rtype = norm_record_type(rtype or "note") or "other"
    add_record(pid, rtype, content)
    print("Record added to %s." % load(pid)["name"])
    return "menu"


def _try_resolve(q, interactive):
    q = (q or "").strip()
    if not q:
        return None
    if q.isdigit() and interactive:
        rows = numbered_profiles()
        n = int(q)
        if 1 <= n <= len(rows):
            return rows[n - 1][1]
    c = find_profiles(q)
    return c[0] if len(c) == 1 else None


def cmd_link_smart(toks, interactive):
    flags, pos = parse_flags(toks)
    rtype = norm_relation(flags.get("type") or "ally") or "ally"
    if len(pos) < 2:
        if interactive:
            a = choose_profile("Link profile A")
            b = choose_profile("Link profile B")
            if not a or not b:
                return "menu"
            if a == b:
                print("Cannot link a profile to itself.")
                return "menu"
            link_profiles(a, b, rtype)
        else:
            print("Usage: link <a> <b> [--type ally]")
        return "menu"
    a = b = None
    for k in range(1, len(pos)):
        ta = _try_resolve(" ".join(pos[:k]), interactive)
        tb = _try_resolve(" ".join(pos[k:]), interactive)
        if ta and tb and ta != tb:
            a, b = ta, tb
            break
    if not a or not b:
        a = resolve_profile(pos[0], interactive)
        b = resolve_profile(pos[1], interactive)
    if not a or not b:
        return "menu"
    if a == b:
        print("Cannot link a profile to itself.")
        return "menu"
    link_profiles(a, b, rtype)
    return "menu"


def cmd_osint_smart(toks, ctx, interactive):
    flags, pos = parse_flags(toks)
    target = flags.get("target")
    if pos:
        pid = resolve_profile(pos[0], interactive)
    elif ctx:
        pid = ctx
    else:
        pid = choose_profile("OSINT for") if interactive else None
    if not pid:
        return "menu"
    cmd_osint(pid, target, interactive)
    return "menu"


def cmd_photo_smart(toks, ctx, interactive):
    flags, pos = parse_flags(toks)
    name = flags.get("name") or (pos[0] if pos else None)
    nums = parse_nums(" ".join(pos[1:])) if pos else []
    if not name and ctx:
        name = ctx
    if not name:
        pid = choose_profile("Photo for") if interactive else None
        if not pid:
            return "menu"
    else:
        pid = resolve_profile(str(name), interactive)
        if not pid:
            return "menu"
    if nums:
        cmd_view(pid, nums)
        return "menu"
    if flags.get("file"):
        cmd_photo_add(pid, str(flags["file"]))
        return "menu"
    if flags.get("camera"):
        cmd_photo_camera(pid)
        return "menu"
    if interactive:
        print("  1. File path  2. Camera  3. View photos")
        r = prompt("Choose")
        if r == "1":
            path = prompt("Path to image")
            if path:
                cmd_photo_add(pid, path)
        elif r == "2":
            cmd_photo_camera(pid)
        elif r == "3":
            cmd_view(pid)
    else:
        print("Usage: photo <name> --file P | --camera | <name> 1,3")
    return "menu"


def cmd_view_smart(toks, ctx, interactive):
    flags, pos = parse_flags(toks)
    name = flags.get("name") or (pos[0] if pos else None)
    nums = parse_nums(" ".join(pos[1:])) if pos else []
    if not name and ctx:
        name = ctx
    if not name:
        pid = choose_profile("View photos of") if interactive else None
        if not pid:
            return "menu"
    else:
        pid = resolve_profile(str(name), interactive)
        if not pid:
            return "menu"
    cmd_view(pid, nums)
    return "menu"


def cmd_map_smart(toks, ctx, interactive):
    flags, pos = parse_flags(toks)
    name = flags.get("name") or (pos[0] if pos else None)
    nums = parse_nums(" ".join(pos[1:])) if pos else []
    if not name and ctx:
        name = ctx
    if not name:
        pid = choose_profile("Map locations of") if interactive else None
        if not pid:
            return "menu"
    else:
        pid = resolve_profile(str(name), interactive)
        if not pid:
            return "menu"
    p = load(pid)
    locs = p.get("locations", [])
    if not locs:
        print("No locations for %s." % p["name"])
        return "menu"
    sel = [locs[i - 1] for i in nums if 1 <= i <= len(locs)] if nums else locs
    if not sel:
        print("No locations match those numbers.")
        return "menu"
    for x in sel:
        print("Opening %s %s" % (x.get("place") or "unknown", x.get("map", "")))
        open_url(x.get("map", ""))
    return "menu"


def cmd_locate_smart(toks, ctx, interactive):
    flags, pos = parse_flags(toks)
    name = flags.get("name") or (pos[0] if pos else None)
    nums = parse_nums(" ".join(pos[1:])) if pos else []
    if not name and ctx:
        name = ctx
    if not name:
        pid = choose_profile("Log location for") if interactive else None
        if not pid:
            return "menu"
    else:
        pid = resolve_profile(str(name), interactive)
        if not pid:
            return "menu"
    if nums:
        cmd_map_smart(["%s %s" % (name, " ".join(pos[1:]))] if name else [str(pid)], ctx, interactive) if False else None
        p = load(pid)
        locs = p.get("locations", [])
        sel = [locs[i - 1] for i in nums if 1 <= i <= len(locs)] if nums else locs
        for x in sel:
            print("Opening %s %s" % (x.get("place") or "unknown", x.get("map", "")))
            open_url(x.get("map", ""))
        return "menu"
    lat, lon = flags.get("lat"), flags.get("lon")
    if lat and lon:
        place = flags.get("place")
        if not place and interactive:
            place = reverse_geocode(lat, lon) or prompt("Place name") or ""
        add_location(pid, lat, lon, place or "")
    else:
        gps_location(pid, manual=interactive)
    return "menu"


def cmd_remind_smart(toks, ctx, interactive):
    flags, pos = parse_flags(toks)
    name = flags.get("name") or (pos[0] if pos else None)
    if not name and ctx:
        name = ctx
    if not name:
        pid = choose_profile("Reminder for") if interactive else None
        if not pid:
            return "menu"
    else:
        pid = resolve_profile(str(name), interactive)
        if not pid:
            return "menu"
    cmd_remind(pid, flags.get("content") or "", flags.get("due") or "")
    return "menu"


# --------------------------------------------------------------------------
# Manage session (interactive profile editor)
# --------------------------------------------------------------------------
def normalize_manage(raw):
    low = raw.strip().lower()
    words = low.split()
    if not words:
        return None
    w0 = words[0]
    if w0 == "a":
        return "record"
    if w0 == "e":
        return "edit"
    if w0 == "r":
        return "rm record"
    if w0 == "p":
        return "rm photo"
    if w0 == "l":
        return "rm location"
    if w0 == "m":
        return "rm reminder"
    if w0 == "k":
        return "rm link"
    if w0 == "d":
        return "delete profile"
    if w0 in ("gps", "track", "locate"):
        return "locate " + " ".join(words[1:])
    if w0 == "add":
        if len(words) >= 2 and words[1] in ("reminder", "remind", "todo"):
            return "remind"
        if len(words) >= 2 and words[1] in ("photo", "pic", "image", "camera"):
            return "photo"
        if len(words) >= 2 and words[1] in ("link", "connect"):
            return "link"
        if len(words) >= 2 and words[1] in ("record", "rec"):
            return "record"
        return "record"
    if w0 in ("remind", "reminder"):
        return "remind " + " ".join(words[1:])
    if w0 in ("photo", "camera"):
        return "photo " + " ".join(words[1:])
    if w0 == "link":
        return "link " + " ".join(words[1:])
    if w0 == "delete":
        return "delete profile"
    return raw


def cmd_manage(pid):
    set_completions(manage_words())
    while True:
        clear_screen()
        p = load(pid)
        display_profile(p)
        print("\n  Actions: a=add record  e=edit  r=rm record  p=rm photo  l=rm loc")
        print("           m=rm rem  k=rm link  d=delete  gps=locate  remind  photo  link  show")
        try:
            raw = input("Action: ").strip()
        except (KeyboardInterrupt, EOFError):
            return "menu"
        if not raw:
            continue
        if raw.lower() in ("b", "back", "menu", "main", "exit", "quit", "q", "home"):
            return "menu"
        norm = normalize_manage(raw)
        try:
            run_command(norm, ctx=pid)
        except KeyboardInterrupt:
            continue
        except Exception as e:
            print("Error: %s" % e)


# --------------------------------------------------------------------------
# Interactive app
# --------------------------------------------------------------------------
def add_profile_form():
    print("\nCreating new profile -- Enter skips a field, c cancels.")
    name = prompt("Name")
    if not name or is_cancel(name):
        print("Cancelled.")
        return
    pid = unique_id(name)
    p = {
        "id": pid, "name": name, "aliases": [], "phone": "", "email": "",
        "address": "", "occupation": "", "employer": "", "dob": "",
        "status": "active", "threat": "none", "relation": "unknown",
        "tags": [], "notes": "", "records": [], "links": [],
        "photos": [], "locations": [], "reminders": [],
    }
    p["created_at"] = p["updated_at"] = now_iso()
    for label, field in (
        ("Aliases (comma-sep)", "aliases"), ("Phone", "phone"), ("Email", "email"),
        ("Address", "address"), ("Occupation", "occupation"), ("Employer", "employer"),
        ("DOB (YYYY-MM-DD)", "dob"), ("Status", "status"), ("Threat", "threat"),
        ("Relation", "relation"), ("Tags (comma-sep)", "tags"), ("Notes", "notes"),
    ):
        v = prompt(label)
        if is_cancel(v):
            print("Cancelled.")
            return
        if v:
            set_field(p, field, v)
    save(pid, p)
    print("Profile '%s' created.  ID: %s" % (name, pid))


def open_profile_from_list():
    cmd_list()
    r = prompt("Open profile (number or name) [Enter to cancel]")
    if r:
        pid = resolve_profile(r, True)
        if pid:
            cmd_manage(pid)


def delete_picker():
    cmd_list()
    r = prompt("Delete profile (number or name) [Enter to cancel]")
    if r:
        pid = resolve_profile(r, True)
        if pid:
            delete_profile(pid, True)


def menu_action(n):
    if n == 1:
        open_profile_from_list()
    elif n == 2:
        add_profile_form()
    elif n == 3:
        pid = choose_profile("Open profile")
        if pid:
            cmd_manage(pid)
    elif n == 4:
        pid = choose_profile("Add record to")
        if pid:
            cmd_record_smart([], pid, True)
    elif n == 5:
        cmd_link_smart([], True)
    elif n == 6:
        cmd_graph()
    elif n == 7:
        pid = choose_profile("OSINT for")
        if pid:
            cmd_osint(pid, None, True)
    elif n == 8:
        pid = choose_profile("Photo for")
        if pid:
            cmd_photo_smart([], pid, True)
    elif n == 9:
        pid = choose_profile("Log location for")
        if pid:
            gps_location(pid, manual=True)
    elif n == 10:
        pid = choose_profile("Reminder for")
        if pid:
            cmd_remind(pid)
    elif n == 11:
        cmd_reminders()
    elif n == 12:
        cmd_backup()
    elif n == 13:
        fmt = (prompt("Export format (json/csv)", "json") or "json").lower()
        cmd_export(fmt)
    elif n == 14:
        path = prompt("Import file")
        if path:
            cmd_import(path, True)
    elif n == 15:
        delete_picker()
    elif n == 16:
        cmd_stats()
    elif n == 17:
        cmd_encrypt("off" if _encryption_enabled() else "on")
    elif n == 18:
        cmd_sync(None, True)
    elif n == 19:
        pid = choose_profile("View photos of")
        if pid:
            cmd_view(pid)
    elif n == 20:
        cmd_ai([], True)
    elif n == 21:
        ai_configure(True)
    elif n == 0:
        return "exit"
    return "menu"


def app_words():
    words = (["exit", "quit", "menu", "back", "help"] + list(COMMANDS)
             + list(FIELD_ALIASES) + list(CATEGORY_ALIASES)
             + RECORD_TYPES + RELATIONS + THREATS
             + ["push", "pull", "check", "json", "csv", "on", "off", "file", "camera",
                "websearch", "fetch", "ask", "ai"])
    for pid in list_pids():
        p = load(pid)
        words += [p["name"], pid] + list(p["aliases"])
    return sorted(set(w for w in words if w))


def manage_words():
    return app_words() + ["a", "e", "r", "p", "l", "m", "k", "d", "b", "gps", "track"]


def set_completions(words):
    try:
        try:
            import readline
        except ImportError:
            if os.name == "nt":
                try:
                    import pyreadline3 as readline
                except ImportError:
                    try:
                        import pyreadline as readline
                    except ImportError:
                        readline = None
            else:
                readline = None
        if readline is None:
            return
        def completer(text, state):
            opts = [w for w in words if w.lower().startswith(text.lower())]
            return opts[state] if state < len(opts) else None
        readline.set_completer(completer)
        readline.set_completer_delims(" \t\n;")
        try:
            if "libedit" in readline.__doc__ or "editline" in readline.__doc__:
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
        except Exception:
            try:
                readline.parse_and_bind("tab: complete")
            except Exception:
                pass
    except Exception:
        pass


def app_menu():
    while True:
        clear_screen()
        print(BANNER)
        print("PROFILES IN DATABASE: %d\n" % len(list_pids()))
        items = [
            "List profiles", "Add profile", "Open profile", "Add record",
            "Link profiles", "Relationship graph", "OSINT scan", "Photo",
            "Log location", "Set reminder", "Show reminders", "Backup",
            "Export (json/csv)", "Import", "Delete profile", "Stats",
            "Toggle encryption", "Sync with Google Drive", "View profile photos",
            "AI assistant (chat)", "Configure AI provider",
            "Exit",
        ]
        for i, label in enumerate(items, 1):
            print("  %d. %s" % (i, label))
        print()
        print("  Commands: ask <text>  |  websearch <q>  |  osint  |  new  |  help")
        print()
        set_completions(app_words())
        try:
            raw = input("Select/Command: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nSession saved. Goodbye.")
            return
        if not raw:
            continue
        if raw.isdigit():
            n = int(raw)
            r = menu_action(n)
            if r == "exit":
                print("\nSession saved. Goodbye.")
                return
            continue
        try:
            r = run_command(raw)
        except KeyboardInterrupt:
            continue
        except Exception as e:
            print("Error: %s" % e)
        if r == "exit":
            print("\nSession saved. Goodbye.")
            return


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def print_cli_usage():
    print(BANNER)
    print("Usage: profiler <subcommand> [args]")
    print("")
    print("  add <name> [--alias --phone --email --address --occupation")
    print("             --employer --dob --status --threat --relation --tags --notes]")
    print("  list [--status X] [--tag Y]")
    print("  show <query>")
    print("  search <query>")
    print("  show-field <category> <query> [--numbers 1,3]")
    print("  record <query> [--type X] [--content text]")
    print("  link <a> <b> [--type ally]")
    print("  graph")
    print("  photo <query> [--file P | --camera]")
    print("  view <query> [--numbers 1,3]")
    print("  open-location <query> [--numbers 1,3]")
    print("  locate <query> [--lat --lon --place | --gps]")
    print("  remind <query> [--content --due]")
    print("  reminders")
    print("  backup")
    print("  export [--format json|csv] [--out F]")
    print("  import <file.json>")
    print("  delete <query>")
    print("  edit <query> --field X [--value Y]")
    print("  manage <query>")
    print("  osint <query> [--target X]   no target = auto-enrich from profile data")
    print("  contacts <query>             scrape found profiles for phone/email/age/location")
    print("  deep <query>                 deep OSINT (sherlock/holehe/subfinder/phoneinfoga)")
    print("  image <query>                reverse image search (Bing)")
    print("  case <query>                 chronological dossier view")
    print("  report <query> [--format html|pdf] [--out F]  generate dossier report")
    print("  import-contacts              import from phone contacts (termux-contact-list)")
    print("  schedule-osint <query> [--freq daily|weekly|monthly]")
    print("  osint-due                    run due scheduled OSINT")
    print("  osint-log                    view OSINT change log")
    print("  dedup / find-dupes           detect duplicate profiles")
    print("  expand <name>                 identify + create related people/companies/subs")
    print("  network <domain>               scan website: DNS, TLS, ports, subdomains, IP")
    print("  network --wifi                 scan wifi networks (Termux)")
    print("  network --bluetooth            scan bluetooth devices (Termux)")
    print("  plugin [add|list|remove|run]   custom plugin system (usable by AI)")
    print("  merge <a> <b>                merge two profiles")
    print("  stats")
    print("  encrypt on|off")
    print("  sync push|pull|check")
    print("  ask <text>                   natural-language assistant")
    print("  ai [config|status|on|off|ask <text>]   custom AI provider (OpenAI-compatible)")
    print("  websearch <query> | fetch <url>   internet access")
    print("  -p <name>   quick-show a profile")
    print("  --help")


def dispatch_cli(args):
    cmd = args[0].lower()
    rest = args[1:]
    interactive = sys.stdin.isatty()

    if cmd in ("add", "new", "create"):
        fields, pos = parse_kv(rest)
        name = fields.pop("name", None) or " ".join(pos).strip()
        if not name:
            print("Usage: profiler add <name> [--phone X ...]")
            return
        pid = new_profile(name, **fields)
        print("Profile '%s' created.  ID: %s" % (name, pid))
        return
    if cmd == "list":
        flags, _ = parse_flags(rest)
        cmd_list(status=flags.get("status"), tag=flags.get("tag"))
        return
    if cmd == "show":
        if not rest:
            print("Usage: profiler show <name> | show <category> <name> [nums]")
            return
        cmd_show_smart(rest, None, interactive)
        return
    if cmd == "search":
        cmd_search(" ".join(rest))
        return
    if cmd == "show-field":
        cmd_show_field_smart(rest, interactive)
        return
    if cmd == "record":
        cmd_record_smart(rest, None, interactive)
        return
    if cmd == "link":
        cmd_link_smart(rest, interactive)
        return
    if cmd == "graph":
        cmd_graph()
        return
    if cmd == "photo":
        cmd_photo_smart(rest, None, interactive)
        return
    if cmd in ("view", "pics"):
        cmd_view_smart(rest, None, interactive)
        return
    if cmd in ("open-location", "map"):
        cmd_map_smart(rest, None, interactive)
        return
    if cmd == "locate":
        cmd_locate_smart(rest, None, interactive)
        return
    if cmd == "remind":
        cmd_remind_smart(rest, None, interactive)
        return
    if cmd in ("reminders", "todo"):
        cmd_reminders()
        return
    if cmd in ("backup", "save"):
        cmd_backup()
        return
    if cmd == "export":
        flags, _ = parse_flags(rest)
        fmt = (flags.get("format") or "json").lower()
        if fmt not in ("json", "csv"):
            print("Unknown format '%s'. Use json or csv." % fmt)
            return
        cmd_export(fmt, flags.get("out"))
        return
    if cmd == "import":
        if not rest:
            print("Usage: profiler import <file.json>")
            return
        cmd_import(rest[0], interactive)
        return
    if cmd in ("delete", "del", "rm", "remove"):
        cmd_delete_smart(rest, None, interactive)
        return
    if cmd == "edit":
        flags, pos = parse_flags(rest)
        query = " ".join(pos)
        field = flags.get("field")
        value = flags.get("value")
        if not query:
            print("Usage: profiler edit <query> --field X [--value Y]")
            return
        pid = resolve_profile(query, interactive)
        if pid:
            apply_edit(pid, field, value, interactive)
        return
    if cmd == "manage":
        if not rest:
            print("Usage: profiler manage <query>")
            return
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_manage(pid)
        return
    if cmd == "osint":
        cmd_osint_smart(rest, None, interactive)
        return
    if cmd in ("contacts", "scrape-contacts"):
        if not rest:
            print("Usage: profiler contacts <query>")
            return
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_osint_contacts(pid)
        return
    if cmd in ("deep", "deep-osint"):
        if not rest:
            print("Usage: profiler deep <query>")
            return
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_osint_deep(pid)
        return
    if cmd in ("image", "imgsearch", "img"):
        cmd_image_search(" ".join(rest), None)
        return
    if cmd == "case":
        if not rest:
            print("Usage: profiler case <query>")
            return
        pid = resolve_profile(" ".join(rest), interactive)
        if pid:
            cmd_case(pid)
        return
    if cmd == "report":
        flags, pos = parse_flags(rest)
        if not pos:
            print("Usage: profiler report <query> [--format html|pdf] [--out F]")
            return
        pid = resolve_profile(" ".join(pos), interactive)
        if pid:
            cmd_report(pid, fmt=(flags.get("format") or "html").lower(),
                       out_path=flags.get("out"))
        return
    if cmd in ("import-contacts", "contacts-import"):
        cmd_import_contacts()
        return
    if cmd in ("schedule-osint", "osint-schedule"):
        flags, pos = parse_flags(rest)
        if not pos:
            print("Usage: profiler schedule-osint <query> [--freq daily|weekly|monthly]")
            return
        pid = resolve_profile(" ".join(pos), interactive)
        if pid:
            cmd_osint_schedule(pid, flags.get("freq") or "daily")
        return
    if cmd in ("osint-due", "osint-check"):
        cmd_osint_due(interactive)
        return
    if cmd in ("osint-log", "osint-changelog"):
        cmd_osint_changelog()
        return
    if cmd in ("dedup", "find-dupes"):
        cmd_dedup(interactive)
        return
    if cmd in ("expand", "explore"):
        if not rest:
            print("Usage: profiler expand <name or word>")
            return
        cmd_expand(" ".join(rest), interactive)
        return
    if cmd in ("network", "scan"):
        cmd_network(rest, interactive)
        return
    if cmd in ("plugin", "plugins", "plugins-tool"):
        cmd_plugin(rest, interactive)
        return
    if cmd in ("shell", "sh", "terminal", "run"):
        cmd_shell(rest, interactive)
        return
    if cmd == "merge":
        if len(rest) < 2:
            print("Usage: profiler merge <profileA> <profileB>")
            return
        pa = resolve_profile(rest[0], interactive)
        pb = resolve_profile(rest[1], interactive)
        if pa and pb and pa != pb:
            cmd_merge(pa, pb)
        return
    if cmd == "stats":
        cmd_stats()
        return
    if cmd == "encrypt":
        mode = (rest[0] if rest else "").lower()
        if mode not in ("on", "off"):
            print("Usage: profiler encrypt on|off")
            return
        cmd_encrypt(mode)
        return
    if cmd == "sync":
        mode = (rest[0] if rest else "").lower()
        cmd_sync(mode if mode in ("push", "pull", "check") else None, interactive)
        return
    if cmd in ("ask", "ai", "assistant"):
        if cmd == "ai":
            cmd_ai(rest, interactive)
            return
        if rest:
            cmd_ask(" ".join(rest), interactive)
        elif interactive:
            ai_chat()
        else:
            print("Usage: profiler ask <natural language text>")
        return
    if cmd in ("who", "who-at", "find-at"):
        cmd_who(" ".join(rest))
        return
    if cmd in ("websearch", "searchweb", "web"):
        cmd_websearch(" ".join(rest))
        return
    if cmd in ("fetch", "geturl"):
        cmd_fetch(" ".join(rest))
        return
    print_cli_usage()


def main():
    args = sys.argv[1:]
    if not args:
        app_menu()
        return
    if args[0] in ("-p", "--profile"):
        if len(args) < 2:
            print("Usage: profiler -p <name>")
            return
        pid = resolve_profile(" ".join(args[1:]), True)
        if pid:
            display_profile(load(pid))
        return
    if args[0] in ("-h", "--help", "-v", "--version"):
        if args[0] in ("-v", "--version"):
            print("PROFILER v%s" % VERSION)
        else:
            print_cli_usage()
        return
    dispatch_cli(args)


if __name__ == "__main__":
    if not sys.stdout.isatty():
        try:
            sys.stdout.reconfigure(line_buffering=True)
        except Exception:
            pass
    try:
        ensure_dirs()
        main()
    except KeyboardInterrupt:
        print("\nSession saved. Goodbye.")
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
