#!/usr/bin/env python3
"""Log analyzer for ai_scores.log (overridable via --log).

Defaults to ai_scores.log (JSONL with fields: ts, dt, sess, nick, target,
msg, flag, scores: heu/bino/cls/llama). Also handles other common shapes:
  - IRC chat:   [HH:MM(:SS)] <nick> message    or    [HH:MM] * nick action
  - JSON Lines: {"timestamp": "...", ...}      (e.g. detections.log)
  - Syslog-ish: YYYY-MM-DD HH:MM:SS[,ms] [LEVEL] component: message

Usage:
  python analyzelog.py                                # ai_scores.log full report
  python analyzelog.py --log other.log
  python analyzelog.py --top 20
  python analyzelog.py --user cfuser                  # filter + LLM behavior analysis
  python analyzelog.py --user cfuser --no-llm

  # New batch modes:
  python analyzelog.py --batch --since 2024-01-01 --until 2024-02-01
  python analyzelog.py --batch --flagged "llama>0.8 heu>0.5"
  python analyzelog.py --batch --similar
  python analyzelog.py --batch --bursts cfuser
  python analyzelog.py --batch --diff other.log
  python analyzelog.py --batch --export-edges edges.csv
  python analyzelog.py --watch                        # live tail
"""

from __future__ import annotations

import argparse
import atexit
import cmd
import contextlib
import csv
import hashlib
import io
import itertools
import json
import math
import os
import pydoc
import re
import shlex
import shutil
import statistics
import sys
import threading
import time
import urllib.request
import urllib.error
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Sequence

try:
    import readline  # type: ignore[import-not-found]
except ImportError:
    readline = None  # type: ignore[assignment]


# ---------- parsing ----------------------------------------------------------

IRC_MSG_RE = re.compile(r"^\[(?P<ts>\d{1,2}:\d{2}(?::\d{2})?)\]\s+<(?P<nick>[^>]+)>\s+(?P<msg>.*)$")
IRC_ACT_RE = re.compile(r"^\[(?P<ts>\d{1,2}:\d{2}(?::\d{2})?)\]\s+\*\s+(?P<rest>.*)$")
SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"
    r"\s+\[?(?P<level>[A-Z]{3,8})\]?\s+(?P<comp>[\w.\-/:]+):\s*(?P<msg>.*)$"
)
ERROR_TOKENS = re.compile(r"\b(error|exception|failed|failure|critical|fatal|traceback|denied)\b", re.I)


@dataclass
class Entry:
    raw: str
    ts: datetime | None
    user: str | None
    level: str | None
    event: str | None
    target: str | None
    text: str
    fmt: str


def _parse_iso(ts: str) -> datetime | None:
    ts = ts.replace(",", ".")
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _compact_json_text(obj: dict) -> str:
    dt = obj.get("dt") or obj.get("timestamp") or obj.get("ts")
    nick = obj.get("nick") or obj.get("user") or obj.get("source") or ""
    target = obj.get("target") or obj.get("channel") or ""
    msg = obj.get("msg") or obj.get("message") or ""
    flag = obj.get("flag") or obj.get("severity") or ""
    typ = obj.get("type") or obj.get("event_type") or ""
    scores = []
    for k in ("heu", "bino", "cls", "llama"):
        if k in obj:
            scores.append(f"{k}={obj[k]}")
    score_str = " ".join(scores)

    parts = []
    if dt:
        parts.append(str(dt))
    if typ:
        parts.append(f"[{typ}]")
    if nick:
        parts.append(str(nick))
    if target:
        parts.append(f"→{target}")
    if flag:
        parts.append(f"({flag})")
    if score_str:
        parts.append(score_str)
    if msg:
        parts.append(f": {msg}")
    if not parts:
        return json.dumps({k: v for k, v in obj.items() if k != "hmac"}, default=str)
    return " ".join(parts)


def _flatten_json_user(obj) -> str | None:
    if not isinstance(obj, dict):
        return None
    for key in ("user", "username", "nick", "source", "host", "process", "name"):
        v = obj.get(key)
        if isinstance(v, str) and v:
            return v
    details = obj.get("details") or obj.get("payload")
    if isinstance(details, dict):
        return _flatten_json_user(details)
    return None


def parse_line(line: str) -> Entry | None:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    if line.lstrip().startswith("{"):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            ts_str = obj.get("timestamp") or obj.get("dt") or obj.get("ts") or obj.get("time")
            ts = None
            if isinstance(ts_str, str):
                ts = _parse_iso(ts_str)
            elif isinstance(obj.get("ts"), (int, float)):
                try:
                    ts = datetime.fromtimestamp(float(obj["ts"]))
                except (OSError, OverflowError, ValueError):
                    ts = None
            user = _flatten_json_user(obj)
            level = obj.get("severity") or obj.get("level") or obj.get("flag")
            event = obj.get("event_type") or obj.get("event") or obj.get("type")
            payload = obj.get("payload")
            if event is None and isinstance(payload, dict):
                event = payload.get("type") or payload.get("action")
            target = obj.get("target") or obj.get("channel")
            text = _compact_json_text(obj)
            return Entry(line, ts, user, str(level) if level else None,
                         str(event) if event else None,
                         str(target) if target else None, text, "json")

    m = SYSLOG_RE.match(line)
    if m:
        ts = _parse_iso(m["ts"])
        return Entry(line, ts, m["comp"], m["level"], None, None, m["msg"], "syslog")

    m = IRC_MSG_RE.match(line)
    if m:
        ts = _parse_irc_time(m["ts"])
        return Entry(line, ts, m["nick"], None, "msg", None, m["msg"], "irc")

    m = IRC_ACT_RE.match(line)
    if m:
        ts = _parse_irc_time(m["ts"])
        rest = m["rest"]
        nick = rest.split(" ", 1)[0] if rest else None
        event = "action"
        for kw in ("joined", "left", "quit", "is now known", "kicked", "set mode", "Topic"):
            if kw in rest:
                event = kw.split()[0].lower()
                break
        return Entry(line, ts, nick, None, event, None, rest, "irc")

    return Entry(line, None, None, None, None, None, line, "raw")


def _parse_irc_time(ts: str) -> datetime | None:
    parts = ts.split(":")
    try:
        h, mi = int(parts[0]), int(parts[1])
        s = int(parts[2]) if len(parts) > 2 else 0
        return datetime(1970, 1, 1, h, mi, s)
    except (ValueError, IndexError):
        return None


def iter_entries(path: str) -> Iterator[Entry]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line)
            if e is not None:
                yield e


# ---------- analysis ---------------------------------------------------------

SCORE_KEYS = ("heu", "bino", "cls", "llama")


def line_matches_user(entry: Entry, user: str) -> bool:
    u = user.lower()
    if entry.user and entry.user.lower() == u:
        return True
    return u in entry.raw.lower()


_NICK_BOUNDARY = re.compile(r"[A-Za-z0-9_\-\[\]\\^{}|`]")


def _mentions(text: str, nick: str) -> bool:
    if not text or not nick:
        return False
    nl = nick.lower()
    tl = text.lower()
    start = 0
    while True:
        i = tl.find(nl, start)
        if i < 0:
            return False
        before = tl[i - 1] if i > 0 else ""
        after = tl[i + len(nl)] if i + len(nl) < len(tl) else ""
        if not _NICK_BOUNDARY.match(before) and not _NICK_BOUNDARY.match(after):
            return True
        start = i + 1


def _scores_from_raw(raw: str) -> dict:
    if not raw.lstrip().startswith("{"):
        return {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    keys = ("heu", "bino", "cls", "llama", "msg_len", "msg", "flag", "target")
    return {k: obj.get(k) for k in keys if k in obj}


def build_profile(entries: list[Entry], user: str) -> dict:
    u = user.lower()
    authored = [e for e in entries if e.user and e.user.lower() == u]
    mentions = [e for e in entries if e.user and e.user.lower() != u
                and _mentions(e.text or e.raw, user)]

    channels: Counter = Counter()
    flags: Counter = Counter()
    score_sums = {k: 0.0 for k in SCORE_KEYS}
    score_counts = {k: 0 for k in SCORE_KEYS}
    msg_lens: list[int] = []
    by_hour: Counter = Counter()
    by_day: Counter = Counter()
    samples: list[str] = []
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    for e in authored:
        if e.target:
            channels[e.target] += 1
        if e.level:
            flags[e.level] += 1
        if e.ts:
            by_hour[e.ts.hour] += 1
            by_day[e.ts.date().isoformat()] += 1
            if first_ts is None or e.ts < first_ts:
                first_ts = e.ts
            if last_ts is None or e.ts > last_ts:
                last_ts = e.ts

        scores = _scores_from_raw(e.raw)
        for k in SCORE_KEYS:
            v = scores.get(k)
            if isinstance(v, (int, float)):
                score_sums[k] += float(v)
                score_counts[k] += 1
        if isinstance(scores.get("msg_len"), int):
            msg_lens.append(scores["msg_len"])
        elif scores.get("msg"):
            msg_lens.append(len(str(scores["msg"])))

        samples.append(e.text)

    score_means = {k: (score_sums[k] / score_counts[k]) if score_counts[k] else None
                   for k in SCORE_KEYS}
    msg_len_mean = (sum(msg_lens) / len(msg_lens)) if msg_lens else None

    return {
        "user": user,
        "authored": len(authored),
        "mentioned_by_others": len(mentions),
        "channels": channels,
        "flags": flags,
        "score_means": score_means,
        "msg_len_mean": msg_len_mean,
        "by_hour": dict(sorted(by_hour.items())),
        "by_day": dict(sorted(by_day.items())),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "samples": samples,
    }


def _fmt_score(x):
    return f"{x:.3f}" if isinstance(x, float) else "—"


def _fmt_dt(d):
    return d.strftime("%Y-%m-%d %H:%M") if d else "—"


def _peak_hours(by_hour: dict) -> str:
    if not by_hour:
        return "—"
    top = sorted(by_hour.items(), key=lambda kv: -kv[1])[:3]
    return ", ".join(f"{h:02d}h({n})" for h, n in top)


def _top_str(counter: Counter, n: int) -> str:
    if not counter:
        return ""
    return ", ".join(f"{k}({v})" for k, v in counter.most_common(n))


def _fmt_num(x):
    if x is None:
        return "—"
    return f"{x:.1f}"


def print_compare_table(pa: dict, pb: dict) -> None:
    print_compare_table_n([pa, pb])


def print_compare_table_n(profiles: list[dict]) -> None:
    rows = [
        ("Authored lines", lambda p: str(p["authored"])),
        ("Mentioned by others", lambda p: str(p["mentioned_by_others"])),
        ("First seen", lambda p: _fmt_dt(p["first_ts"])),
        ("Last seen", lambda p: _fmt_dt(p["last_ts"])),
        ("Active days", lambda p: str(len(p["by_day"]))),
        ("Peak hours", lambda p: _peak_hours(p["by_hour"])),
        ("Top channels", lambda p: _top_str(p["channels"], 3) or "—"),
        ("Flags", lambda p: _top_str(p["flags"], 4) or "—"),
        ("Mean msg_len", lambda p: _fmt_num(p["msg_len_mean"])),
        ("heu mean", lambda p: _fmt_score(p["score_means"]["heu"])),
        ("bino mean", lambda p: _fmt_score(p["score_means"]["bino"])),
        ("cls mean", lambda p: _fmt_score(p["score_means"]["cls"])),
        ("llama mean", lambda p: _fmt_score(p["score_means"]["llama"])),
    ]
    label_w = max(len(r[0]) for r in rows)
    cells = [[fn(p) for p in profiles] for _, fn in rows]
    headers = [p["user"] for p in profiles]
    col_w = max(20, max(len(h) for h in headers),
                max((len(c) for row in cells for c in row), default=0))
    print("  " + "METRIC".ljust(label_w) + "   " + "   ".join(h.ljust(col_w) for h in headers))
    print("  " + "-" * label_w + "   " + "   ".join("-" * col_w for _ in headers))
    for (label, _), row in zip(rows, cells):
        print("  " + label.ljust(label_w) + "   " + "   ".join(c.ljust(col_w) for c in row))


def line_is_interaction(entry: Entry, a: str, b: str) -> bool:
    if not entry.user:
        return False
    nick = entry.user.lower()
    a_l, b_l = a.lower(), b.lower()
    if nick == a_l:
        other = b
    elif nick == b_l:
        other = a
    else:
        return False
    if entry.target and entry.target.lower() == other.lower():
        return True
    return _mentions(entry.text or entry.raw, other)


def summarize(entries: Iterable[Entry], top_n: int) -> dict:
    total = 0
    formats: Counter = Counter()
    users: Counter = Counter()
    events: Counter = Counter()
    levels: Counter = Counter()
    targets: Counter = Counter()
    by_hour: Counter = Counter()
    by_day: Counter = Counter()
    errors: list[str] = []
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    for e in entries:
        total += 1
        formats[e.fmt] += 1
        if e.user:
            users[e.user] += 1
        if e.event:
            events[e.event] += 1
        if e.level:
            levels[e.level.upper()] += 1
        if e.target:
            targets[e.target] += 1
        if e.ts:
            by_hour[e.ts.hour] += 1
            by_day[e.ts.date().isoformat()] += 1
            if first_ts is None or e.ts < first_ts:
                first_ts = e.ts
            if last_ts is None or e.ts > last_ts:
                last_ts = e.ts
        if (e.level and e.level.upper() in {"ERROR", "CRITICAL", "FATAL", "HIGH", "SUS", "SUSPICIOUS"}) \
                or ERROR_TOKENS.search(e.text or ""):
            if len(errors) < 25:
                errors.append(e.raw)

    return {
        "total": total,
        "formats": formats,
        "top_users": users.most_common(top_n),
        "top_events": events.most_common(top_n),
        "top_targets": targets.most_common(top_n),
        "levels": dict(levels),
        "by_hour": dict(sorted(by_hour.items())),
        "by_day": dict(sorted(by_day.items())),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "errors": errors,
    }


def print_report(s: dict) -> None:
    print(f"Total entries: {s['total']}")
    print(f"Formats: {dict(s['formats'])}")
    if s["first_ts"] or s["last_ts"]:
        print(f"Time range: {s['first_ts']}  →  {s['last_ts']}")
    if s["levels"]:
        print(f"Levels/severities: {s['levels']}")

    if s["top_users"]:
        print("\nTop users / sources:")
        for name, n in s["top_users"]:
            print(f"  {n:>7}  {name}")

    if s["top_events"]:
        print("\nTop events:")
        for name, n in s["top_events"]:
            print(f"  {n:>7}  {name}")

    if s.get("top_targets"):
        print("\nTop targets / channels:")
        for name, n in s["top_targets"]:
            print(f"  {n:>7}  {name}")

    if s["by_hour"]:
        print("\nActivity by hour:")
        peak = max(s["by_hour"].values()) or 1
        for h, n in s["by_hour"].items():
            bar = "█" * int(40 * n / peak)
            print(f"  {h:02d}  {n:>7}  {bar}")

    if s["by_day"] and len(s["by_day"]) > 1:
        print("\nActivity by day:")
        peak = max(s["by_day"].values()) or 1
        for d, n in s["by_day"].items():
            bar = "█" * int(40 * n / peak)
            print(f"  {d}  {n:>7}  {bar}")

    if s["errors"]:
        print(f"\nError-like entries (showing {len(s['errors'])}):")
        for line in s["errors"]:
            print(f"  {line[:200]}")


# ---------- time / score / fingerprint helpers ------------------------------

def parse_iso_arg(s: str) -> datetime | None:
    """User-supplied datetime: ISO, '5h ago', 'now'."""
    if not s:
        return None
    s = s.strip().replace(",", ".")
    if s.lower() == "now":
        return datetime.now()
    m = re.match(r"^(\d+)\s*([smhd])\s*(?:ago)?$", s, re.I)
    if m:
        amt = int(m.group(1))
        unit = m.group(2).lower()
        units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
        return datetime.now() - timedelta(**{units[unit]: amt})
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    for attempt in (s, s.replace(" ", "T")):
        try:
            return datetime.fromisoformat(attempt)
        except ValueError:
            pass
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        return None


def in_time_range(ts: datetime | None, since: datetime | None,
                  until: datetime | None) -> bool:
    if since is None and until is None:
        return True
    if ts is None:
        return False
    if since and ts < since:
        return False
    if until and ts > until:
        return False
    return True


def apply_time_filter(entries: Iterable[Entry], since: datetime | None,
                      until: datetime | None) -> list[Entry]:
    if since is None and until is None:
        return list(entries) if not isinstance(entries, list) else entries
    return [e for e in entries if in_time_range(e.ts, since, until)]


_SCORE_OP_RE = re.compile(
    r"^(?P<key>[A-Za-z_]+)\s*(?P<op>>=|<=|==|=|!=|>|<)\s*(?P<val>-?\d+(?:\.\d+)?)$"
)


def parse_score_filter(expr: str) -> list[tuple[str, str, float]]:
    """Parse 'llama>0.8 heu<0.3' into list of (key, op, value)."""
    out: list[tuple[str, str, float]] = []
    for tok in expr.split():
        m = _SCORE_OP_RE.match(tok)
        if not m:
            raise ValueError(f"bad score expression: {tok!r}")
        op = m["op"]
        if op == "=":
            op = "=="
        out.append((m["key"], op, float(m["val"])))
    return out


def _cmp(op: str, a: float, b: float) -> bool:
    return {
        "==": a == b, "!=": a != b,
        ">": a > b, "<": a < b,
        ">=": a >= b, "<=": a <= b,
    }[op]


def matches_score_filter(entry: Entry,
                         filters: Sequence[tuple[str, str, float]]) -> bool:
    if not filters:
        return True
    scores = _scores_from_raw(entry.raw)
    for key, op, val in filters:
        v = scores.get(key)
        if not isinstance(v, (int, float)):
            return False
        if not _cmp(op, float(v), val):
            return False
    return True


def collect_scores(entries: Iterable[Entry], user: str | None = None
                   ) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {k: [] for k in SCORE_KEYS}
    u = user.lower() if user else None
    for e in entries:
        if u and not (e.user and e.user.lower() == u):
            continue
        scores = _scores_from_raw(e.raw)
        for k in SCORE_KEYS:
            v = scores.get(k)
            if isinstance(v, (int, float)):
                out[k].append(float(v))
    return out


def population_score_stats(entries: Iterable[Entry]
                           ) -> dict[str, tuple[float, float, int]]:
    pool = collect_scores(entries)
    res: dict[str, tuple[float, float, int]] = {}
    for k, vals in pool.items():
        if len(vals) >= 2:
            res[k] = (statistics.mean(vals), statistics.pstdev(vals), len(vals))
        elif len(vals) == 1:
            res[k] = (vals[0], 0.0, 1)
        else:
            res[k] = (0.0, 0.0, 0)
    return res


def histogram(values: list[float], bins: int = 10,
              lo: float | None = None, hi: float | None = None
              ) -> tuple[list[int], list[tuple[float, float]]]:
    if not values:
        return [], []
    if lo is None:
        lo = min(values)
    if hi is None:
        hi = max(values)
    if hi <= lo:
        hi = lo + 1.0
    edges = [lo + (hi - lo) * i / bins for i in range(bins + 1)]
    counts = [0] * bins
    for v in values:
        idx = int((v - lo) / (hi - lo) * bins)
        if idx == bins:
            idx = bins - 1
        if 0 <= idx < bins:
            counts[idx] += 1
    intervals = [(edges[i], edges[i + 1]) for i in range(bins)]
    return counts, intervals


def percentiles(values: list[float], ps: Sequence[int] = (10, 25, 50, 75, 90)
                ) -> dict[int, float]:
    if not values:
        return {}
    s = sorted(values)
    out: dict[int, float] = {}
    for p in ps:
        if len(s) == 1:
            out[p] = s[0]
            continue
        rank = (p / 100) * (len(s) - 1)
        lo = int(rank)
        hi = min(lo + 1, len(s) - 1)
        frac = rank - lo
        out[p] = s[lo] * (1 - frac) + s[hi] * frac
    return out


def print_score_dist(label: str, scores_by_key: dict[str, list[float]],
                     bins: int = 10) -> None:
    print(f"\nScore distributions for {label}:")
    for key in SCORE_KEYS:
        vals = scores_by_key.get(key) or []
        if not vals:
            print(f"  {key:6s}  (no data)")
            continue
        pcs = percentiles(vals)
        m = statistics.mean(vals)
        sd = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        print(f"  {key:6s}  n={len(vals):<5d}  mean={m:.3f}  stdev={sd:.3f}"
              f"  p10={pcs[10]:.2f}  p50={pcs[50]:.2f}  p90={pcs[90]:.2f}")
        counts, intervals = histogram(vals, bins, 0.0, 1.0)
        peak = max(counts) or 1
        for c, (a, b) in zip(counts, intervals):
            bar = "█" * int(20 * c / peak)
            print(f"          [{a:.2f},{b:.2f})  {c:>5d}  {bar}")


def zscores_for_user(profile: dict,
                     pop: dict[str, tuple[float, float, int]]
                     ) -> dict[str, float | None]:
    out: dict[str, float | None] = {}
    means = profile.get("score_means", {})
    for k in SCORE_KEYS:
        um = means.get(k)
        pm, ps, n = pop.get(k, (0.0, 0.0, 0))
        if um is None or ps == 0 or n == 0:
            out[k] = None
        else:
            out[k] = (um - pm) / ps
    return out


def print_zscores(profile: dict, pop: dict[str, tuple[float, float, int]]) -> None:
    z = zscores_for_user(profile, pop)
    print(f"\nZ-scores for {profile['user']} vs population:")
    for k in SCORE_KEYS:
        pm, ps, n = pop.get(k, (0.0, 0.0, 0))
        um = profile["score_means"].get(k)
        zk = z[k]
        u_str = f"{um:.3f}" if isinstance(um, float) else "—"
        z_str = f"{zk:+.2f}σ" if isinstance(zk, float) else "—"
        print(f"  {k:6s}  user={u_str}  pop_mean={pm:.3f}  pop_sd={ps:.3f}"
              f"  n={n}   z={z_str}")


def user_fingerprint(profile: dict) -> list[float]:
    vec: list[float] = []
    sm = profile.get("score_means", {})
    for k in SCORE_KEYS:
        v = sm.get(k)
        vec.append(float(v) if isinstance(v, float) else 0.0)
    by_hour = profile.get("by_hour") or {}
    total = sum(by_hour.values()) or 1
    for h in range(24):
        vec.append(by_hour.get(h, 0) / total)
    msg_len = profile.get("msg_len_mean")
    vec.append((float(msg_len) / 200.0) if msg_len else 0.0)
    return vec


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def find_similar_users(entries: list[Entry], min_lines: int = 5,
                       threshold: float = 0.95, top: int = 20
                       ) -> list[tuple[str, str, float, int, int]]:
    counts: Counter = Counter(e.user for e in entries if e.user)
    candidates = sorted(u for u, n in counts.items() if n >= min_lines)
    profiles = {u: build_profile(entries, u) for u in candidates}
    fps = {u: user_fingerprint(p) for u, p in profiles.items()}
    pairs: list[tuple[str, str, float, int, int]] = []
    for i, a in enumerate(candidates):
        for b in candidates[i + 1:]:
            sim = cosine(fps[a], fps[b])
            if sim >= threshold:
                pairs.append((a, b, sim, profiles[a]["authored"],
                              profiles[b]["authored"]))
    pairs.sort(key=lambda p: -p[2])
    return pairs[:top]


def print_similar_users(pairs: list[tuple[str, str, float, int, int]]) -> None:
    if not pairs:
        print("\nNo user pairs above similarity threshold.")
        return
    print("\nMost-similar user pairs (cosine over score+hour fingerprint):")
    print(f"  {'sim':>8}   {'user A':<20} {'(lines)':>9}    {'user B':<20} {'(lines)':>9}")
    for a, b, sim, na, nb in pairs:
        print(f"  {sim:>8.4f}   {a:<20} ({na:>7})    {b:<20} ({nb:>7})")


def detect_bursts(entries: list[Entry], user: str, window_seconds: int = 60,
                  z_threshold: float = 3.0
                  ) -> list[tuple[datetime, int, float]]:
    u = user.lower()
    timestamps = [e.ts for e in entries
                  if e.ts and e.user and e.user.lower() == u]
    if len(timestamps) < 5:
        return []
    timestamps.sort()
    bins: Counter = Counter()
    start_epoch = int(timestamps[0].timestamp())
    for t in timestamps:
        bucket = int(t.timestamp() - start_epoch) // window_seconds
        bins[bucket] += 1
    counts = list(bins.values())
    mean = statistics.mean(counts)
    sd = statistics.pstdev(counts) if len(counts) > 1 else 0.0
    if sd == 0:
        return []
    bursts: list[tuple[datetime, int, float]] = []
    for b, c in sorted(bins.items()):
        z = (c - mean) / sd
        if z >= z_threshold:
            ts = datetime.fromtimestamp(start_epoch + b * window_seconds)
            bursts.append((ts, c, z))
    return bursts


def print_bursts(user: str, bursts: list[tuple[datetime, int, float]],
                 window_seconds: int) -> None:
    if not bursts:
        print(f"\nNo bursts detected for {user} (window={window_seconds}s).")
        return
    print(f"\nBursts for {user} (window={window_seconds}s):")
    for ts, c, z in bursts:
        print(f"  {ts}  count={c:<5d}  z={z:.2f}σ")


REPLY_PREFIX_RE = re.compile(r"^\s*([A-Za-z0-9_\-\[\]\\^{}|`]+)\s*[:,]\s+")
MENTION_RE = re.compile(r"@([A-Za-z0-9_\-\[\]\\^{}|`]+)")


def detect_reply_target(entry: Entry, known_nicks_lower: set[str]) -> str | None:
    text = entry.text or entry.raw or ""
    own = entry.user.lower() if entry.user else None
    m = REPLY_PREFIX_RE.match(text)
    if m:
        cand = m.group(1)
        if cand.lower() in known_nicks_lower and cand.lower() != own:
            return cand
    m = MENTION_RE.search(text)
    if m:
        cand = m.group(1)
        if cand.lower() in known_nicks_lower and cand.lower() != own:
            return cand
    return None


def build_edge_graph(entries: list[Entry]) -> Counter:
    nicks_lower = {e.user.lower() for e in entries if e.user}
    edges: Counter = Counter()
    for e in entries:
        if not e.user:
            continue
        tgt = detect_reply_target(e, nicks_lower)
        if tgt:
            edges[(e.user, tgt)] += 1
    return edges


def build_thread_for_user(entries: list[Entry], user: str
                          ) -> list[tuple[Entry, str | None]]:
    nicks_lower = {e.user.lower() for e in entries if e.user}
    out: list[tuple[Entry, str | None]] = []
    u = user.lower()
    for e in entries:
        if not e.user:
            continue
        author = e.user.lower()
        text = e.text or e.raw or ""
        if author == u:
            tgt = detect_reply_target(e, nicks_lower)
            out.append((e, tgt))
        elif _mentions(text, user):
            out.append((e, user))
    return out


# ---------- views (named filter sets) ---------------------------------------

@dataclass
class View:
    name: str
    user: str | None = None
    target: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    regex: str | None = None
    score_filter: list[tuple[str, str, float]] = field(default_factory=list)


def apply_view(entries: Iterable[Entry], view: View) -> list[Entry]:
    rx = re.compile(view.regex, re.I) if view.regex else None
    u = view.user.lower() if view.user else None
    t = view.target.lower() if view.target else None
    out: list[Entry] = []
    for e in entries:
        if not in_time_range(e.ts, view.since, view.until):
            continue
        if u:
            ok = (e.user and e.user.lower() == u) or (u in (e.raw or "").lower())
            if not ok:
                continue
        if t and not (e.target and e.target.lower() == t):
            continue
        if rx and not rx.search(e.raw):
            continue
        if view.score_filter and not matches_score_filter(e, view.score_filter):
            continue
        out.append(e)
    return out


def view_describe(v: View) -> str:
    parts = []
    if v.user:
        parts.append(f"user={v.user}")
    if v.target:
        parts.append(f"target={v.target}")
    if v.since:
        parts.append(f"since={v.since.isoformat()}")
    if v.until:
        parts.append(f"until={v.until.isoformat()}")
    if v.regex:
        parts.append(f"regex={v.regex!r}")
    if v.score_filter:
        parts.append("scores=[" + " ".join(f"{k}{op}{val}" for k, op, val in v.score_filter) + "]")
    return ", ".join(parts) or "(empty)"


# ---------- color / spinner / sparkline / config helpers -------------------

class _Color:
    enabled: bool = True
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def wrap(cls, s: str, c: str) -> str:
        return f"{c}{s}{cls.RESET}" if cls.enabled else s

    @classmethod
    def auto_disable(cls) -> None:
        if not sys.stdout.isatty():
            cls.enabled = False
        if os.environ.get("NO_COLOR"):
            cls.enabled = False


def _color_score(x) -> str:
    """Color a score float by threshold (red ≥ 0.8, yellow ≥ 0.5, green else)."""
    if not isinstance(x, float):
        return _fmt_score(x)
    s = f"{x:.3f}"
    if x >= 0.8:
        return _Color.wrap(s, _Color.RED)
    if x >= 0.5:
        return _Color.wrap(s, _Color.YELLOW)
    return _Color.wrap(s, _Color.GREEN)


SPARK_GLYPHS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    peak = max(values) or 1
    out = []
    for v in values:
        idx = int((v / peak) * (len(SPARK_GLYPHS) - 1))
        out.append(SPARK_GLYPHS[idx])
    return "".join(out)


class Spinner:
    """Thread-driven spinner on stderr; no-op when stderr is not a TTY."""
    GLYPHS = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, msg: str = "working", enabled: bool | None = None) -> None:
        self.msg = msg
        if enabled is None:
            enabled = bool(getattr(sys.stderr, "isatty", lambda: False)())
        self.enabled = enabled
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "Spinner":
        if self.enabled:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._thread:
            self._stop.set()
            self._thread.join(timeout=1.0)
            try:
                sys.stderr.write("\r" + " " * (len(self.msg) + 4) + "\r")
                sys.stderr.flush()
            except Exception:  # noqa: BLE001
                pass

    def _spin(self) -> None:
        for ch in itertools.cycle(self.GLYPHS):
            if self._stop.is_set():
                break
            try:
                sys.stderr.write(f"\r{ch} {self.msg} ")
                sys.stderr.flush()
            except Exception:  # noqa: BLE001
                return
            if self._stop.wait(0.1):
                return


def _config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    p = os.path.join(base, "analyzelog")
    try:
        os.makedirs(p, exist_ok=True)
    except OSError:
        pass
    return p


def _aliases_path() -> str:
    return os.path.join(_config_dir(), "aliases.json")


def _ignore_path() -> str:
    return os.path.join(_config_dir(), "ignore.json")


def _notes_path() -> str:
    return os.path.join(_config_dir(), "notes.json")


def _history_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "analyzelog_history")


def _load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def _save_json(path: str, data) -> None:
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"Failed to write {path}: {exc}", file=sys.stderr)


# ---------- LLM --------------------------------------------------------------

def _llm_endpoint(base: str) -> str:
    base = base.rstrip("/")
    if base.endswith("/v1/chat/completions") or base.endswith("/chat/completions"):
        return base
    return base + "/v1/chat/completions"


def call_llm(base_url: str, model: str, system: str, user_msg: str,
             timeout: int = 180) -> str:
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.3,
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        _llm_endpoint(base_url),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(data)[:2000]


class LLMCache:
    """JSON-on-disk cache of LLM responses keyed by (model, system, user_msg)."""

    def __init__(self, path: str | None) -> None:
        self.path = path
        self.data: dict[str, str] = {}
        self.dirty = False
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if isinstance(obj, dict):
                    self.data = {k: v for k, v in obj.items() if isinstance(v, str)}
            except (OSError, json.JSONDecodeError):
                self.data = {}

    @staticmethod
    def make_key(model: str, system: str, user_msg: str) -> str:
        h = hashlib.sha256()
        h.update(model.encode())
        h.update(b"\0")
        h.update(system.encode())
        h.update(b"\0")
        h.update(user_msg.encode())
        return h.hexdigest()

    def get(self, model: str, system: str, user_msg: str) -> str | None:
        return self.data.get(self.make_key(model, system, user_msg))

    def put(self, model: str, system: str, user_msg: str, response: str) -> None:
        self.data[self.make_key(model, system, user_msg)] = response
        self.dirty = True
        self.save()

    def save(self) -> None:
        if not self.path or not self.dirty:
            return
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f)
            os.replace(tmp, self.path)
            self.dirty = False
        except OSError as exc:
            print(f"LLM cache save failed: {exc}", file=sys.stderr)

    def __len__(self) -> int:
        return len(self.data)


def call_llm_cached(base_url: str, model: str, system: str, user_msg: str,
                    timeout: int = 180, cache: LLMCache | None = None,
                    spinner_msg: str = "LLM thinking") -> str:
    if cache is not None:
        hit = cache.get(model, system, user_msg)
        if hit is not None:
            return hit
    with Spinner(spinner_msg):
        out = call_llm(base_url, model, system, user_msg, timeout)
    if cache is not None:
        cache.put(model, system, user_msg, out)
    return out


def chunk_lines(lines: list[str], max_chars: int) -> list[str]:
    chunks: list[str] = []
    buf: list[str] = []
    size = 0
    for ln in lines:
        ln_len = len(ln) + 1
        if size + ln_len > max_chars and buf:
            chunks.append("\n".join(buf))
            buf, size = [], 0
        buf.append(ln)
        size += ln_len
    if buf:
        chunks.append("\n".join(buf))
    return chunks


def analyze_user_with_llm(user: str, lines: list[str], llm_url: str,
                          model: str, max_chars: int,
                          cache: LLMCache | None = None) -> None:
    if not lines:
        print(f"\nNo lines matched user '{user}'. Nothing to send to the LLM.")
        return

    print(f"\nFiltered to {len(lines)} lines for user '{user}'.")
    chunks = chunk_lines(lines, max_chars)
    print(f"Sending {len(chunks)} chunk(s) to LLM at {llm_url} (model={model}).")

    system = (
        "You are a log-analysis assistant. Given log lines that all relate to a "
        "single user/identifier, summarize that user's behavior: what they do, "
        "when they are active, who/what they interact with, anomalies, and any "
        "signs of trouble. Be concrete, cite line patterns, and keep it tight."
    )

    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"User of interest: {user}\n"
            f"Chunk {i}/{len(chunks)} of log lines mentioning this user:\n\n"
            f"{chunk}\n\n"
            f"Summarize this chunk's evidence about {user}'s behavior."
        )
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache)
        except urllib.error.URLError as exc:
            print(f"  [chunk {i}] LLM request failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"  [chunk {i}] LLM error: {exc}", file=sys.stderr)
            return
        partials.append(out)
        print(f"\n--- Chunk {i}/{len(chunks)} summary ---\n{out}")

    if len(partials) > 1:
        merge_prompt = (
            f"Combine these per-chunk summaries about user '{user}' into one "
            f"cohesive behavior profile. Deduplicate, resolve contradictions, "
            f"and call out the strongest signals.\n\n"
            + "\n\n---\n\n".join(f"Chunk {i+1}:\n{p}" for i, p in enumerate(partials))
        )
        try:
            final = call_llm_cached(llm_url, model, system, merge_prompt, cache=cache)
            print(f"\n=== Final behavior profile for {user} ===\n{final}")
        except Exception as exc:  # noqa: BLE001
            print(f"Final merge failed: {exc}", file=sys.stderr)


def analyze_interaction_with_llm(a: str, b: str, lines: list[str], llm_url: str,
                                 model: str, max_chars: int,
                                 cache: LLMCache | None = None) -> None:
    if not lines:
        print(f"\nNo direct interactions found between '{a}' and '{b}'. Nothing to send to the LLM.")
        return

    print(f"\nFound {len(lines)} direct-interaction lines between '{a}' and '{b}'.")
    chunks = chunk_lines(lines, max_chars)
    print(f"Sending {len(chunks)} chunk(s) to LLM at {llm_url} (model={model}).")

    system = (
        "You are a log-analysis assistant. You will receive log lines that "
        "represent direct exchanges between exactly two users. Characterize "
        "their relationship: frequency and rhythm of contact, tone, who "
        "initiates, recurring topics, agreement vs. conflict, role asymmetry "
        "(e.g. helper/asker, friends, antagonists, bot/operator), and any "
        "anomalies. Cite concrete evidence and keep it tight."
    )

    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"User A: {a}\nUser B: {b}\n"
            f"Chunk {i}/{len(chunks)} of log lines representing direct exchanges "
            f"between them:\n\n{chunk}\n\n"
            f"Summarize this chunk's evidence about how {a} and {b} interact."
        )
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache)
        except urllib.error.URLError as exc:
            print(f"  [chunk {i}] LLM request failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"  [chunk {i}] LLM error: {exc}", file=sys.stderr)
            return
        partials.append(out)
        print(f"\n--- Chunk {i}/{len(chunks)} summary ---\n{out}")

    if len(partials) > 1:
        merge_prompt = (
            f"Combine these per-chunk summaries about the interaction between "
            f"'{a}' and '{b}' into one cohesive relationship profile. "
            f"Deduplicate, resolve contradictions, and call out the strongest "
            f"signals.\n\n"
            + "\n\n---\n\n".join(f"Chunk {i+1}:\n{p}" for i, p in enumerate(partials))
        )
        try:
            final = call_llm_cached(llm_url, model, system, merge_prompt, cache=cache)
            print(f"\n=== Final interaction profile: {a} ↔ {b} ===\n{final}")
        except Exception as exc:  # noqa: BLE001
            print(f"Final merge failed: {exc}", file=sys.stderr)


def _profile_summary_for_llm(p: dict) -> str:
    sm = p["score_means"]
    return (
        f"User: {p['user']}\n"
        f"  authored_lines: {p['authored']}\n"
        f"  mentioned_by_others: {p['mentioned_by_others']}\n"
        f"  first_seen: {_fmt_dt(p['first_ts'])}   last_seen: {_fmt_dt(p['last_ts'])}\n"
        f"  active_days: {len(p['by_day'])}   peak_hours: {_peak_hours(p['by_hour'])}\n"
        f"  top_channels: {_top_str(p['channels'], 5) or '—'}\n"
        f"  flags: {_top_str(p['flags'], 5) or '—'}\n"
        f"  mean_msg_len: {_fmt_num(p['msg_len_mean'])}\n"
        f"  score_means: heu={_fmt_score(sm['heu'])} bino={_fmt_score(sm['bino'])} "
        f"cls={_fmt_score(sm['cls'])} llama={_fmt_score(sm['llama'])}"
    )


def _trim_samples(samples: list[str], max_chars: int) -> list[str]:
    if not samples:
        return []
    if len(samples) <= 60:
        chosen = samples
    else:
        step = len(samples) / 60
        chosen = [samples[int(i * step)] for i in range(60)]
    out: list[str] = []
    used = 0
    for s in chosen:
        if used + len(s) + 1 > max_chars:
            break
        out.append(s)
        used += len(s) + 1
    return out


def compare_users_with_llm(pa: dict, pb: dict, llm_url: str, model: str,
                           max_chunk_chars: int,
                           cache: LLMCache | None = None) -> None:
    compare_n_users_with_llm([pa, pb], llm_url, model, max_chunk_chars, cache)


def compare_n_users_with_llm(profiles: list[dict], llm_url: str, model: str,
                             max_chunk_chars: int,
                             cache: LLMCache | None = None) -> None:
    names = ", ".join(p["user"] for p in profiles)
    if not any(p["authored"] for p in profiles):
        print(f"\nNone of the requested users ({names}) authored lines in this log.")
        return

    sample_budget = max(1500, max_chunk_chars // (len(profiles) + 1))
    parts: list[str] = []
    counts: list[int] = []
    for p in profiles:
        samples = _trim_samples(p["samples"], sample_budget)
        counts.append(len(samples))
        parts.append(
            f"=== Profile: {p['user']} ===\n{_profile_summary_for_llm(p)}\n\n"
            f"Sample lines authored by {p['user']} ({len(samples)}):\n"
            + "\n".join(samples)
        )
    user_msg = "\n\n".join(parts) + f"\n\nCompare these users: {names}."

    if len(profiles) == 2:
        system = (
            "You are a log-analysis assistant. You will receive two users' "
            "behavior profiles (aggregate metrics) plus sample messages each "
            "user authored. Compare them: tone and style, topics they engage "
            "with, where and when they're active, score-profile differences, "
            "role (helper/asker/lurker/bot/troll), similarities, and any "
            "anomalies that distinguish them. Cite metrics and quote short "
            "snippets when useful. Keep it tight and structured."
        )
    else:
        system = (
            "You are a log-analysis assistant. You will receive several users' "
            "behavior profiles and sample messages. Compare them across tone, "
            "topics, activity windows, score-profile differences, and roles. "
            "Group users that look alike (possible sock-puppets) and call out "
            "ones that stand apart. Cite metrics, quote short snippets, and "
            "structure clearly."
        )

    print(f"\nSending {len(profiles)}-way behavior comparison to LLM at {llm_url} (model={model}).")
    print("  " + "  |  ".join(f"{p['user']}: {n} samples" for p, n in zip(profiles, counts)))

    try:
        out = call_llm_cached(llm_url, model, system, user_msg, cache=cache)
    except urllib.error.URLError as exc:
        print(f"LLM request failed: {exc}", file=sys.stderr)
        return
    except Exception as exc:  # noqa: BLE001
        print(f"LLM error: {exc}", file=sys.stderr)
        return
    print(f"\n=== Behavior comparison: {names} ===\n{out}")


def ask_about_user_with_llm(user: str, question: str, lines: list[str],
                            llm_url: str, model: str, max_chars: int,
                            cache: LLMCache | None = None) -> None:
    if not lines:
        print(f"\nNo lines for '{user}'. Nothing to ask.")
        return
    chunks = chunk_lines(lines, max_chars)
    print(f"\nAsking LLM about {user} ({len(chunks)} chunk(s)) at {llm_url} (model={model}).")
    system = (
        "You are a log-analysis assistant. Given log lines that all relate to "
        "a single user, answer the operator's question concretely, citing "
        "evidence from the lines. If the lines do not contain enough "
        "information to answer, say so."
    )
    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"User of interest: {user}\n"
            f"Operator question: {question}\n\n"
            f"Chunk {i}/{len(chunks)} of log lines for this user:\n\n{chunk}\n\n"
            f"Answer the question for this chunk. Cite lines when useful."
        )
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache)
        except urllib.error.URLError as exc:
            print(f"  [chunk {i}] LLM request failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"  [chunk {i}] LLM error: {exc}", file=sys.stderr)
            return
        partials.append(out)
        print(f"\n--- Chunk {i}/{len(chunks)} answer ---\n{out}")
    if len(partials) > 1:
        merge = (
            f"Operator question: {question}\n\n"
            f"Combine the per-chunk answers below into one coherent response. "
            f"Resolve contradictions, deduplicate, and cite the strongest evidence.\n\n"
            + "\n\n---\n\n".join(f"Chunk {i+1}:\n{p}" for i, p in enumerate(partials))
        )
        try:
            final = call_llm_cached(llm_url, model, system, merge, cache=cache)
            print(f"\n=== Final answer about {user}: {question} ===\n{final}")
        except Exception as exc:  # noqa: BLE001
            print(f"Final merge failed: {exc}", file=sys.stderr)


# ---------- exports ---------------------------------------------------------

def serialize_profile(profile: dict, sample_cap: int = 200) -> dict:
    out = dict(profile)
    out["channels"] = dict(profile["channels"])
    out["flags"] = dict(profile["flags"])
    out["first_ts"] = profile["first_ts"].isoformat() if profile["first_ts"] else None
    out["last_ts"] = profile["last_ts"].isoformat() if profile["last_ts"] else None
    out["samples"] = profile["samples"][:sample_cap]
    return out


def serialize_summary(summary: dict) -> dict:
    out = dict(summary)
    out["formats"] = dict(summary["formats"])
    out["first_ts"] = summary["first_ts"].isoformat() if summary["first_ts"] else None
    out["last_ts"] = summary["last_ts"].isoformat() if summary["last_ts"] else None
    return out


def export_profile_json(profile: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serialize_profile(profile), f, indent=2, default=str)


def export_profile_csv(profile: dict, path: str) -> None:
    rows: list[tuple[str, object]] = [
        ("user", profile["user"]),
        ("authored", profile["authored"]),
        ("mentioned_by_others", profile["mentioned_by_others"]),
        ("first_ts", profile["first_ts"].isoformat() if profile["first_ts"] else ""),
        ("last_ts", profile["last_ts"].isoformat() if profile["last_ts"] else ""),
        ("active_days", len(profile["by_day"])),
        ("msg_len_mean", profile["msg_len_mean"] if profile["msg_len_mean"] is not None else ""),
    ]
    for k in SCORE_KEYS:
        v = profile["score_means"].get(k)
        rows.append((f"{k}_mean", v if v is not None else ""))
    rows.append(("top_channels", _top_str(profile["channels"], 5)))
    rows.append(("flags", _top_str(profile["flags"], 5)))
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])
        for k, v in rows:
            w.writerow([k, v])


def export_summary_json(summary: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serialize_summary(summary), f, indent=2, default=str)


def export_edges_csv(edges: Counter, path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source", "target", "weight"])
        for (a, b), n in edges.most_common():
            w.writerow([a, b, n])


def export_edges_dot(edges: Counter, path: str, top: int = 200) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("digraph chat {\n")
        f.write('  rankdir=LR;\n  node [shape=box];\n')
        for (a, b), n in edges.most_common(top):
            pen = 1.0 + min(n, 10) / 2.0
            f.write(f'  "{a}" -> "{b}" [label="{n}", penwidth={pen:.1f}];\n')
        f.write("}\n")


# ---------- diff between two log files --------------------------------------

def diff_summaries(a: dict, b: dict, top: int = 25) -> dict:
    a_users = dict(a["top_users"])
    b_users = dict(b["top_users"])
    all_users = set(a_users) | set(b_users)
    user_deltas = sorted(
        ((u, b_users.get(u, 0) - a_users.get(u, 0),
          a_users.get(u, 0), b_users.get(u, 0)) for u in all_users),
        key=lambda r: -abs(r[1])
    )[:top]
    return {
        "totals": (a["total"], b["total"], b["total"] - a["total"]),
        "first_ts": (a["first_ts"], b["first_ts"]),
        "last_ts": (a["last_ts"], b["last_ts"]),
        "user_deltas": user_deltas,
    }


def print_log_diff(path_a: str, path_b: str, diff: dict) -> None:
    ta, tb, dt = diff["totals"]
    print(f"\nDiff: {path_a}  →  {path_b}")
    print(f"  totals: {ta} → {tb}  (Δ {dt:+d})")
    fa, fb = diff["first_ts"]
    la, lb = diff["last_ts"]
    print(f"  range A: {fa} → {la}")
    print(f"  range B: {fb} → {lb}")
    print(f"  top user-count deltas (B - A):")
    for u, d, av, bv in diff["user_deltas"]:
        print(f"    {d:+6d}  {u:30s}  {av} → {bv}")


# ---------- watch / tail ----------------------------------------------------

def watch_loop(path: str, on_new, poll_seconds: float = 2.0) -> None:
    """Tail-like watcher; calls on_new(list[Entry]) for newly appended lines."""
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    while True:
        try:
            time.sleep(poll_seconds)
            try:
                cur = os.path.getsize(path)
            except OSError:
                continue
            if cur < size:
                size = 0
            if cur == size:
                continue
            new_entries: list[Entry] = []
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(size)
                for line in f:
                    e = parse_line(line)
                    if e is not None:
                        new_entries.append(e)
            size = cur
            if new_entries:
                on_new(new_entries)
        except KeyboardInterrupt:
            print("\n(watch stopped)")
            return


def watch_callback_default(new: list[Entry]) -> None:
    print(f"\n[watch] +{len(new)} new lines")
    for e in new[-10:]:
        ts = _fmt_dt(e.ts)
        u = e.user or "—"
        t = e.target or ""
        print(f"  {ts}  {u:>15}  {t:>10}  {(e.text or e.raw)[:160]}")


class WatchBg:
    """Background tail thread: appends new entries to shell.state.entries and
    bumps a counter the prompt can read."""

    def __init__(self, shell: "LogShell", poll: float = 2.0) -> None:
        self.shell = shell
        self.poll = poll
        self._stop = threading.Event()
        self.new_count = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        path = self.shell.state.log_path
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        while not self._stop.wait(self.poll):
            try:
                cur = os.path.getsize(path)
            except OSError:
                continue
            if cur < size:
                size = 0
            if cur == size:
                continue
            new_entries: list[Entry] = []
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(size)
                    for line in f:
                        e = parse_line(line)
                        if e is not None:
                            new_entries.append(e)
            except OSError:
                continue
            size = cur
            if new_entries:
                self.shell.state.entries.extend(new_entries)
                self.new_count += len(new_entries)


# ---------- TUI --------------------------------------------------------------

@dataclass
class ShellState:
    log_path: str
    entries: list[Entry] = field(default_factory=list)
    focused_user: str | None = None
    focused_target: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    top_n: int = 15
    llm_url: str = "http://127.0.0.1:8033/"
    llm_model: str = "local"
    max_chunk_chars: int = 12000
    llm_cache: LLMCache | None = None
    views: dict[str, View] = field(default_factory=dict)
    # New (TUI features 1-20):
    aliases: dict[str, str] = field(default_factory=dict)
    ignore_set: set[str] = field(default_factory=set)
    notes: dict[str, str] = field(default_factory=dict)
    last_output: str = ""
    last_listing: list[str] = field(default_factory=list)   # for `pick`
    last_entries: list[Entry] = field(default_factory=list)  # for `inspect`
    focus_back: list[tuple] = field(default_factory=list)
    focus_forward: list[tuple] = field(default_factory=list)
    pager_enabled: bool = True
    color_enabled: bool = True
    watch_bg: "WatchBg | None" = None


class LogShell(cmd.Cmd):
    intro = (
        "analyzelog interactive shell.  Type 'commands' for a full reference, "
        "'help <name>' for one command, 'quit' to exit.\n"
    )
    prompt = "(log) "

    NO_CAPTURE_CMDS = {"watch"}
    _REDIRECT_RE = re.compile(r"^(.*?)\s+(>>|>)\s+(\S+)\s*$")

    def __init__(self, state: ShellState) -> None:
        super().__init__()
        self.state = state
        # Load persistent config
        loaded_aliases = _load_json(_aliases_path(), {})
        if isinstance(loaded_aliases, dict):
            self.state.aliases.update({k: v for k, v in loaded_aliases.items() if isinstance(v, str)})
        loaded_ignore = _load_json(_ignore_path(), [])
        if isinstance(loaded_ignore, list):
            self.state.ignore_set.update(str(u) for u in loaded_ignore if isinstance(u, str))
        loaded_notes = _load_json(_notes_path(), {})
        if isinstance(loaded_notes, dict):
            self.state.notes.update({k: v for k, v in loaded_notes.items() if isinstance(v, str)})
        self._in_script = False
        self._setup_readline()
        self._refresh_prompt()

    # --- helpers -------------------------------------------------------------

    def _setup_readline(self) -> None:
        if readline is None:
            return
        try:
            readline.read_history_file(_history_path())
        except (FileNotFoundError, OSError):
            pass
        try:
            readline.set_history_length(2000)
        except Exception:  # noqa: BLE001
            pass
        atexit.register(self._save_history)

    def _save_history(self) -> None:
        if readline is None:
            return
        try:
            readline.write_history_file(_history_path())
        except OSError:
            pass

    def _refresh_prompt(self) -> None:
        path = self.state.log_path
        n_total = len(self.state.entries)
        n_active = len(self._active_entries())
        bits = []
        if self.state.focused_user:
            bits.append(f"user={self.state.focused_user}")
        if self.state.focused_target:
            bits.append(f"target={self.state.focused_target}")
        if self.state.since:
            bits.append(f"since={self.state.since.date()}")
        if self.state.until:
            bits.append(f"until={self.state.until.date()}")
        tag = (" [" + " ".join(bits) + "]") if bits else ""
        count_str = f"n={n_active}/{n_total}" if n_active != n_total else f"n={n_total}"
        bg_str = ""
        if self.state.watch_bg and self.state.watch_bg.new_count > 0:
            bg_str = f" +{self.state.watch_bg.new_count}new"
        self.prompt = f"(log {path} {count_str}{tag}{bg_str}) "

    def _time_filtered(self) -> list[Entry]:
        """Time-filtered entries, ignoring the global ignore_set.
        Used when a user is named explicitly."""
        return apply_time_filter(self.state.entries, self.state.since, self.state.until)

    def _active_entries(self) -> list[Entry]:
        """Time-filtered + ignore_set applied. Used for stats / global commands."""
        base = self._time_filtered()
        if not self.state.ignore_set:
            return base
        ig = {u.lower() for u in self.state.ignore_set}
        return [e for e in base if not (e.user and e.user.lower() in ig)]

    def _resolve_user(self, arg: str) -> str | None:
        arg = arg.strip()
        if arg:
            return arg
        if self.state.focused_user:
            return self.state.focused_user
        print("No user given and no focused user. Try: user <nick>")
        return None

    def _filtered(self, user: str) -> list[Entry]:
        return [e for e in self._time_filtered() if line_matches_user(e, user)]

    def _filtered_by_target(self, target: str) -> list[Entry]:
        t = target.lower()
        return [e for e in self._active_entries()
                if e.target and e.target.lower() == t]

    def _split(self, line: str) -> list[str]:
        try:
            return shlex.split(line)
        except ValueError:
            return line.split()

    def _push_focus(self) -> None:
        snap = (self.state.focused_user, self.state.focused_target,
                self.state.since, self.state.until)
        self.state.focus_back.append(snap)
        self.state.focus_forward.clear()

    @staticmethod
    def _split_chained(line: str) -> list[str]:
        """Split line on top-level ';' respecting quotes."""
        parts: list[str] = []
        buf: list[str] = []
        in_q: str | None = None
        for ch in line:
            if in_q:
                if ch == in_q:
                    in_q = None
                buf.append(ch)
            elif ch in ('"', "'"):
                in_q = ch
                buf.append(ch)
            elif ch == ";":
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        parts.append("".join(buf).strip())
        return [p for p in parts if p]

    def _should_page(self, output: str) -> bool:
        if not output:
            return False
        if not getattr(sys.__stdout__, "isatty", lambda: False)():
            return False
        try:
            rows = shutil.get_terminal_size().lines
        except OSError:
            return False
        return output.count("\n") > max(rows - 2, 10)

    # --- nick / target / view completion sources -----------------------------

    def _nicks(self) -> list[str]:
        return sorted({e.user for e in self.state.entries if e.user})

    def _targets(self) -> list[str]:
        return sorted({e.target for e in self.state.entries if e.target})

    def _complete_prefix(self, text: str, options: Iterable[str]) -> list[str]:
        tl = text.lower()
        return [o for o in options if o.lower().startswith(tl)]

    def _complete_path(self, text: str) -> list[str]:
        head, tail = os.path.split(text)
        base = head or "."
        try:
            items = os.listdir(base)
        except OSError:
            return []
        out = []
        for it in items:
            if not it.startswith(tail):
                continue
            full = os.path.join(head, it) if head else it
            if os.path.isdir(os.path.join(base, it)):
                full += os.sep
            out.append(full)
        return out

    # --- input pipeline (alias / chaining / redirect / capture / pager) -----

    def onecmd(self, line: str) -> bool:  # type: ignore[override]
        if not isinstance(line, str):
            return super().onecmd(line)
        line = line.strip()
        if not line:
            return super().onecmd(line)

        # ?? → commands
        if line == "??":
            line = "commands"

        # Alias expansion (first whitespace-separated token only)
        head, sep, rest = line.partition(" ")
        if head in self.state.aliases:
            line = self.state.aliases[head] + (sep + rest if sep else "")

        # ; chaining: dispatch each sub-command via onecmd recursively
        if ";" in line:
            parts = self._split_chained(line)
            if len(parts) > 1:
                stop = False
                for sub in parts:
                    stop = bool(self.onecmd(sub))
                    if stop:
                        break
                return stop

        # Trailing redirect
        redirect: tuple[str, str] | None = None
        m = self._REDIRECT_RE.match(line)
        if m:
            line = m.group(1)
            op, path = m.group(2), m.group(3)
            redirect = (path, "a" if op == ">>" else "w")

        # Real-time commands bypass capture (so foreground watch streams)
        head_token = line.split()[0] if line.split() else ""
        if head_token in self.NO_CAPTURE_CMDS:
            return super().onecmd(line)

        # Capture stdout for last/pager/redirect
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                result = super().onecmd(line)
            except Exception as exc:  # noqa: BLE001
                print(f"Error: {exc}")
                result = False
        output = buf.getvalue()
        self.state.last_output = output

        if redirect:
            path, mode = redirect
            try:
                with open(path, mode, encoding="utf-8") as f:
                    f.write(output)
                sys.stdout.write(f"Wrote {len(output)} chars to {path}\n")
            except OSError as exc:
                sys.stdout.write(f"Could not write {path}: {exc}\n")
        elif self.state.pager_enabled and not self._in_script and self._should_page(output):
            try:
                pydoc.pager(output)
            except Exception:  # noqa: BLE001
                sys.stdout.write(output)
        else:
            sys.stdout.write(output)
        return result

    def postcmd(self, stop, line):  # type: ignore[override]
        self._refresh_prompt()
        return stop

    # --- commands ------------------------------------------------------------

    def do_load(self, arg: str) -> None:
        """load <path>   Load a different log file."""
        path = arg.strip().strip('"').strip("'")
        if not path:
            print(f"Currently loaded: {self.state.log_path} ({len(self.state.entries)} entries)")
            return
        try:
            entries = list(iter_entries(path))
        except FileNotFoundError:
            print(f"File not found: {path}")
            return
        self.state.log_path = path
        self.state.entries = entries
        print(f"Loaded {len(entries)} entries from {path}")
        self._refresh_prompt()

    def do_reload(self, arg: str) -> None:
        """reload   Re-read the current log file from disk."""
        try:
            self.state.entries = list(iter_entries(self.state.log_path))
            print(f"Reloaded {len(self.state.entries)} entries from {self.state.log_path}")
            self._refresh_prompt()
        except FileNotFoundError:
            print(f"File not found: {self.state.log_path}")

    def do_report(self, arg: str) -> None:
        """report [user]   Full stats report. With a user, restrict to lines for/about them."""
        user = arg.strip() or self.state.focused_user
        if user:
            entries = self._filtered(user)
            print(f"=== {self.state.log_path}  filtered to user '{user}' ===")
        elif self.state.focused_target:
            entries = self._filtered_by_target(self.state.focused_target)
            print(f"=== {self.state.log_path}  filtered to target '{self.state.focused_target}' ===")
        else:
            entries = self._active_entries()
            print(f"=== {self.state.log_path} ===")
        print_report(summarize(entries, self.state.top_n))

    def do_user(self, arg: str) -> None:
        """user <nick>   Focus on a user (empty arg clears)."""
        nick = arg.strip()
        self._push_focus()
        if not nick:
            self.state.focused_user = None
            print("Cleared focused user.")
        else:
            self.state.focused_user = nick
            matched = self._filtered(nick)
            print(f"Focused on '{nick}' — {len(matched)} matching lines.")
        self._refresh_prompt()

    def do_target(self, arg: str) -> None:
        """target <chan>   Focus on a target/channel (empty arg clears)."""
        t = arg.strip()
        self._push_focus()
        if not t:
            self.state.focused_target = None
            print("Cleared focused target.")
        else:
            self.state.focused_target = t
            matched = self._filtered_by_target(t)
            print(f"Focused on target '{t}' — {len(matched)} matching lines.")
        self._refresh_prompt()

    def do_since(self, arg: str) -> None:
        """since <when>   Lower time bound (ISO date, '5h ago', 'now'; empty clears)."""
        s = arg.strip()
        self._push_focus()
        if not s:
            self.state.since = None
            print("Cleared 'since'.")
        else:
            ts = parse_iso_arg(s)
            if not ts:
                self.state.focus_back.pop()
                print(f"Could not parse: {s!r}")
                return
            self.state.since = ts
            print(f"since = {ts}")
        self._refresh_prompt()

    def do_until(self, arg: str) -> None:
        """until <when>   Upper time bound (ISO date, '5h ago', 'now'; empty clears)."""
        s = arg.strip()
        self._push_focus()
        if not s:
            self.state.until = None
            print("Cleared 'until'.")
        else:
            ts = parse_iso_arg(s)
            if not ts:
                self.state.focus_back.pop()
                print(f"Could not parse: {s!r}")
                return
            self.state.until = ts
            print(f"until = {ts}")
        self._refresh_prompt()

    def do_clear_filters(self, arg: str) -> None:
        """clear_filters   Clear focused user/target and since/until."""
        self._push_focus()
        self.state.focused_user = None
        self.state.focused_target = None
        self.state.since = None
        self.state.until = None
        print("Cleared all global filters.")
        self._refresh_prompt()

    def do_back(self, arg: str) -> None:
        """back   Restore previous focus state."""
        if not self.state.focus_back:
            print("(no previous focus)")
            return
        cur = (self.state.focused_user, self.state.focused_target,
               self.state.since, self.state.until)
        self.state.focus_forward.append(cur)
        prev = self.state.focus_back.pop()
        (self.state.focused_user, self.state.focused_target,
         self.state.since, self.state.until) = prev
        print("Restored previous focus.")
        self._refresh_prompt()

    def do_forward(self, arg: str) -> None:
        """forward   Re-apply focus undone by 'back'."""
        if not self.state.focus_forward:
            print("(no forward focus)")
            return
        cur = (self.state.focused_user, self.state.focused_target,
               self.state.since, self.state.until)
        self.state.focus_back.append(cur)
        nxt = self.state.focus_forward.pop()
        (self.state.focused_user, self.state.focused_target,
         self.state.since, self.state.until) = nxt
        print("Reapplied focus.")
        self._refresh_prompt()

    def do_analyze(self, arg: str) -> None:
        """analyze [nick]   LLM behavior analysis on a user's lines."""
        user = self._resolve_user(arg)
        if not user:
            return
        matched = self._filtered(user)
        if not matched:
            print(f"No lines match '{user}'.")
            return
        analyze_user_with_llm(
            user, [e.text for e in matched],
            self.state.llm_url, self.state.llm_model,
            self.state.max_chunk_chars, cache=self.state.llm_cache,
        )

    def do_ask(self, arg: str) -> None:
        """ask [nick] "<question>"   Free-form LLM question about a user's lines."""
        parts = self._split(arg)
        if not parts:
            print('Usage: ask [nick] "<question>"')
            return
        if len(parts) >= 2 and any(
            e.user and e.user.lower() == parts[0].lower()
            for e in self._active_entries()
        ):
            nick = parts[0]
            question = " ".join(parts[1:])
        else:
            nick = self.state.focused_user
            question = " ".join(parts)
        if not nick:
            print('Usage: ask <nick> "<question>"  (or set "user <nick>" first)')
            return
        matched = self._filtered(nick)
        if not matched:
            print(f"No lines match '{nick}'.")
            return
        ask_about_user_with_llm(
            nick, question, [e.text for e in matched],
            self.state.llm_url, self.state.llm_model,
            self.state.max_chunk_chars, cache=self.state.llm_cache,
        )

    def do_show(self, arg: str) -> None:
        """show [nick] [N]   Print up to N raw lines for the user (default 10)."""
        parts = self._split(arg)
        nick = None
        n = 10
        for p in parts:
            if p.isdigit():
                n = int(p)
            else:
                nick = p
        user = self._resolve_user(nick or "")
        if not user:
            return
        matched = self._filtered(user)
        if not matched:
            print(f"No lines match '{user}'.")
            return
        self.state.last_entries = matched[:n]
        print(f"First {min(n, len(matched))}/{len(matched)} lines for '{user}':")
        for e in matched[:n]:
            print(f"  {e.raw[:300]}")

    def do_interact(self, arg: str) -> None:
        """interact <userA> <userB> [--no-llm] [--show N]"""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: interact <userA> <userB> [--no-llm] [--show N]")
            return
        a, b = parts[0], parts[1]
        no_llm = False
        show_n = 0
        i = 2
        while i < len(parts):
            tok = parts[i]
            if tok == "--no-llm":
                no_llm = True
            elif tok == "--show" and i + 1 < len(parts) and parts[i + 1].isdigit():
                show_n = int(parts[i + 1])
                i += 1
            else:
                print(f"Unknown option: {tok}")
                return
            i += 1

        matched = [e for e in self._active_entries() if line_is_interaction(e, a, b)]
        if not matched:
            print(f"No direct interactions found between '{a}' and '{b}'.")
            return

        print(f"=== {self.state.log_path}  interactions: {a} ↔ {b} ({len(matched)} lines) ===")
        by_author = Counter(e.user for e in matched if e.user)
        print("Lines per author:")
        for nick, n in by_author.most_common():
            print(f"  {n:>7}  {nick}")
        by_target = Counter(e.target for e in matched if e.target)
        if by_target:
            print("Where they interact:")
            for tgt, n in by_target.most_common(10):
                print(f"  {n:>7}  {tgt}")
        ts_list = [e.ts for e in matched if e.ts]
        if ts_list:
            print(f"Time range: {min(ts_list)}  →  {max(ts_list)}")

        if show_n:
            print(f"\nFirst {min(show_n, len(matched))} interaction lines:")
            for e in matched[:show_n]:
                print(f"  {e.text[:300]}")

        if not no_llm:
            analyze_interaction_with_llm(
                a, b, [e.text for e in matched],
                self.state.llm_url, self.state.llm_model,
                self.state.max_chunk_chars, cache=self.state.llm_cache,
            )

    def do_compare(self, arg: str) -> None:
        """compare <userA> <userB> [<userC> ...] [--no-llm]
        Multi-user behavior comparison: side-by-side table + LLM."""
        parts = self._split(arg)
        users = [p for p in parts if not p.startswith("--")]
        flags = [p for p in parts if p.startswith("--")]
        if len(users) < 2:
            print("Usage: compare <userA> <userB> [<userC> ...] [--no-llm]")
            return
        no_llm = "--no-llm" in flags

        active = self._active_entries()
        profiles = [build_profile(active, u) for u in users]

        print(f"=== {self.state.log_path}  compare: {' vs '.join(users)} ===")
        if not any(p["authored"] for p in profiles):
            print(f"None of {users} authored lines in this log.")
            return
        for p in profiles:
            if p["authored"] == 0:
                print(f"Note: '{p['user']}' has no authored lines; only mentions count.")

        print_compare_table_n(profiles)

        if not no_llm:
            compare_n_users_with_llm(profiles, self.state.llm_url,
                                     self.state.llm_model,
                                     self.state.max_chunk_chars,
                                     cache=self.state.llm_cache)

    def do_top(self, arg: str) -> None:
        """top [users|events|targets|levels] [N]"""
        parts = self._split(arg) or ["users"]
        kind = parts[0].lower()
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else self.state.top_n
        s = summarize(self._active_entries(), n)
        key = {"users": "top_users", "events": "top_events",
               "targets": "top_targets", "channels": "top_targets",
               "levels": None}.get(kind)
        if kind == "levels":
            print(s["levels"] or "(none)")
            return
        if not key or not s.get(key):
            print(f"Unknown or empty: {kind}. Try: users | events | targets | levels")
            return
        rows = s[key]
        self.state.last_listing = [name for name, _ in rows]
        for name, count in rows:
            note = self.state.notes.get(name, "") if kind == "users" else ""
            note_str = f"  // {note}" if note else ""
            print(f"  {count:>7}  {name}{note_str}")

    def do_hours(self, arg: str) -> None:
        """hours [compact]   Activity histogram by hour-of-day. Auto-compact when narrow."""
        s = summarize(self._active_entries(), self.state.top_n)
        if not s["by_hour"]:
            print("(no timestamps)")
            return
        try:
            width = shutil.get_terminal_size().columns
        except OSError:
            width = 80
        compact = arg.strip() == "compact" or width < 60
        if compact:
            all_hours = [s["by_hour"].get(h, 0) for h in range(24)]
            print(f"  {sparkline(all_hours)}  (00..23)  total={sum(all_hours)}")
            return
        peak = max(s["by_hour"].values()) or 1
        for h, n in s["by_hour"].items():
            bar = "█" * int(40 * n / peak)
            print(f"  {h:02d}  {n:>7}  {bar}")

    def do_days(self, arg: str) -> None:
        """days [compact]   Activity histogram by date. Auto-compact when narrow."""
        s = summarize(self._active_entries(), self.state.top_n)
        if not s["by_day"]:
            print("(no timestamps)")
            return
        try:
            width = shutil.get_terminal_size().columns
        except OSError:
            width = 80
        compact = arg.strip() == "compact" or width < 60
        if compact:
            days = sorted(s["by_day"].items())
            counts = [n for _, n in days]
            print(f"  {sparkline(counts)}  ({days[0][0]}..{days[-1][0]})  total={sum(counts)}")
            return
        peak = max(s["by_day"].values()) or 1
        for d, n in s["by_day"].items():
            bar = "█" * int(40 * n / peak)
            print(f"  {d}  {n:>7}  {bar}")

    def do_errors(self, arg: str) -> None:
        """errors   Error-like entries."""
        active = self._active_entries()
        s = summarize(active, self.state.top_n)
        if not s["errors"]:
            print("(none)")
            return
        # Re-derive Entry objects to populate last_entries (summarize loses them).
        err_entries: list[Entry] = []
        seen_raw = set(s["errors"])
        for e in active:
            if e.raw in seen_raw:
                err_entries.append(e)
                if len(err_entries) >= len(s["errors"]):
                    break
        self.state.last_entries = err_entries
        for line in s["errors"]:
            print(f"  {line[:300]}")

    def do_grep(self, arg: str) -> None:
        """grep [--user U] [--target T] [--since W] [--until W] [--score 'EXPR'] <regex>"""
        parts = self._split(arg)
        user = self.state.focused_user
        target = self.state.focused_target
        since = self.state.since
        until = self.state.until
        score_filters: list[tuple[str, str, float]] = []
        positional: list[str] = []
        i = 0
        while i < len(parts):
            tok = parts[i]
            if tok == "--user" and i + 1 < len(parts):
                user = parts[i + 1]; i += 2; continue
            if tok == "--target" and i + 1 < len(parts):
                target = parts[i + 1]; i += 2; continue
            if tok == "--since" and i + 1 < len(parts):
                since = parse_iso_arg(parts[i + 1]); i += 2; continue
            if tok == "--until" and i + 1 < len(parts):
                until = parse_iso_arg(parts[i + 1]); i += 2; continue
            if tok == "--score" and i + 1 < len(parts):
                try:
                    score_filters = parse_score_filter(parts[i + 1])
                except ValueError as exc:
                    print(f"Bad score filter: {exc}"); return
                i += 2; continue
            positional.append(tok); i += 1
        if not positional:
            print("Usage: grep [--user U] [--target T] [--since W] [--until W] [--score 'EXPR'] <regex>")
            return
        pattern = " ".join(positional)
        try:
            rx = re.compile(pattern, re.I)
        except re.error as exc:
            print(f"Bad regex: {exc}")
            return
        u_l = user.lower() if user else None
        t_l = target.lower() if target else None
        matched: list[Entry] = []
        for e in self.state.entries:
            if not in_time_range(e.ts, since, until):
                continue
            if u_l and not (e.user and e.user.lower() == u_l) and u_l not in (e.raw or "").lower():
                continue
            if t_l and not (e.target and e.target.lower() == t_l):
                continue
            if score_filters and not matches_score_filter(e, score_filters):
                continue
            if rx.search(e.raw):
                matched.append(e)
                print(f"  {e.raw[:300]}")
                if len(matched) >= 50:
                    print("(truncated at 50 matches — refine your pattern)")
                    break
        self.state.last_entries = matched
        if not matched:
            print("(no matches)")

    # --- new analytic commands ----------------------------------------------

    def do_flagged(self, arg: str) -> None:
        """flagged "EXPR" [user]   Lines where score expr matches.
        e.g. flagged "llama>0.8"     flagged "llama>=0.7 heu>0.5" cfuser"""
        parts = self._split(arg)
        if not parts:
            print('Usage: flagged "EXPR" [user]   e.g. flagged "llama>0.8"')
            return
        expr = parts[0]
        user = parts[1] if len(parts) > 1 else self.state.focused_user
        try:
            filters = parse_score_filter(expr)
        except ValueError as exc:
            print(f"Bad score expression: {exc}")
            return
        u_l = user.lower() if user else None
        cap = 100
        matched: list[Entry] = []
        for e in self._active_entries():
            if u_l and not (e.user and e.user.lower() == u_l):
                continue
            if not matches_score_filter(e, filters):
                continue
            matched.append(e)
            print(f"  {e.raw[:300]}")
            if len(matched) >= cap:
                print(f"(truncated at {cap} matches — refine your filter)")
                break
        self.state.last_entries = matched
        if not matched:
            print("(no matches)")
        else:
            print(f"({len(matched)} match{'es' if len(matched) != 1 else ''})")

    def do_dist(self, arg: str) -> None:
        """dist [user]   Score distributions / percentiles. No user → population."""
        user = arg.strip() or self.state.focused_user
        active = self._active_entries()
        if user:
            scores = collect_scores(active, user)
            label = user
        else:
            scores = collect_scores(active)
            label = "(population)"
        print_score_dist(label, scores)

    def do_zscores(self, arg: str) -> None:
        """zscores [user]   Per-score z-scores for user vs population."""
        user = self._resolve_user(arg)
        if not user:
            return
        active = self._active_entries()
        profile = build_profile(active, user)
        pop = population_score_stats(active)
        print_zscores(profile, pop)

    def do_similar(self, arg: str) -> None:
        """similar [threshold] [min_lines]   Find user pairs with similar fingerprints."""
        parts = self._split(arg)
        threshold = 0.95
        min_lines = 5
        if len(parts) >= 1:
            try:
                threshold = float(parts[0])
            except ValueError:
                print("threshold must be a float between 0 and 1"); return
        if len(parts) >= 2:
            try:
                min_lines = int(parts[1])
            except ValueError:
                print("min_lines must be int"); return
        pairs = find_similar_users(self._active_entries(),
                                   min_lines=min_lines, threshold=threshold)
        # Record both members of each pair for `pick`
        seen: list[str] = []
        for a, b, *_ in pairs:
            if a not in seen:
                seen.append(a)
            if b not in seen:
                seen.append(b)
        self.state.last_listing = seen
        print_similar_users(pairs)

    def do_bursts(self, arg: str) -> None:
        """bursts [user] [window_seconds] [z_threshold]   Detect activity bursts."""
        parts = self._split(arg)
        nick = None
        window = 60
        z = 3.0
        floats: list[float] = []
        for p in parts:
            try:
                v = float(p)
                floats.append(v)
            except ValueError:
                if nick is None:
                    nick = p
        if len(floats) >= 1:
            window = int(floats[0])
        if len(floats) >= 2:
            z = floats[1]
        user = self._resolve_user(nick or "")
        if not user:
            return
        bursts = detect_bursts(self._active_entries(), user,
                               window_seconds=window, z_threshold=z)
        print_bursts(user, bursts, window)

    def do_threads(self, arg: str) -> None:
        """threads [user]   Reply/mention reconstruction around a user."""
        user = self._resolve_user(arg)
        if not user:
            return
        thread = build_thread_for_user(self._active_entries(), user)
        if not thread:
            print(f"No thread lines for {user}.")
            return
        self.state.last_entries = [e for e, _ in thread[:200]]
        print(f"\nThread reconstruction for {user} ({len(thread)} lines):")
        for e, tgt in thread[:200]:
            arrow = f" -> {tgt}" if tgt else ""
            ts = _fmt_dt(e.ts)
            print(f"  {ts}  {(e.user or '?'):>15}{arrow:<20}  {(e.text or e.raw)[:160]}")
        if len(thread) > 200:
            print(f"(showing first 200 of {len(thread)})")

    def do_edges(self, arg: str) -> None:
        """edges [N]   Top N reply/mention edges."""
        parts = self._split(arg)
        n = int(parts[0]) if parts and parts[0].isdigit() else 25
        edges = build_edge_graph(self._active_entries())
        if not edges:
            print("(no edges detected)")
            return
        print(f"\nTop {min(n, len(edges))} edges (source -> target, weight):")
        for (a, b), w in edges.most_common(n):
            print(f"  {w:>5}  {a} -> {b}")

    def do_view(self, arg: str) -> None:
        """view {save NAME | load NAME | list | drop NAME | show NAME}
        Save the current global filters as a named view."""
        parts = self._split(arg)
        if not parts:
            self.do_view("list")
            return
        cmd_ = parts[0].lower()
        if cmd_ == "list":
            if not self.state.views:
                print("(no saved views)")
                return
            for name, v in self.state.views.items():
                print(f"  {name}: {view_describe(v)}")
            return
        if cmd_ == "save":
            if len(parts) < 2:
                print("Usage: view save NAME"); return
            name = parts[1]
            self.state.views[name] = View(
                name=name,
                user=self.state.focused_user,
                target=self.state.focused_target,
                since=self.state.since,
                until=self.state.until,
            )
            print(f"Saved view '{name}': {view_describe(self.state.views[name])}")
            return
        if cmd_ == "load":
            if len(parts) < 2 or parts[1] not in self.state.views:
                print("Usage: view load NAME (existing: " + ", ".join(self.state.views) + ")")
                return
            v = self.state.views[parts[1]]
            self.state.focused_user = v.user
            self.state.focused_target = v.target
            self.state.since = v.since
            self.state.until = v.until
            print(f"Loaded view '{v.name}': {view_describe(v)}")
            self._refresh_prompt()
            return
        if cmd_ == "drop":
            if len(parts) < 2:
                print("Usage: view drop NAME"); return
            self.state.views.pop(parts[1], None)
            print(f"Dropped view '{parts[1]}'.")
            return
        if cmd_ == "show":
            if len(parts) < 2 or parts[1] not in self.state.views:
                print("Usage: view show NAME"); return
            v = self.state.views[parts[1]]
            print(f"  {v.name}: {view_describe(v)}")
            return
        print(f"Unknown view subcommand: {cmd_}")

    def do_export(self, arg: str) -> None:
        """export {profile <user> <path.json|csv> | report <path.json> | edges <path.csv|dot>}"""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: export profile <user> <path>  |  export report <path>  |  export edges <path>")
            return
        kind = parts[0].lower()
        if kind == "profile":
            if len(parts) < 3:
                print("Usage: export profile <user> <path>"); return
            user, path = parts[1], parts[2]
            profile = build_profile(self._active_entries(), user)
            ext = os.path.splitext(path)[1].lower()
            if ext == ".csv":
                export_profile_csv(profile, path)
            else:
                export_profile_json(profile, path)
            print(f"Wrote {path}")
            return
        if kind == "report":
            path = parts[1]
            export_summary_json(summarize(self._active_entries(), self.state.top_n), path)
            print(f"Wrote {path}")
            return
        if kind == "edges":
            path = parts[1]
            edges = build_edge_graph(self._active_entries())
            ext = os.path.splitext(path)[1].lower()
            if ext == ".dot":
                export_edges_dot(edges, path)
            else:
                export_edges_csv(edges, path)
            print(f"Wrote {path} ({len(edges)} edges)")
            return
        print(f"Unknown export kind: {kind}")

    def do_diff(self, arg: str) -> None:
        """diff <other.log>   Diff current log against another."""
        path = arg.strip()
        if not path:
            print("Usage: diff <other.log>"); return
        try:
            other = list(iter_entries(path))
        except FileNotFoundError:
            print(f"File not found: {path}"); return
        a = summarize(self._active_entries(), 1000)
        b = summarize(other, 1000)
        print_log_diff(self.state.log_path, path, diff_summaries(a, b))

    def do_watch(self, arg: str) -> None:
        """watch [poll_seconds] [--bg | --stop]
        Tail the current log file. --bg runs in a background thread (prompt
        shows '+N new'); --stop terminates a running background watch."""
        parts = self._split(arg)
        if "--stop" in parts:
            if self.state.watch_bg:
                self.state.watch_bg.stop()
                self.state.watch_bg = None
                print("Stopped background watch.")
            else:
                print("(no background watch running)")
            return
        bg = "--bg" in parts
        nums = [p for p in parts if p not in ("--bg", "--stop")]
        poll = 2.0
        if nums:
            try:
                poll = float(nums[0])
            except ValueError:
                print("poll_seconds must be a number"); return
        if bg:
            if self.state.watch_bg:
                print("(background watch already running; use 'watch --stop')")
                return
            self.state.watch_bg = WatchBg(self, poll=poll)
            self.state.watch_bg.start()
            print(f"Watching {self.state.log_path} in background (poll={poll}s). 'watch --stop' to halt.")
            return

        def on_new(new: list[Entry]) -> None:
            self.state.entries.extend(new)
            watch_callback_default(new)
            self._refresh_prompt()

        print(f"Watching {self.state.log_path} (poll={poll}s). Ctrl-C to stop.")
        watch_loop(self.state.log_path, on_new, poll_seconds=poll)

    def do_set(self, arg: str) -> None:
        """set <key> <value>   Configure: top, llm_url, llm_model, max_chunk_chars,
        llm_cache, pager (on/off), color (on/off)."""
        parts = self._split(arg)
        if len(parts) < 2:
            self.do_settings("")
            return
        key, value = parts[0], " ".join(parts[1:])
        bool_yes = {"on", "yes", "true", "1"}
        if key == "top":
            try:
                self.state.top_n = int(value)
            except ValueError:
                print("top must be an integer"); return
        elif key == "llm_url":
            self.state.llm_url = value
        elif key == "llm_model":
            self.state.llm_model = value
        elif key == "max_chunk_chars":
            try:
                self.state.max_chunk_chars = int(value)
            except ValueError:
                print("max_chunk_chars must be an integer"); return
        elif key == "llm_cache":
            if value.lower() in {"none", "off", ""}:
                self.state.llm_cache = None
            else:
                self.state.llm_cache = LLMCache(value)
            print(f"llm_cache = {value or '(off)'}")
            return
        elif key == "pager":
            self.state.pager_enabled = value.lower() in bool_yes
            print(f"pager = {self.state.pager_enabled}")
            return
        elif key == "color":
            on = value.lower() in bool_yes
            self.state.color_enabled = on
            _Color.enabled = on
            print(f"color = {on}")
            return
        else:
            print(f"Unknown setting: {key}. See 'settings'.")
            return
        attr = "top_n" if key == "top" else key
        print(f"{key} = {getattr(self.state, attr)}")

    def do_settings(self, arg: str) -> None:
        """settings   Show current settings."""
        st = self.state
        print(f"  log_path        = {st.log_path}")
        print(f"  entries         = {len(st.entries)}  active = {len(self._active_entries())}")
        print(f"  focused_user    = {st.focused_user}")
        print(f"  focused_target  = {st.focused_target}")
        print(f"  since           = {st.since}")
        print(f"  until           = {st.until}")
        print(f"  top             = {st.top_n}")
        print(f"  llm_url         = {st.llm_url}")
        print(f"  llm_model       = {st.llm_model}")
        print(f"  max_chunk_chars = {st.max_chunk_chars}")
        if st.llm_cache:
            print(f"  llm_cache       = {st.llm_cache.path}  ({len(st.llm_cache)} entries)")
        else:
            print(f"  llm_cache       = (off)")
        print(f"  pager           = {st.pager_enabled}")
        print(f"  color           = {st.color_enabled}")
        if st.views:
            print(f"  views           = {', '.join(st.views)}")
        if st.aliases:
            print(f"  aliases         = {len(st.aliases)} ({', '.join(list(st.aliases)[:5])}{'...' if len(st.aliases) > 5 else ''})")
        if st.ignore_set:
            print(f"  ignored         = {len(st.ignore_set)} users")
        if st.notes:
            print(f"  notes           = {len(st.notes)} users")
        if st.watch_bg:
            print(f"  watch_bg        = running (+{st.watch_bg.new_count} new since last check)")
        print(f"  back/fwd        = {len(st.focus_back)}/{len(st.focus_forward)}")

    def do_commands(self, arg: str) -> None:
        """commands   Print all commands with a short description and usage."""
        ref: list[tuple[str, str, str]] = [
            ("load", "load <path>", "Load a different log file."),
            ("reload", "reload", "Re-read the current log file from disk."),
            ("watch", "watch [poll_seconds] [--bg | --stop]",
             "Tail the log (foreground or background)."),
            ("report", "report [user]", "Full stats report (honors since/until/focused_target)."),
            ("info", "info [user]", "One-line summary of a user (with note if any)."),
            ("user", "user <nick>", "Set the focused user."),
            ("target", "target <chan>", "Set the focused target/channel."),
            ("since", "since <when>", "Lower time bound (ISO date or '5h ago')."),
            ("until", "until <when>", "Upper time bound."),
            ("back", "back", "Restore previous focus state."),
            ("forward", "forward", "Re-apply focus undone by 'back'."),
            ("clear_filters", "clear_filters", "Clear focused user/target and since/until."),
            ("analyze", "analyze [nick]", "LLM behavior analysis on a user's lines."),
            ("ask", 'ask [nick] "<question>"', "Free-form LLM question via the chunking pipeline."),
            ("interact", "interact <A> <B> [--show N] [--no-llm]",
             "Direct exchanges between two users + LLM relationship analysis."),
            ("compare", "compare <A> <B> [<C>...] [--no-llm]",
             "Multi-user behavior comparison: side-by-side table + LLM."),
            ("show", "show [nick] [N]", "Print up to N raw lines for the user (default 10)."),
            ("flagged", 'flagged "EXPR" [user]',
             'Lines where score expression matches (e.g. "llama>0.8 heu>0.5").'),
            ("dist", "dist [user]", "Score distributions / percentiles (no user = population)."),
            ("zscores", "zscores [user]", "Per-score z-scores for user vs population."),
            ("similar", "similar [threshold] [min_lines]", "Find user pairs with similar fingerprints."),
            ("bursts", "bursts [user] [window_s] [z]", "Detect activity bursts."),
            ("threads", "threads [user]", "Reply/mention reconstruction around a user."),
            ("edges", "edges [N]", "Top N reply/mention edges in the corpus."),
            ("top", "top [users|events|targets|levels] [N]", "Show a top-N ranking."),
            ("hours", "hours [compact]", "Activity histogram by hour-of-day (sparkline if narrow)."),
            ("days", "days [compact]", "Activity histogram by date (sparkline if narrow)."),
            ("errors", "errors", "Error-like entries."),
            ("grep", "grep [--user U] [--target T] [--since W] [--until W] [--score E] <regex>",
             "Filtered regex search (cap 50)."),
            ("pick", "pick <N>", "Focus on the Nth item from the previous listing."),
            ("inspect", "inspect <N>", "Show full details for the Nth entry from the previous listing."),
            ("last", "last", "Re-print the previous command's output."),
            ("view", "view {save|load|drop|show|list} [NAME]", "Save/load named filter sets."),
            ("export", "export {profile <user> <path> | report <path> | edges <path>}",
             "Serialize profiles, summary, or edge graph."),
            ("diff", "diff <other.log>", "Diff current log against another."),
            ("script", "script <path>", "Run TUI commands from a file (one per line; # comments)."),
            ("alias", "alias [<name> = <command>]",
             "Define/list/remove aliases (persisted)."),
            ("ignore", "ignore [add|drop|list] <user...>",
             "Maintain global ignore list (excluded from analyses)."),
            ("note", "note <user> [<text> | --del]", "Attach a note to a user (persisted)."),
            ("set", "set <key> <value>",
             "Configure: top, llm_url, llm_model, max_chunk_chars, llm_cache, pager, color."),
            ("settings", "settings", "Show current settings."),
            ("commands", "commands  (or ??)", "Print this reference."),
            ("help", "help [name]  (or ?<name>)", "Built-in help."),
            ("quit", "quit  (exit, Ctrl-D)", "Exit the shell."),
        ]
        usage_w = min(max(len(u) for _, u, _ in ref), 70)
        print(f"\n  {'COMMAND'.ljust(usage_w)}   DESCRIPTION")
        print(f"  {'-' * usage_w}   {'-' * 40}")
        for _name, usage, desc in ref:
            print(f"  {usage[:usage_w].ljust(usage_w)}   {desc}")
        print(
            "\n  Tips:\n"
            "    - Quote args containing spaces.\n"
            "    - Global filters (user/target/since/until) apply to most commands.\n"
            "    - 'view save NAME' captures the current global filters.\n"
            "    - 'set llm_url http://host:port/' switches the LLM endpoint at runtime.\n"
            "    - Launch with --c to print this reference on startup."
        )

    def do_quit(self, arg: str) -> bool:
        """quit   Exit the shell."""
        if self.state.watch_bg:
            self.state.watch_bg.stop()
            self.state.watch_bg = None
        if self.state.llm_cache:
            self.state.llm_cache.save()
        self._save_history()
        return True

    do_exit = do_quit
    do_EOF = do_quit

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        print(f"Unknown command: {line.split()[0] if line.split() else ''}. Try 'help'.")

    # --- new commands: info / pick / inspect / last / script / alias / ignore / note ---

    def do_info(self, arg: str) -> None:
        """info [user]   One-line user summary (uses focused_user if no arg)."""
        user = self._resolve_user(arg)
        if not user:
            return
        profile = build_profile(self._time_filtered(), user)
        sm = profile["score_means"]
        peak = _peak_hours(profile["by_hour"]).split(",")[0] or "—"
        top_chan = _top_str(profile["channels"], 1) or "—"
        score_strs = []
        for k in SCORE_KEYS:
            v = sm.get(k)
            score_strs.append(f"{k}={_color_score(v) if isinstance(v, float) else '—'}")
        note = self.state.notes.get(user, "")
        bits = [
            user,
            f"lines={profile['authored']}",
            f"days={len(profile['by_day'])}",
            f"peak={peak}",
            f"top_chan={top_chan}",
            *score_strs,
        ]
        if note:
            bits.append(f"note=\"{note}\"")
        if user in self.state.ignore_set:
            bits.append("[IGNORED]")
        print("  " + "  ".join(bits))

    def do_pick(self, arg: str) -> None:
        """pick <N>   Focus on the Nth item from the previous listing (1-indexed).
        Falls back to the author of the Nth entry from the previous entry list."""
        parts = self._split(arg)
        if not parts or not parts[0].isdigit():
            print("Usage: pick <N>"); return
        idx = int(parts[0]) - 1
        listing = self.state.last_listing
        if not listing and self.state.last_entries:
            seen: list[str] = []
            for e in self.state.last_entries:
                if e.user and e.user not in seen:
                    seen.append(e.user)
            listing = seen
        if idx < 0 or idx >= len(listing):
            print(f"No item {idx + 1} in last listing (have {len(listing)}).")
            return
        pick = listing[idx]
        self._push_focus()
        self.state.focused_user = pick
        print(f"Focused user = {pick}")
        self._refresh_prompt()

    def do_inspect(self, arg: str) -> None:
        """inspect <N>   Show full raw line / pretty-printed JSON for entry N from the
        previous listing (flagged, errors, grep, show, threads)."""
        parts = self._split(arg)
        if not parts or not parts[0].isdigit():
            print("Usage: inspect <N>"); return
        idx = int(parts[0]) - 1
        if idx < 0 or idx >= len(self.state.last_entries):
            print(f"No entry {idx + 1} in last listing (have {len(self.state.last_entries)}).")
            return
        e = self.state.last_entries[idx]
        print(f"=== Entry {idx + 1} ({e.fmt}) ===")
        print(f"  ts:     {e.ts}")
        print(f"  user:   {e.user}")
        print(f"  target: {e.target}")
        print(f"  level:  {e.level}")
        print(f"  event:  {e.event}")
        print(f"  text:   {e.text}")
        if e.fmt == "json":
            try:
                obj = json.loads(e.raw)
                print("  json:")
                print(json.dumps(obj, indent=2, default=str))
                return
            except json.JSONDecodeError:
                pass
        print(f"  raw:    {e.raw}")

    def do_last(self, arg: str) -> None:
        """last   Re-print the captured output of the previous command."""
        if not self.state.last_output:
            print("(no previous output)")
            return
        sys.stdout.write(self.state.last_output)

    def do_script(self, arg: str) -> None:
        """script <path>   Run TUI commands from a file (one per line; # comments)."""
        path = arg.strip().strip('"').strip("'")
        if not path:
            print("Usage: script <path>"); return
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError as exc:
            print(f"Could not read {path}: {exc}"); return
        saved_pager = self.state.pager_enabled
        saved_in_script = self._in_script
        self.state.pager_enabled = False
        self._in_script = True
        try:
            for raw in lines:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                print(f"{self.prompt}{line}")
                if self.onecmd(line):
                    return
                self._refresh_prompt()
        finally:
            self.state.pager_enabled = saved_pager
            self._in_script = saved_in_script

    def do_alias(self, arg: str) -> None:
        """alias                       List all aliases.
        alias <name>                 Show one alias.
        alias <name> = <command>     Define/replace.
        alias <name> =               Remove."""
        s = arg.strip()
        if not s:
            if not self.state.aliases:
                print("(no aliases)")
                return
            for name, cmd_ in sorted(self.state.aliases.items()):
                print(f"  {name} = {cmd_}")
            return
        if "=" in s:
            name, _, body = s.partition("=")
            name = name.strip()
            body = body.strip()
            if not name:
                print("Usage: alias <name> = <command>"); return
            if not body:
                self.state.aliases.pop(name, None)
                _save_json(_aliases_path(), self.state.aliases)
                print(f"Removed alias '{name}'.")
                return
            self.state.aliases[name] = body
            _save_json(_aliases_path(), self.state.aliases)
            print(f"alias {name} = {body}")
        else:
            if s in self.state.aliases:
                print(f"  {s} = {self.state.aliases[s]}")
            else:
                print(f"(no alias '{s}')")

    def do_ignore(self, arg: str) -> None:
        """ignore                       List ignored users.
        ignore <user>...             Add to ignore list.
        ignore add <user>...         Add (explicit).
        ignore drop <user>...        Remove from ignore list.
        ignore list                  List ignored users."""
        parts = self._split(arg)
        if not parts or (len(parts) == 1 and parts[0].lower() == "list"):
            if not self.state.ignore_set:
                print("(ignore list empty)")
                return
            for u in sorted(self.state.ignore_set):
                print(f"  {u}")
            return
        sub = parts[0].lower()
        if sub == "add" and len(parts) >= 2:
            for u in parts[1:]:
                self.state.ignore_set.add(u)
        elif sub == "drop" and len(parts) >= 2:
            for u in parts[1:]:
                self.state.ignore_set.discard(u)
        else:
            for u in parts:
                self.state.ignore_set.add(u)
        _save_json(_ignore_path(), sorted(self.state.ignore_set))
        print(f"Ignore list now: {len(self.state.ignore_set)} users.")
        self._refresh_prompt()

    def do_note(self, arg: str) -> None:
        """note                       List notes.
        note <user>                 Show note.
        note <user> <text>          Set note.
        note <user> --del           Remove note."""
        s = arg.strip()
        if not s:
            if not self.state.notes:
                print("(no notes)")
                return
            for u, n in sorted(self.state.notes.items()):
                print(f"  {u}: {n}")
            return
        head, _, body = s.partition(" ")
        user = head
        body = body.strip()
        if not body:
            if user in self.state.notes:
                print(f"  {user}: {self.state.notes[user]}")
            else:
                print(f"(no note for '{user}')")
            return
        if body in {"--del", "--delete", "-d"}:
            removed = self.state.notes.pop(user, None)
            _save_json(_notes_path(), self.state.notes)
            if removed is not None:
                print(f"Removed note for '{user}'.")
            else:
                print(f"(no note for '{user}')")
            return
        self.state.notes[user] = body
        _save_json(_notes_path(), self.state.notes)
        print(f"  {user}: {body}")

    # --- tab completion ------------------------------------------------------

    def complete_user(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_analyze(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_ask(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_compare(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_interact(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_show(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_info(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_dist(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_zscores(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_bursts(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_threads(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_flagged(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) >= 2:
            return self._complete_prefix(text, self._nicks())
        return []

    def complete_target(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._targets())

    def complete_load(self, text, line, begidx, endidx):
        return self._complete_path(text)

    def complete_diff(self, text, line, begidx, endidx):
        return self._complete_path(text)

    def complete_script(self, text, line, begidx, endidx):
        return self._complete_path(text)

    def complete_view(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["save", "load", "drop", "show", "list"])
        if len(prev) == 2 and prev[1] in ("load", "drop", "show"):
            return self._complete_prefix(text, list(self.state.views))
        return []

    def complete_export(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["profile", "report", "edges"])
        if len(prev) == 2 and prev[1] == "profile":
            return self._complete_prefix(text, self._nicks())
        return self._complete_path(text)

    def complete_set(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["top", "llm_url", "llm_model",
                                                "max_chunk_chars", "llm_cache",
                                                "pager", "color"])
        return []

    def complete_alias(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, list(self.state.aliases))
        return []

    def complete_ignore(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["add", "drop", "list"] + self._nicks())
        if len(prev) >= 2 and prev[1] == "drop":
            return self._complete_prefix(text, sorted(self.state.ignore_set))
        return self._complete_prefix(text, self._nicks())

    def complete_note(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, self._nicks())
        return []

    def complete_watch(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["--bg", "--stop"])


# ---------- main -------------------------------------------------------------

def _default_llm_cache_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "analyzelog_llm.json")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    _Color.auto_disable()

    p = argparse.ArgumentParser(description="Interactive log analyzer (TUI by default; --batch for one-shot).")
    p.add_argument("--log", default="ai_scores.log")
    p.add_argument("--user")
    p.add_argument("--users", help="Pair 'A,B' for interaction analysis (--batch only)")
    p.add_argument("--compare", help="Comma list 'A,B[,C,...]' for behavior comparison (--batch only)")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--llm-url", default="http://127.0.0.1:8033/")
    p.add_argument("--llm-model", default="local")
    p.add_argument("--max-chunk-chars", type=int, default=12000)
    p.add_argument("--llm-cache", default=_default_llm_cache_path(),
                   help="Path to LLM response cache JSON ('none' to disable)")
    p.add_argument("--since", help="Time-range lower bound (ISO date or '5h ago')")
    p.add_argument("--until", help="Time-range upper bound (ISO date or '5h ago')")
    p.add_argument("--batch", action="store_true")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--show-lines", type=int, default=0)
    p.add_argument("--ask", help="With --batch and --user, ask a free-form question")
    p.add_argument("--flagged", help="With --batch, list lines matching score expression")
    p.add_argument("--dist", action="store_true",
                   help="With --batch, show score distributions (whole log or --user)")
    p.add_argument("--zscores", action="store_true",
                   help="With --batch and --user, show z-scores vs population")
    p.add_argument("--similar", action="store_true")
    p.add_argument("--similar-threshold", type=float, default=0.95)
    p.add_argument("--similar-min-lines", type=int, default=5)
    p.add_argument("--bursts", help="With --batch, detect bursts for the given user")
    p.add_argument("--bursts-window", type=int, default=60)
    p.add_argument("--bursts-z", type=float, default=3.0)
    p.add_argument("--diff", help="With --batch, diff against another log file")
    p.add_argument("--export-profile", help="With --batch and --user, write profile to this path")
    p.add_argument("--export-report", help="With --batch, write report JSON to this path")
    p.add_argument("--export-edges", help="With --batch, write edges (.csv or .dot)")
    p.add_argument("--watch", action="store_true",
                   help="Tail the log file and print new entries; runs forever")
    p.add_argument("-c", "--cmd", action="append", default=[],
                   help="Run TUI command(s) before the prompt (repeatable). Use 'quit' to exit after.")
    p.add_argument("--c", dest="show_commands", action="store_true",
                   help="On startup, open the TUI and print the full command reference.")
    args = p.parse_args(argv)

    try:
        all_entries = list(iter_entries(args.log))
    except FileNotFoundError:
        print(f"File not found: {args.log}", file=sys.stderr)
        return 1

    since = parse_iso_arg(args.since) if args.since else None
    until = parse_iso_arg(args.until) if args.until else None
    if args.since and not since:
        print(f"Could not parse --since {args.since!r}", file=sys.stderr); return 2
    if args.until and not until:
        print(f"Could not parse --until {args.until!r}", file=sys.stderr); return 2

    active = apply_time_filter(all_entries, since, until)

    cache_path = args.llm_cache
    if cache_path and cache_path.lower() in {"none", "off", ""}:
        cache_path = None
    if cache_path:
        cache_dir = os.path.dirname(cache_path)
        if cache_dir:
            try:
                os.makedirs(cache_dir, exist_ok=True)
            except OSError:
                pass
    cache = LLMCache(cache_path) if cache_path else None

    if args.watch:
        print(f"Watching {args.log}. Ctrl-C to stop.")
        watch_loop(args.log, watch_callback_default)
        return 0

    if args.batch:
        if args.diff:
            try:
                other = list(iter_entries(args.diff))
            except FileNotFoundError:
                print(f"File not found: {args.diff}", file=sys.stderr); return 1
            sa = summarize(active, 1000)
            sb = summarize(other, 1000)
            print_log_diff(args.log, args.diff, diff_summaries(sa, sb))
            return 0

        if args.similar:
            pairs = find_similar_users(active,
                                       min_lines=args.similar_min_lines,
                                       threshold=args.similar_threshold)
            print_similar_users(pairs)
            return 0

        if args.flagged:
            try:
                filters = parse_score_filter(args.flagged)
            except ValueError as exc:
                print(f"Bad score expression: {exc}", file=sys.stderr); return 2
            u_l = args.user.lower() if args.user else None
            count = 0
            for e in active:
                if u_l and not (e.user and e.user.lower() == u_l):
                    continue
                if matches_score_filter(e, filters):
                    print(e.raw)
                    count += 1
            print(f"# {count} matches", file=sys.stderr)
            return 0

        if args.bursts:
            bursts = detect_bursts(active, args.bursts,
                                   window_seconds=args.bursts_window,
                                   z_threshold=args.bursts_z)
            print_bursts(args.bursts, bursts, args.bursts_window)
            return 0

        if args.zscores:
            if not args.user:
                print("--zscores requires --user", file=sys.stderr); return 2
            profile = build_profile(active, args.user)
            pop = population_score_stats(active)
            print_zscores(profile, pop)
            return 0

        if args.dist:
            if args.user:
                print_score_dist(args.user, collect_scores(active, args.user))
            else:
                print_score_dist("(population)", collect_scores(active))
            return 0

        if args.export_edges:
            edges = build_edge_graph(active)
            ext = os.path.splitext(args.export_edges)[1].lower()
            if ext == ".dot":
                export_edges_dot(edges, args.export_edges)
            else:
                export_edges_csv(edges, args.export_edges)
            print(f"Wrote {args.export_edges} ({len(edges)} edges)")
            return 0
        if args.export_report:
            export_summary_json(summarize(active, args.top), args.export_report)
            print(f"Wrote {args.export_report}")
            return 0
        if args.export_profile:
            if not args.user:
                print("--export-profile requires --user", file=sys.stderr); return 2
            profile = build_profile(active, args.user)
            ext = os.path.splitext(args.export_profile)[1].lower()
            if ext == ".csv":
                export_profile_csv(profile, args.export_profile)
            else:
                export_profile_json(profile, args.export_profile)
            print(f"Wrote {args.export_profile}")
            return 0

        if args.compare:
            users = [u.strip() for u in args.compare.split(",") if u.strip()]
            if len(users) < 2:
                print("--compare must be at least 'A,B'", file=sys.stderr); return 2
            profiles = [build_profile(active, u) for u in users]
            print(f"=== {args.log}  compare: {' vs '.join(users)} ===")
            print_compare_table_n(profiles)
            if not args.no_llm:
                compare_n_users_with_llm(profiles, args.llm_url, args.llm_model,
                                         args.max_chunk_chars, cache=cache)
            return 0

        if args.users:
            pair = [u.strip() for u in args.users.split(",") if u.strip()]
            if len(pair) != 2:
                print("--users must be 'A,B'", file=sys.stderr); return 2
            a, b = pair
            matched = [e for e in active if line_is_interaction(e, a, b)]
            print(f"=== {args.log}  interactions: {a} <-> {b} ({len(matched)} lines) ===")
            if args.show_lines:
                for e in matched[:args.show_lines]:
                    print(f"  {e.text[:300]}")
            if not args.no_llm:
                analyze_interaction_with_llm(
                    a, b, [e.text for e in matched],
                    args.llm_url, args.llm_model, args.max_chunk_chars, cache=cache,
                )
            return 0

        if args.ask:
            if not args.user:
                print("--ask requires --user", file=sys.stderr); return 2
            matched = [e for e in active if line_matches_user(e, args.user)]
            print(f"=== {args.log}  ask about '{args.user}': {args.ask} ===")
            if not args.no_llm:
                ask_about_user_with_llm(
                    args.user, args.ask, [e.text for e in matched],
                    args.llm_url, args.llm_model, args.max_chunk_chars, cache=cache,
                )
            return 0

        if args.user:
            matched = [e for e in active if line_matches_user(e, args.user)]
            print(f"=== {args.log}  filtered to user '{args.user}' ===")
            print_report(summarize(matched, args.top))

            if args.show_lines:
                print(f"\nFirst {min(args.show_lines, len(matched))} matched lines:")
                for e in matched[:args.show_lines]:
                    print(f"  {e.raw[:300]}")

            if not args.no_llm:
                analyze_user_with_llm(
                    args.user, [e.text for e in matched],
                    args.llm_url, args.llm_model, args.max_chunk_chars, cache=cache,
                )
        else:
            print(f"=== {args.log} ===")
            print_report(summarize(active, args.top))
        return 0

    state = ShellState(
        log_path=args.log,
        entries=all_entries,
        focused_user=args.user,
        since=since,
        until=until,
        top_n=args.top,
        llm_url=args.llm_url,
        llm_model=args.llm_model,
        max_chunk_chars=args.max_chunk_chars,
        llm_cache=cache,
    )
    shell = LogShell(state)
    shell._refresh_prompt()

    try:
        startup_cmds: list[str] = []
        if args.show_commands:
            startup_cmds.append("commands")
        startup_cmds.extend(args.cmd)

        if startup_cmds:
            print(shell.intro, end="")
            for c in startup_cmds:
                print(f"{shell.prompt}{c}")
                if shell.onecmd(c):
                    return 0
                shell._refresh_prompt()
            shell.cmdloop(intro="")
        else:
            shell.cmdloop()
    except KeyboardInterrupt:
        print()
    finally:
        if state.llm_cache:
            state.llm_cache.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
