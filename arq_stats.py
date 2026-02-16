#!/usr/bin/env python3
"""Scan Arq backup logs and report the most frequently changed files.

"""

from __future__ import annotations

import argparse
import csv
import json
import pydoc
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_LOG_DIR = Path("/Library/Application Support/ArqAgent/logs/backup")
UPLOADED_PREFIX = "Uploaded "
OUTPUT_COLUMNS = ["count", "size", "first_seen", "last_seen", "path"]
RIGHT_ALIGN_COLUMNS = {"count", "size"}
LINE_RE = re.compile(
    r"^(?P<date>\d{2}-[A-Za-z]{3}-\d{4}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<tz>[A-Za-z]{2,6}) (?P<message>.*)$"
)
LOG_NAME_RE = re.compile(r"^backup-(\d+)-")
SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([BKMGTP]?)\s*$", re.IGNORECASE)
SIZE_MULTIPLIERS = {
    "B": 1,
    "K": 1000,
    "M": 1000**2,
    "G": 1000**3,
    "T": 1000**4,
    "P": 1000**5,
}


@dataclass
class FileStats:
    path: str
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def add_event(self, ts: datetime) -> None:
        self.count += 1
        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts


def parse_user_datetime(value: str) -> datetime:
    value = value.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Invalid datetime '{value}'. Use YYYY-MM-DD[ HH:MM]"
    )


def parse_size_bytes(value: str) -> int:
    m = SIZE_RE.match(value)
    if not m:
        raise argparse.ArgumentTypeError(
            f"Invalid size '{value}'. Use NUMBER with optional B/K/M/G/T/P suffix."
        )
    number = float(m.group(1))
    suffix = m.group(2).upper() or "B"
    return int(number * SIZE_MULTIPLIERS[suffix])


def parse_line(line: str) -> tuple[datetime, str] | None:
    m = LINE_RE.match(line)
    if not m:
        return None

    try:
        ts = datetime.strptime(
            f"{m.group('date')} {m.group('time')}", "%d-%b-%Y %H:%M:%S"
        )
    except ValueError:
        return None

    return ts, m.group("message")


def log_start_time_from_name(path: Path) -> datetime | None:
    m = LOG_NAME_RE.match(path.name)
    if not m:
        return None
    try:
        raw = int(m.group(1))
    except ValueError:
        return None
    ts = raw / 1000.0 if raw >= 1_000_000_000_000 else float(raw)
    try:
        return datetime.fromtimestamp(ts)
    except (OSError, OverflowError, ValueError):
        return None


def iter_log_files(log_dir: Path, since: datetime | None, until: datetime | None) -> tuple[list[Path], int]:
    files = sorted(p for p in log_dir.glob("backup-*") if p.is_file())
    if not since and not until:
        return files, 0

    selected: list[Path] = []
    skipped_unparseable = 0
    for p in files:
        started = log_start_time_from_name(p)
        if started is None:
            skipped_unparseable += 1
            continue
        if since and started < since:
            continue
        if until and started > until:
            continue
        selected.append(p)
    return selected, skipped_unparseable


def should_keep_path(path: str, include_re: re.Pattern[str] | None, exclude_re: re.Pattern[str] | None) -> bool:
    return (not include_re or include_re.search(path)) and (
        not exclude_re or not exclude_re.search(path)
    )


def compile_optional_regex(pattern: str | None, flag_name: str) -> re.Pattern[str] | None:
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"Invalid {flag_name} regex: {exc}") from exc


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    class _DefaultsFormatter(argparse.HelpFormatter):
        def _get_help_string(self, action: argparse.Action) -> str:
            text = action.help or ""
            if "%(default)" in text or "default:" in text.lower():
                return text
            if (
                action.default is not None
                and action.default is not argparse.SUPPRESS
                and action.nargs != 0
            ):
                default_val = action.default
                if isinstance(default_val, int):
                    default_text = f"{default_val:,}"
                else:
                    default_text = str(default_val)
                return f"{text} (default: {default_text})"
            return text

    parser = argparse.ArgumentParser(
        description="Top uploaded files from Arq backup logs.",
        formatter_class=_DefaultsFormatter,
    )
    filter_group = parser.add_argument_group("filters")
    display_group = parser.add_argument_group("display")

    parser.add_argument("--log-dir", metavar="DIR", type=Path, default=DEFAULT_LOG_DIR, help="Log directory")

    filter_group.add_argument("--max-logs", metavar="N", type=int, default=100, help="Search newest N logs (0=all; default: 100)")
    filter_group.add_argument(
        "--since",
        metavar="DATETIME",
        type=parse_user_datetime,
        default=None,
        help="Min log time (default: all; ignores time zones; YYYY-MM-DD[ HH:MM])",
    )
    filter_group.add_argument(
        "--until",
        metavar="DATETIME",
        type=parse_user_datetime,
        default=None,
        help="Max log time (default: all; ignores time zones; YYYY-MM-DD[ HH:MM])",
    )
    filter_group.add_argument("--min-count", metavar="N", type=int, default=1, help="Min uploads (default: all)")
    filter_group.add_argument(
        "--min-size",
        metavar="SIZE",
        type=parse_size_bytes,
        default=None,
        help="Min current size (default: off; B/K/M/G/T/P)",
    )
    filter_group.add_argument(
        "--min-space",
        metavar="SIZE",
        type=parse_size_bytes,
        default=None,
        help="Min size*count (default: off; B/K/M/G/T/P)",
    )
    filter_group.add_argument("--include", metavar="REGEX", default=None, help="Include path regex (default: all)")
    filter_group.add_argument("--exclude", metavar="REGEX", default=None, help="Exclude path regex (default: all)")

    display_group.add_argument(
        "-p",
        "--progress",
        dest="progress",
        action="store_true",
        default=None,
        help="Show progress (default if interactive)",
    )
    display_group.add_argument(
        "--no-progress",
        dest="progress",
        action="store_false",
        help="Hide progress (default if piped)",
    )
    display_group.add_argument(
        "-s",
        "--summary",
        dest="summary",
        action="store_true",
        default=None,
        help="Show summary (default if interactive)",
    )
    display_group.add_argument(
        "--no-summary",
        dest="summary",
        action="store_false",
        help="Hide summary (default if piped)",
    )
    display_group.add_argument("--top", metavar="N", type=int, default=25, help="Top N rows")
    display_group.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        metavar="FMT",
        default="table",
        help="Output format: table|json|csv",
    )
    display_group.add_argument(
        "--sort",
        choices=("count", "size", "path"),
        metavar="KEY",
        default="count",
        help="Sort by: count|size|path",
    )
    display_group.add_argument("--no-header", action="store_true", help="Hide header row")
    display_group.add_argument(
        "--show-dates",
        action="store_true",
        help="Show date columns",
    )
    display_group.add_argument(
        "--show-bytes",
        action="store_true",
        help="Show raw byte sizes instead of human-readable sizes",
    )
    return parser.parse_args(argv)


def output_columns(show_dates: bool) -> list[str]:
    if show_dates:
        return OUTPUT_COLUMNS
    return ["count", "size", "path"]


def render_table(rows: list[dict[str, str | int]], include_header: bool, columns: list[str]) -> str:
    def display_value(row: dict[str, str | int], col: str) -> str:
        val = row[col]
        if col == "count" and isinstance(val, int):
            return f"{val:,}"
        return str(val)

    widths = {c: len(c) for c in columns}
    for row in rows:
        for col in columns:
            widths[col] = max(widths[col], len(display_value(row, col)))

    def fmt(row: dict[str, str | int]) -> str:
        parts: list[str] = []
        for col in columns:
            val = display_value(row, col)
            if col in RIGHT_ALIGN_COLUMNS:
                parts.append(val.rjust(widths[col]))
            else:
                parts.append(val.ljust(widths[col]))
        return "  ".join(parts)

    lines: list[str] = []
    if include_header:
        header = {c: c for c in columns}
        lines.append(fmt(header))
        lines.append("  ".join("-" * widths[c] for c in columns))

    if not rows:
        lines.append("No matching files.")
        return "\n".join(lines) + "\n"

    for row in rows:
        lines.append(fmt(row))
    return "\n".join(lines) + "\n"


def get_current_size(path_text: str) -> int | None:
    try:
        return Path(path_text).stat().st_size
    except OSError:
        return None


def build_size_cache(stats: Iterable[FileStats]) -> dict[str, int | None]:
    return {st.path: get_current_size(st.path) for st in stats}


def emit_table_output(text: str) -> None:
    if sys.stdout.isatty():
        cols = shutil.get_terminal_size(fallback=(120, 24)).columns
        needs_pager = any(len(line) > cols for line in text.splitlines())
        if needs_pager:
            pydoc.pager(text)
            return
    sys.stdout.write(text)


def human_size(num_bytes: int) -> str:
    units = ["B", "K", "M", "G", "T", "P"]
    size = float(num_bytes)
    unit_idx = 0
    while unit_idx < len(units) - 1 and size >= 1000:
        size /= 1000.0
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(size):,} {units[unit_idx]}"

    if size < 10:
        one_decimal = round(size, 1)
        if one_decimal < 10:
            return f"{one_decimal:.1f} {units[unit_idx]}"
        size = one_decimal

    rounded_int = int(size + 0.5)
    while rounded_int > 999 and unit_idx < len(units) - 1:
        size = rounded_int / 1000.0
        unit_idx += 1
        if size < 10:
            one_decimal = round(size, 1)
            if one_decimal < 10:
                return f"{one_decimal:.1f} {units[unit_idx]}"
            size = one_decimal
        rounded_int = int(size + 0.5)

    return f"{rounded_int:,} {units[unit_idx]}"


def to_rows(
    stats: Iterable[FileStats], size_cache: dict[str, int | None], show_bytes: bool
) -> list[dict[str, str | int]]:
    return [
        {
            "count": st.count,
            "size": (
                (
                    str(size_cache[st.path])
                    if show_bytes
                    else human_size(size_cache[st.path])
                )
                if size_cache.get(st.path) is not None
                else "MISSING"
            ),
            "first_seen": st.first_seen.isoformat(sep=" ") if st.first_seen else "",
            "last_seen": st.last_seen.isoformat(sep=" ") if st.last_seen else "",
            "path": st.path,
        }
        for st in stats
    ]


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)

    if args.top <= 0:
        print("--top must be > 0", file=sys.stderr)
        return 2
    if args.max_logs < 0:
        print("--max-logs must be >= 0", file=sys.stderr)
        return 2
    if args.min_count <= 0:
        print("--min-count must be > 0", file=sys.stderr)
        return 2

    if not args.log_dir.exists() or not args.log_dir.is_dir():
        print(f"Log directory not found: {args.log_dir}", file=sys.stderr)
        return 2

    try:
        include_re = compile_optional_regex(args.include, "--include")
        exclude_re = compile_optional_regex(args.exclude, "--exclude")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    files, skipped_unparseable = iter_log_files(args.log_dir, args.since, args.until)
    if args.max_logs > 0:
        files = files[-args.max_logs :]

    if args.since or args.until:
        print(
            "Warning: --since/--until filter by log timestamp only and ignore upload timestamps/time zones.",
            file=sys.stderr,
        )
        if skipped_unparseable:
            print(
                (
                    f"Warning: skipped {skipped_unparseable} log(s) with unparseable timestamps "
                    "while applying --since/--until."
                ),
                file=sys.stderr,
            )

    stats_by_path: dict[str, FileStats] = {}
    matched_lines = 0
    parseable_lines = 0
    show_progress = args.progress if args.progress is not None else sys.stderr.isatty()

    total_logs = len(files)
    for idx, log_file in enumerate(files, start=1):
        seen_paths_this_log: set[str] = set()
        try:
            with log_file.open("r", encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.rstrip("\n")
                    parsed = parse_line(line)
                    if parsed is None:
                        continue
                    ts, message = parsed

                    parseable_lines += 1

                    if not message.startswith(UPLOADED_PREFIX):
                        continue
                    path = message[len(UPLOADED_PREFIX) :].strip()
                    if not path:
                        continue

                    if not should_keep_path(path, include_re, exclude_re):
                        continue

                    if path in seen_paths_this_log:
                        continue

                    st = stats_by_path.setdefault(path, FileStats(path=path))

                    st.add_event(ts)
                    matched_lines += 1

                    seen_paths_this_log.add(path)
        except OSError as exc:
            print(f"Warning: could not read {log_file}: {exc}", file=sys.stderr)

        if show_progress:
            width = 30
            filled = int((idx / total_logs) * width) if total_logs else width
            bar = "=" * filled + "." * (width - filled)
            sys.stderr.write(f"\rScanning logs [{bar}] {idx:,}/{total_logs:,}")
            sys.stderr.flush()

    if show_progress:
        sys.stderr.write("\n")

    filtered = [s for s in stats_by_path.values() if s.count >= args.min_count]
    use_size_filters = args.min_size is not None or args.min_space is not None
    needs_size_cache = use_size_filters or args.sort == "size"
    size_cache: dict[str, int | None] = {}

    if needs_size_cache:
        size_cache = build_size_cache(filtered)

    if args.min_size is not None:
        print(
            (
                "Warning: --min-size uses current on-disk file size; "
                "missing files are ignored."
            ),
            file=sys.stderr,
        )
        filtered = [
            st
            for st in filtered
            if size_cache.get(st.path) is not None and size_cache[st.path] >= args.min_size
        ]

    if args.min_space is not None:
        print(
            (
                "Warning: --min-space uses current on-disk file size; "
                "this may not reflect historical size, and missing files are ignored."
            ),
            file=sys.stderr,
        )
        filtered = [
            st
            for st in filtered
            if size_cache.get(st.path) is not None
            and (size_cache[st.path] * st.count) >= args.min_space
        ]

    if args.sort == "count":
        filtered.sort(key=lambda s: (-s.count, s.path))
    elif args.sort == "path":
        filtered.sort(key=lambda s: s.path)
    else:
        filtered.sort(
            key=lambda s: (
                1 if size_cache.get(s.path) is None else 0,
                -(size_cache[s.path] or 0),
                s.path,
            )
        )
    top = filtered[: args.top]

    if needs_size_cache:
        top_size_cache = {st.path: size_cache.get(st.path) for st in top}
    else:
        top_size_cache = build_size_cache(top)

    rows = to_rows(top, top_size_cache, show_bytes=args.show_bytes)

    columns = output_columns(show_dates=args.show_dates)
    output_rows = [{k: row[k] for k in columns} for row in rows]

    if args.format == "json":
        print(json.dumps(output_rows, indent=2))
    elif args.format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=columns)
        if not args.no_header:
            writer.writeheader()
        writer.writerows(output_rows)
    else:
        output_text = render_table(output_rows, include_header=not args.no_header, columns=columns)
        emit_table_output(output_text)

    show_summary = args.summary if args.summary is not None else sys.stderr.isatty()
    if show_summary:
        unique_post_filter = len(filtered)
        shown_rows = len(top)
        print(
            (
                f"Scanned logs: {len(files):,}, parseable log lines: {parseable_lines:,}, "
                f"matched events: {matched_lines:,}, "
                f"unique files: {unique_post_filter:,}, "
                f"rows shown: {shown_rows:,}"
            ),
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
