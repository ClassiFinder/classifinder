#!/usr/bin/env python3
"""
ClassiFinder — Feedback Report

CLI tool for querying feedback trends from Turso.

Usage:
    python scripts/feedback_report.py                 # full report
    python scripts/feedback_report.py --fp             # false positives only
    python scripts/feedback_report.py --fn             # false negative gaps only
    python scripts/feedback_report.py --volume         # volume by day only

Requires TURSO_DATABASE_URL and TURSO_AUTH_TOKEN environment variables.
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import get_settings
from app.feedback_store import (
    query_false_positive_counts,
    query_false_negative_gaps,
    query_volume_by_day,
)


def print_section(title: str, rows: list[tuple], col1: str, col2: str) -> None:
    """Print a formatted table section."""
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")
    if not rows:
        print("  (no data)")
        return
    max_col1 = max(len(str(r[0])) for r in rows)
    max_col1 = max(max_col1, len(col1))
    print(f"  {col1:<{max_col1}}  {col2}")
    print(f"  {'-' * max_col1}  {'-' * len(col2)}")
    for row in rows:
        print(f"  {str(row[0]):<{max_col1}}  {row[1]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ClassiFinder feedback report")
    parser.add_argument("--fp", action="store_true", help="Show false positive counts by finding_id")
    parser.add_argument("--fn", action="store_true", help="Show false negative gaps by expected_type")
    parser.add_argument("--volume", action="store_true", help="Show feedback volume by day")
    args = parser.parse_args()

    settings = get_settings()
    if not settings.turso_enabled:
        print("Error: Turso is not configured. Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN.", file=sys.stderr)
        sys.exit(1)

    show_all = not (args.fp or args.fn or args.volume)

    if show_all or args.fp:
        rows = query_false_positive_counts()
        print_section("False Positives by Finding ID", rows, "finding_id", "count")

    if show_all or args.fn:
        rows = query_false_negative_gaps()
        print_section("False Negative Gaps by Expected Type", rows, "expected_type", "count")

    if show_all or args.volume:
        rows = query_volume_by_day()
        print_section("Feedback Volume by Day", rows, "date", "count")

    print()


if __name__ == "__main__":
    main()
