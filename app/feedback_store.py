"""
ClassiFinder — Feedback Store

Persists feedback metadata (false positives / false negatives) to Turso.
Only structured metadata is stored — never comment text, never secret values.

All Turso calls are synchronous and must be run via asyncio.to_thread() from
async contexts. If Turso is not configured, operations are no-ops or raise
RuntimeError as documented per function.
"""

import time
from typing import Optional

from app.config import get_settings

# ── Database ──────────────────────────────────────────────────────────────────

_db_conn = None


def _get_conn():
    """Get or create the Turso database connection."""
    global _db_conn
    if _db_conn is not None:
        return _db_conn
    settings = get_settings()
    if not settings.turso_enabled:
        raise RuntimeError("Turso is not configured")
    # Imported lazily: the self-host image ships without the Turso driver
    # (no linux/arm64 wheel), so it must not be required at import time.
    import libsql_experimental as libsql

    _db_conn = libsql.connect(
        settings.turso_database_url,
        auth_token=settings.turso_auth_token,
    )
    return _db_conn


def reset_conn() -> None:
    """Reset the connection. Used in tests."""
    global _db_conn
    _db_conn = None


# ── Table init ────────────────────────────────────────────────────────────────

def init_feedback_table(conn=None) -> None:
    """Create the feedback table if it doesn't exist.

    If ``conn`` is None, uses the module-level Turso connection. Returns early
    (without error) if Turso is not configured and no explicit conn is given.

    Schema stores only structured metadata — never comment text or secret values.
    """
    if conn is None:
        settings = get_settings()
        if not settings.turso_enabled:
            return
        conn = _get_conn()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            feedback_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            feedback_type TEXT NOT NULL,
            has_comment INTEGER NOT NULL DEFAULT 0,
            expected_type TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()


# ── Insert ────────────────────────────────────────────────────────────────────

def insert_feedback(
    *,
    conn=None,
    feedback_id: str,
    request_id: str,
    finding_id: str,
    feedback_type: str,
    has_comment: bool,
    expected_type: Optional[str] = None,
) -> None:
    """Insert a feedback row into the feedback table.

    If ``conn`` is None, uses the module-level Turso connection.

    SECURITY: Only anonymous structured metadata is stored. No user identity,
    comment text, or secret values are persisted.

    Args:
        conn: Optional database connection (for testing with local SQLite).
        feedback_id: Unique identifier for this feedback event.
        request_id: The request_id from the original scan.
        finding_id: The finding_id that was flagged.
        feedback_type: One of "false_positive" or "false_negative".
        has_comment: Whether the user supplied a comment (boolean; text not stored).
        expected_type: If provided, the pattern type the user expected (e.g. "aws_access_key").
    """
    if conn is None:
        conn = _get_conn()

    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    conn.execute(
        """
        INSERT INTO feedback
            (feedback_id, request_id, finding_id, feedback_type,
             has_comment, expected_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            feedback_id,
            request_id,
            finding_id,
            feedback_type,
            int(has_comment),
            expected_type,
            created_at,
        ),
    )
    conn.commit()


# ── Aggregate queries ────────────────────────────────────────────────────────


def query_false_positive_counts(conn=None) -> list[tuple[str, int]]:
    """Return false positive counts grouped by finding_id, descending.

    Returns: [(finding_id, count), ...]
    """
    if conn is None:
        conn = _get_conn()
    rows = conn.execute(
        """SELECT finding_id, COUNT(*) as cnt
           FROM feedback
           WHERE feedback_type = 'false_positive'
           GROUP BY finding_id
           ORDER BY cnt DESC"""
    ).fetchall()
    return [(row[0], row[1]) for row in rows]


def query_false_negative_gaps(conn=None) -> list[tuple[str, int]]:
    """Return false negative counts grouped by expected_type, descending.

    Only includes rows where expected_type is not NULL.
    Returns: [(expected_type, count), ...]
    """
    if conn is None:
        conn = _get_conn()
    rows = conn.execute(
        """SELECT expected_type, COUNT(*) as cnt
           FROM feedback
           WHERE feedback_type = 'false_negative' AND expected_type IS NOT NULL
           GROUP BY expected_type
           ORDER BY cnt DESC"""
    ).fetchall()
    return [(row[0], row[1]) for row in rows]


def query_volume_by_day(conn=None) -> list[tuple[str, int]]:
    """Return total feedback count grouped by day, most recent first.

    Returns: [(date_str, count), ...]
    """
    if conn is None:
        conn = _get_conn()
    rows = conn.execute(
        """SELECT SUBSTR(created_at, 1, 10) as day, COUNT(*) as cnt
           FROM feedback
           GROUP BY day
           ORDER BY day DESC"""
    ).fetchall()
    return [(row[0], row[1]) for row in rows]
