"""One `ingest_runs` row per attempt, finalized on success and on failure alike."""

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from threatfeed.models import IngestRun, IngestStatus

# A stack trace does not belong in a database column; the type + message is what an operator needs.
MAX_ERROR_LENGTH = 2_000


@contextmanager
def track_run(session: Session, feed: str) -> Iterator[IngestRun]:
    """Create a `running` row before touching the feed and always finalize it.

    Callers update the counters on the yielded row and commit each batch. On error the session
    is rolled back first, so the run row is finalized in a clean transaction and partial batches
    stay committed: the upsert is idempotent, so re-running converges.
    """
    run = IngestRun(feed=feed, status=IngestStatus.RUNNING)
    session.add(run)
    session.commit()

    try:
        yield run
    except Exception as exc:
        session.rollback()
        run.status = IngestStatus.FAILED
        run.error = f"{type(exc).__name__}: {exc}"[:MAX_ERROR_LENGTH]
        raise
    else:
        run.status = IngestStatus.SUCCEEDED
    finally:
        run.finished_at = datetime.now(UTC)
        session.commit()
