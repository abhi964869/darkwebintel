"""
scheduler.py — Automated Threat Ingestor Scheduler
====================================================
Runs the simulated ingestor every 5 minutes automatically.
Uses APScheduler so no cron configuration needed.

Run standalone:  python scheduler.py
(Keep this running alongside app.py in a separate terminal)

For production: Use Celery + Redis, or a systemd timer.
"""

import os
import logging
from apscheduler.schedulers.blocking import BlockingScheduler
from pymongo import MongoClient
from dotenv import load_dotenv
from ingestor import generate_simulated_threat, match_keywords
from models import ensure_indexes

load_dotenv()

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [SCHEDULER] %(message)s")
logger = logging.getLogger(__name__)

MONGO_URI   = os.getenv("MONGO_URI", "mongodb://localhost:27017/dark_web_intel")
BATCH_SIZE  = int(os.getenv("INGEST_BATCH_SIZE", 5))   # Threats per run
INTERVAL_S  = int(os.getenv("INGEST_INTERVAL_S", 300)) # 5 minutes

client = MongoClient(MONGO_URI)
db     = client["dark_web_intel"]
ensure_indexes(db)


def ingest_batch():
    """Generate BATCH_SIZE threats and match keywords."""
    logger.info(f"Starting ingestion batch — {BATCH_SIZE} threats")
    inserted  = 0
    alerts_n  = 0

    for _ in range(BATCH_SIZE):
        threat = generate_simulated_threat()
        result = db.threats.insert_one(threat)
        alerts_n += match_keywords(db, threat, result.inserted_id)
        inserted += 1

    logger.info(f"Done — inserted {inserted} threats, generated {alerts_n} alerts")


if __name__ == "__main__":
    scheduler = BlockingScheduler()

    # Run once immediately on start
    ingest_batch()

    # Then run every INTERVAL_S seconds
    scheduler.add_job(
        ingest_batch,
        trigger="interval",
        seconds=INTERVAL_S,
        id="ingest_batch",
        replace_existing=True,
    )

    logger.info(f"Scheduler started — running every {INTERVAL_S}s")
    try:
        scheduler.start()
    except KeyboardInterrupt:
        logger.info("Scheduler stopped.")
        client.close()
