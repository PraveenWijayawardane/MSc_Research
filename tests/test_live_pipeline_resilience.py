import logging
import sys
import tempfile
import unittest
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from live_pipeline import configure_logging  # noqa: E402


class LivePipelineResilienceTests(unittest.TestCase):
    def tearDown(self):
        logger = logging.getLogger()
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

    def test_configure_logging_uses_daily_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "live_pipeline.log"
            configure_logging(log_file, retention_days=14)

            rotating_handlers = [
                handler
                for handler in logging.getLogger().handlers
                if isinstance(handler, TimedRotatingFileHandler)
            ]
            self.assertEqual(len(rotating_handlers), 1)
            self.assertEqual(rotating_handlers[0].backupCount, 14)
            self.assertEqual(rotating_handlers[0].suffix, "%Y-%m-%d")


if __name__ == "__main__":
    unittest.main()
