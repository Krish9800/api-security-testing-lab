"""Structured JSON vulnerability and session reporter."""

import json
from pathlib import Path

from apisec.models.session import ScanSession


class JSONReporter:
    """Generates machine-readable JSON security assessment reports."""

    @staticmethod
    def generate(session: ScanSession) -> str:
        """Serialize a scan session to an indented JSON string."""
        data = session.model_dump(mode="json")
        return json.dumps(data, indent=2, sort_keys=False)

    @classmethod
    def save(cls, session: ScanSession, output_path: Path | str) -> Path:
        """Write JSON report output to a file."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        content = cls.generate(session)
        target.write_text(content, encoding="utf-8")
        return target
