import json
from pathlib import Path


def write_intermediate(flows: list[dict], output_path: Path) -> None:
    output_path.write_text(
        json.dumps(flows, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def read_intermediate(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))
