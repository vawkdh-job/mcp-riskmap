from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def read_file_safe(filename):
    target_path = (BASE_DIR / filename).resolve()

    try:
        target_path.relative_to(BASE_DIR)
    except ValueError:
        return "Access denied: path escapes the allowed directory."

    if not target_path.is_file():
        return "Access denied: expected a file inside the allowed directory."

    return target_path.read_text(encoding="utf-8")
