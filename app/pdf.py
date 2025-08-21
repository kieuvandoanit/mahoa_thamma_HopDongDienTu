from weasyprint import HTML
from pathlib import Path
import hashlib

def html_to_pdf(html_content: str, out_path: Path):
    """
    Convert HTML content to PDF and save it to the specified path.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_content).write_pdf(target=str(out_path))
    data = out_path.read_bytes()
    return hashlib.sha256(data).hexdigest()
