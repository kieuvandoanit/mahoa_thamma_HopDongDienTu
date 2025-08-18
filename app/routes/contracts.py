from fastapi import APIRouter, Form, HTTPException, UploadFile, File
from pathlib import Path
from app.pdf import html_to_pdf
from app.signer import sign_pdf_async, verify_pdf_signed_async
from app.auth import generate_otp, verify_otp
from app.crypto_ca import issue_user_cert, create_or_load_root_ca
import shutil

router = APIRouter(prefix="/contracts", tags=["contracts"])
STORAGE = Path("storage"); (STORAGE / "contracts").mkdir(parents=True, exist_ok=True); (STORAGE / "signed").mkdir(exist_ok=True)

# Giả định đã có user_id; thực tế lấy từ auth session/JWT
DEMO_USER = "user1"
USER_DIR = Path("storage/certs") / DEMO_USER; USER_DIR.mkdir(parents=True, exist_ok=True)
KEY_PATH, CERT_PATH = issue_user_cert(DEMO_USER, USER_DIR)  # cấp cert khi khởi tạo
CA_KEY, CA_CERT = create_or_load_root_ca()

@router.post("/create")
async def create_contract(title: str = Form(...), body_html: str = Form(...)):
    # sanitize title to simple filename
    safe_title = "".join([c for c in title if c.isalnum() or c in ("-", "_")]).strip() or "contract"
    pdf_path = STORAGE / "contracts" / f"{safe_title}.pdf"
    sha256 = html_to_pdf(body_html, pdf_path)
    return {"title": safe_title, "pdf": str(pdf_path), "sha256": sha256, "status": "DRAFT"}

@router.post("/upload")
async def upload_contract(title: str = Form(...), file: UploadFile = File(...)):
    # Validate file type
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed")

    # Sanitize title to simple filename
    safe_title = "".join([c for c in title if c.isalnum() or c in ("-", "_")]).strip() or "uploaded"
    pdf_path = STORAGE / "contracts" / f"{safe_title}.pdf"

    # Save uploaded file
    with pdf_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {"title": safe_title, "pdf": str(pdf_path), "status": "UPLOADED", "original_filename": file.filename}

@router.post("/{title}/request-otp")
async def request_otp(title: str):
    generate_otp(DEMO_USER)
    return {"message": "OTP sent (console)", "ttl": 120}

@router.post("/{title}/sign")
async def sign(title: str, otp: str = Form(...)):
    safe_title = "".join([c for c in title if c.isalnum() or c in ("-", "_")]).strip()
    in_pdf  = STORAGE / "contracts" / f"{safe_title}.pdf"
    out_pdf = STORAGE / "signed" / f"{safe_title}-signed.pdf"
    if not in_pdf.exists():
        raise HTTPException(status_code=404, detail="PDF not found")
    if not verify_otp(DEMO_USER, otp):
        raise HTTPException(status_code=400, detail="OTP invalid")
    await sign_pdf_async(in_pdf, out_pdf, KEY_PATH, CERT_PATH)
    return {"title": safe_title, "signed_pdf": str(out_pdf)}

@router.post("/preview")
async def preview_pdf(body_html: str = Form(...)):
    """Generate preview PDF from HTML for live preview"""
    import tempfile
    import base64

    # Create temporary PDF
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp_file:
        temp_path = Path(temp_file.name)

    try:
        # Generate PDF
        sha256 = html_to_pdf(body_html, temp_path)

        # Read PDF content and encode as base64
        with temp_path.open("rb") as f:
            pdf_content = f.read()
            pdf_base64 = base64.b64encode(pdf_content).decode()

        return {
            "pdf_base64": pdf_base64,
            "sha256": sha256
        }
    finally:
        # Clean up temporary file
        if temp_path.exists():
            temp_path.unlink()

@router.get("/{title}/verify")
async def verify(title: str):
    safe_title = "".join([c for c in title if c.isalnum() or c in ("-", "_")]).strip()
    signed_pdf = STORAGE / "signed" / f"{safe_title}-signed.pdf"
    if not signed_pdf.exists():
        raise HTTPException(status_code=404, detail="Signed PDF not found")
    report = await verify_pdf_signed_async(signed_pdf, Path("storage/certs/user1/user1.cert.pem"))
    return report
