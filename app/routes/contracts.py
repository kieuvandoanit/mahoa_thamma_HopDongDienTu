# app/routes/contracts.py
from fastapi import APIRouter, Form, HTTPException, UploadFile, File
from pathlib import Path
from app.pdf import html_to_pdf
from app.signer import sign_pdf_async, verify_pdf_signed_async, list_pdf_signatures
from app.auth import generate_otp, verify_otp
from app.crypto_ca import issue_user_cert, create_or_load_root_ca
from typing import Literal, Optional

from fastapi.responses import JSONResponse
import base64

router = APIRouter(prefix="/contracts", tags=["contracts"])
STORAGE = Path("storage")
CONTRACTS_DIR = STORAGE / "contracts"
SIGNED_DIR = STORAGE / "signed"
CONTRACTS_DIR.mkdir(parents=True, exist_ok=True)
SIGNED_DIR.mkdir(parents=True, exist_ok=True)

# CA gốc
CA_KEY, CA_CERT = create_or_load_root_ca()

# Tạo 2 người ký (demo)
PARTIES = {
    "partyA": {"common_name": "Party A", "dir": STORAGE / "certs" / "partyA"},
    "partyB": {"common_name": "Party B", "dir": STORAGE / "certs" / "partyB"},
}
for p in PARTIES.values():
    p["dir"].mkdir(parents=True, exist_ok=True)
    key_path, cert_path = issue_user_cert(p["common_name"], p["dir"])
    p["key"] = key_path
    p["cert"] = cert_path

# Helper: lấy file PDF mới nhất của title
def latest_pdf_for(title: str) -> Path:
    base = CONTRACTS_DIR / f"{title}.pdf"
    if not base.exists():
        raise HTTPException(status_code=404, detail="Base PDF not found")

    # các tên output tiệm tiến mình đặt lần lượt:
    #   <title>-signed-A.pdf
    #   <title>-signed-A-B.pdf
    candidates = [base] + sorted(SIGNED_DIR.glob(f"{title}-signed-*.pdf"))
    return candidates[-1]

# Helper: tên file output tiếp theo
def next_signed_path(title: str, who: str) -> Path:
    # who là "A" hoặc "B" để tạo tên gọn
    existing = sorted(SIGNED_DIR.glob(f"{title}-signed-*.pdf"))
    if not existing:
        return SIGNED_DIR / f"{title}-signed-{who}.pdf"
    # nếu đã có A rồi, thêm B; nếu có nhiều, nối thêm -X
    head = existing[-1].stem  # ví dụ "abc-signed-A"
    return SIGNED_DIR / f"{head}-{who}.pdf"

@router.post("/create")
async def create_contract(title: str = Form(...), body_html: str = Form(...)):
    safe_title = "".join([c for c in title if c.isalnum() or c in ("-", "_")]).strip() or "contract"
    pdf_path = CONTRACTS_DIR / f"{safe_title}.pdf"
    sha256 = html_to_pdf(body_html, pdf_path)
    return {"title": safe_title, "pdf": str(pdf_path), "sha256": sha256, "status": "DRAFT"}

@router.post("/{title}/request-otp/{party}")
async def request_otp(title: str, party: Literal["partyA","partyB"]):
    # demo: chỉ in OTP ra console
    generate_otp(party)
    return {"message": f"OTP sent for {party} (console)", "ttl": 120}

@router.post("/{title}/sign/{party}")
async def sign_for_party(
        title: str,
        party: Literal["partyA","partyB"],
        otp: str = Form(...),
        stamp_page: int = Form(-1),
        stamp_x: float = Form(450),
        stamp_y: float = Form(40),
        stamp_w: float = Form(120),
        stamp_h: float = Form(120),
        stamp_image: Optional[UploadFile] = File(None),

):
    # verify OTP theo user (party)
    if not verify_otp(party, otp):
        raise HTTPException(status_code=400, detail="OTP invalid")

    field_name = "SignatureA" if party == "partyA" else "SignatureB"
    who_mark = "A" if party == "partyA" else "B"

    in_pdf = latest_pdf_for(title)
    out_pdf = next_signed_path(title, who_mark)

    # đọc stamp bytes nếu có
    stamp_bytes = None
    if stamp_image is not None:
        stamp_bytes = await stamp_image.read()

    creds = PARTIES[party]
    await sign_pdf_async(
        in_pdf=in_pdf,
        out_pdf=out_pdf,
        user_key_path=creds["key"],
        user_cert_path=creds["cert"],
        field_name=field_name,
        stamp_image_bytes=stamp_bytes,
        stamp_page=stamp_page,
        stamp_xywh=(stamp_x, stamp_y, stamp_w, stamp_h),
    )

    fields = list_pdf_signatures(out_pdf)
    return {"title": title, "signed_pdf": str(out_pdf), "signatures": fields}

@router.get("/{title}/verify")
async def verify(title: str):
    signed_pdf = latest_pdf_for(title)
    report = await verify_pdf_signed_async(signed_pdf, Path("storage/ca/rootCA.pem"))
    fields = list_pdf_signatures(signed_pdf)
    return {"file": str(signed_pdf), "fields": fields, "report": report}


def _html_to_pdf_bytes(html: str) -> bytes:
    """
    Render HTML -> PDF, ưu tiên WeasyPrint, fallback pdfkit (wkhtmltopdf).
    """
    html = html or ""
    # 1) WeasyPrint
    try:
        from weasyprint import HTML  # type: ignore
        pdf_bytes = HTML(string=html).write_pdf()
        if not pdf_bytes:
            raise RuntimeError("WeasyPrint returned empty PDF")
        return pdf_bytes
    except Exception:
        pass

    # 2) pdfkit (cần wkhtmltopdf đã cài sẵn trong hệ thống)
    try:
        import pdfkit  # type: ignore
        pdf_bytes = pdfkit.from_string(html, False)
        if not pdf_bytes:
            raise RuntimeError("pdfkit returned empty PDF")
        # pdfkit có thể trả về str hoặc bytes tùy version
        if isinstance(pdf_bytes, str):
            pdf_bytes = pdf_bytes.encode("latin-1", errors="ignore")
        return pdf_bytes
    except Exception as e:
        raise RuntimeError(
            "Cannot render HTML to PDF. Please install 'weasyprint' "
            "or 'pdfkit' (with wkhtmltopdf). Original error: " + repr(e)
        )

@router.post("/preview")
async def preview(body_html: str = Form(...)):
    """
    Nhận HTML và trả PDF base64 để hiển thị ở iframe (data URL).
    """
    try:
        pdf_bytes = _html_to_pdf_bytes(body_html)
        b64 = base64.b64encode(pdf_bytes).decode("ascii")
        return JSONResponse({"pdf_base64": b64})
    except Exception as e:
        # log tuỳ ý tại đây
        raise HTTPException(status_code=500, detail=f"Preview failed: {e}")
