from fastapi import APIRouter, Form, HTTPException, UploadFile, File
from pathlib import Path
from app.pdf import html_to_pdf
from app.signer import sign_with_png_stamp, verify_pdf_signed_async, list_pdf_signatures
from app.auth import generate_otp, verify_otp
from app.crypto_ca import issue_user_cert, create_or_load_root_ca
from typing import Literal, Optional
from pypdf import PdfReader
from pyhanko.sign.fields import MDPPerm

from fastapi.responses import JSONResponse
import base64

router = APIRouter(prefix="/contracts", tags=["contracts"])
STORAGE = Path("storage")
CONTRACTS_DIR = STORAGE / "contracts"
SIGNED_DIR = STORAGE / "signed"
CONTRACTS_DIR.mkdir(parents=True, exist_ok=True)
SIGNED_DIR.mkdir(parents=True, exist_ok=True)

# CA root
CA_KEY, CA_CERT = create_or_load_root_ca()

# Create 2 party sign (demo)
PARTIES = {
    "partyA": {"common_name": "PartyA", "dir": STORAGE / "certs" / "partyA"},
    "partyB": {"common_name": "PartyB", "dir": STORAGE / "certs" / "partyB"},
}
for p in PARTIES.values():
    p["dir"].mkdir(parents=True, exist_ok=True)
    key_path, cert_path = issue_user_cert(p["common_name"], p["dir"])
    p["key"] = key_path
    p["cert"] = cert_path

# Helper
def latest_pdf_for(title: str) -> Path:
    """
    Get the latest signed PDF for a given contract title.
    """
    base = CONTRACTS_DIR / f"{title}.pdf"
    if not base.exists():
        raise HTTPException(status_code=404, detail="Base PDF not found")

    # Some name output file signed is:
    #   <title>-signed-A.pdf
    #   <title>-signed-A-B.pdf
    candidates = [base] + sorted(SIGNED_DIR.glob(f"{title}-signed-*.pdf"))
    print(candidates)
    return candidates[-1]

# Helper
def next_signed_path(title: str, who: str) -> Path:
    """
    Create the next signed PDF path based on the title and party.
    """
    # who is "A" or "B" to create short name
    existing = sorted(SIGNED_DIR.glob(f"{title}-signed-*.pdf"))
    if not existing:
        return SIGNED_DIR / f"{title}-signed-{who}.pdf"
    # If A already exists, add B; if has more, add -X
    head = existing[-1].stem  # example: "abc-signed-A"
    return SIGNED_DIR / f"{head}-{who}.pdf"

@router.post("/create")
async def create_contract(title: str = Form(...), body_html: str = Form(...)):
    """
    Router create a new contract PDF from HTML.
    """
    safe_title = "".join([c for c in title if c.isalnum() or c in ("-", "_")]).strip() or "contract"
    pdf_path = CONTRACTS_DIR / f"{safe_title}.pdf"
    sha256 = html_to_pdf(body_html, pdf_path)
    return {"title": safe_title, "pdf": str(pdf_path), "sha256": sha256, "status": "DRAFT"}

@router.post("/{title}/request-otp/{party}")
async def request_otp(title: str, party: Literal["partyA","partyB"]):
    """
    Request OTP for a party to sign the contract.
    """
    # Demo: Only print OTP to console
    generate_otp(party)
    return {"message": f"OTP sent for {party} (console)", "ttl": 120}

def _page_index(pdf_path: Path, page_req: int) -> int:
    """
    Convert -1 => Last page; the rest remains the same (0-based).
    """
    with pdf_path.open("rb") as f:
        n = len(PdfReader(f).pages)
    if page_req == -1:
        return max(0, n - 1)
    # Block basic out-of-range
    if page_req < 0 or page_req >= n:
        raise HTTPException(status_code=400, detail=f"stamp_page out of range (0..{n-1} or -1)")
    return page_req
@router.post("/{title}/sign/{party}")
async def sign_for_party(
    title: str,
    party: Literal["partyA", "partyB"],
    otp: str = Form(...),

    # ---- stamp (optional) ----
    stamp_page: int = Form(-1),
    stamp_x: float = Form(450),
    stamp_y: float = Form(40),
    stamp_w: float = Form(120),
    stamp_h: float = Form(120),
    stamp_image: Optional[UploadFile] = File(None),
):
    # 1) verify OTP by user (party)
    if not verify_otp(party, otp):
        raise HTTPException(status_code=400, detail="OTP invalid")

    # 2) Define field
    field_name = "SignatureA" if party == "partyA" else "SignatureB"
    who_mark = "A" if party == "partyA" else "B"

    in_pdf = latest_pdf_for(title)

    # 3) Count existing signatures
    existing_fields = list_pdf_signatures(in_pdf)
    print("Existing fields:", existing_fields)
    already_signed = len(existing_fields) > 0

    # 3a) Mandatory A signature first
    if not already_signed and party == "partyB":
        raise HTTPException(status_code=400, detail="Party A must sign first (certification)")

    # 3b) Prevent duplicate sign same party
    if already_signed and party == "partyA":
        raise HTTPException(status_code=400, detail="Party A already signed")

    # Define output path
    out_pdf = next_signed_path(title, who_mark)

    # 4) Read stamp bytes (optional)
    stamp_bytes = await stamp_image.read() if stamp_image is not None else None

    # 5) Calculate page index & box (pyHanko use (llx,lly,urx,ury))
    page_idx = _page_index(in_pdf, stamp_page)
    box = (float(stamp_x), float(stamp_y), float(stamp_x + stamp_w), float(stamp_y + stamp_h))

    # 6) Choose signing method:
    # - If not exists signature -> Party A sign first (certify + DocMDP P=2)
    # - If has exists signature -> All party later sign approval; appearance contain PNG (don't rewrite)
    creds = PARTIES[party]

    if not already_signed:
        # First signature -> certification (DocMDP: FILL_FORMS allow continue signing)
        await sign_with_png_stamp(
            in_pdf=in_pdf,
            out_pdf=out_pdf,
            key_path=creds["key"],
            cert_path=creds["cert"],
            field_name=field_name,
            page_index=page_idx,
            box=box,
            png_bytes=stamp_bytes,          # None-able
            stamp_text="",                   # Empty: only use PNG
            certify=True,
            docmdp_perms=MDPPerm.FILL_FORMS
        )
    else:
        # Subsequent signatures -> approval
        await sign_with_png_stamp(
            in_pdf=in_pdf,
            out_pdf=out_pdf,
            key_path=creds["key"],
            cert_path=creds["cert"],
            field_name=field_name,
            page_index=page_idx,
            box=box,
            png_bytes=stamp_bytes,          # show image in signature frame
            stamp_text="",
            certify=False
        )

    # 7) Return list field now in the new file
    fields = list_pdf_signatures(out_pdf)
    return {"title": title, "signed_pdf": str(out_pdf), "signatures": fields}

# @router.get("/{title}/verify")
# async def verify(title: str):
#     signed_pdf = latest_pdf_for(title)
#     print(signed_pdf)
#     report = await verify_pdf_signed_async(signed_pdf, Path("storage/ca/rootCA.pem"))
#     fields = list_pdf_signatures(signed_pdf)
#     return {"file": str(signed_pdf), "fields": fields, "report": report}


@router.get("/{title}/verify")
async def verify(title: str):
    signed_pdf = latest_pdf_for(title)
    print(signed_pdf)

    # Get list of signatures
    fields = list_pdf_signatures(signed_pdf)
    print(fields)

    # Always use Root CA for verification instead of individual party certificates
    # This is the correct approach for a PKI system
    root_ca_path = Path("storage/ca/rootCA.pem")

    try:
        # Verify with Root CA and skip strict diff analysis for multi-signature PDFs
        report = await verify_pdf_signed_async(signed_pdf, root_ca_path)
    except Exception as e:
        # If verification fails, return error details
        report = {
            "status": "FAILED",
            "error": str(e),
            "details": "Verification failed - possibly due to multi-signature policy conflicts"
        }

    return {"file": str(signed_pdf), "fields": fields, "report": report}

def _html_to_pdf_bytes(html: str) -> bytes:
    """
    Render HTML -> PDF, prioritize WeasyPrint, fallback pdfkit (wkhtmltopdf).
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

    # 2) pdfkit (need wkhtmltopdf already installed in system)
    try:
        import pdfkit  # type: ignore
        pdf_bytes = pdfkit.from_string(html, False)
        if not pdf_bytes:
            raise RuntimeError("pdfkit returned empty PDF")
        # pdfkit can return str or bytes depend on version
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
    Receive HTML and return PDF base64 to show in iframe (data URL).
    """
    try:
        pdf_bytes = _html_to_pdf_bytes(body_html)
        b64 = base64.b64encode(pdf_bytes).decode("ascii")
        return JSONResponse({"pdf_base64": b64})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Preview failed: {e}")
