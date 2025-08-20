from pathlib import Path
from io import BytesIO

from pypdf import PdfReader, PdfWriter # For overlay operations
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata, SigSeedSubFilter
from pyhanko_certvalidator import ValidationContext
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.fields import enumerate_sig_fields
from pyhanko.sign.general import load_cert_from_pemder

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader as HankoPdfReader
from pyhanko.sign.fields import MDPPerm, SigFieldSpec

def _overlay_stamp_return_bytes(
    in_pdf: Path,
    stamp_image_bytes: bytes | None,
    stamp_page: int,
    stamp_xywh: tuple[float, float, float, float],
) -> BytesIO:
    """
    Nếu có stamp -> vẽ ảnh lên trang chỉ định rồi trả về stream PDF mới.
    Nếu không có stamp -> trả về stream chứa nội dung của in_pdf.
    """
    with in_pdf.open("rb") as f:
        base_reader = PdfReader(f)
        out_stream = BytesIO()

        if not stamp_image_bytes:
            out_stream.write(f.read())
            out_stream.seek(0)
            return out_stream

        # kích thước trang 1 (giả sử các trang cùng kích thước)
        page0 = base_reader.pages[0]
        w_page = float(page0.mediabox.width)
        h_page = float(page0.mediabox.height)

        # tạo layer PDF chứa ảnh stamp đặt đúng trang
        x, y, w, h = stamp_xywh
        target_page = (len(base_reader.pages)-1 if stamp_page == -1 else int(stamp_page))

        layer_stream = BytesIO()
        c = canvas.Canvas(layer_stream, pagesize=(w_page, h_page))
        img = ImageReader(BytesIO(stamp_image_bytes))
        for i in range(len(base_reader.pages)):
            if i == target_page:
                c.drawImage(img, x, y, width=w, height=h, mask='auto')
            c.showPage()
        c.save()
        layer_stream.seek(0)
        layer_reader = PdfReader(layer_stream)

        # hợp nhất layer vào tài liệu gốc
        writer = PdfWriter()
        for i, page in enumerate(base_reader.pages):
            if i == target_page:
                page.merge_page(layer_reader.pages[i])
            writer.add_page(page)

        writer.write(out_stream)
        out_stream.seek(0)
        return out_stream

async def sign_pdf_certify_async(
    in_pdf: Path,
    out_pdf: Path,
    user_key_path: Path,
    user_cert_path: Path,
    *,
    field_name: str = "SignatureA",
    docmdp_perms: MDPPerm = MDPPerm.FILL_FORMS,  # cho phép form & thêm chữ ký
    stamp_image_path: Path | None = None,
    stamp_page: int = -1,
    stamp_xywh: tuple[float, float, float, float] = (450, 40, 120, 120),
):
    """
    Ký certification (DocMDP) -> phải là chữ ký đầu tiên.
    """
    # 1) Overlay dấu (nếu có)
    source_stream = _overlay_stamp_return_bytes(in_pdf, stamp_image_path, stamp_page, stamp_xywh)

    # 2) Chuẩn bị signer & metadata (certify + DocMDP)
    key = signers.SimpleSigner.load(
        key_file=str(user_key_path),
        cert_file=str(user_cert_path),
        key_passphrase=None
    )
    meta = PdfSignatureMetadata(
        field_name=field_name,
        subfilter=SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        certify=True,                             # 👈 certification signature
        docmdp_permissions=docmdp_perms,          # 👈 DocMDP = P=2 (mặc định ở tham số)
    )
    pdf_signer = PdfSigner(meta, signer=key)

    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    with out_pdf.open('wb') as f_out:
        writer = IncrementalPdfFileWriter(source_stream)
        # LƯU Ý: certification signature phải là chữ ký đầu tiên, pyHanko sẽ kiểm tra
        await pdf_signer.async_sign_pdf(writer, output=f_out)

    return out_pdf

async def sign_pdf_approval_async(
    in_pdf: Path,
    out_pdf: Path,
    user_key_path: Path,
    user_cert_path: Path,
    *,
    field_name: str = "SignatureB",
    stamp_image_path: Path | None = None,
    stamp_page: int = -1,
    stamp_xywh: tuple[float, float, float, float] = (450, 40, 120, 120),
):
    """
    Ký approval (thêm chữ ký) trên file đã có certification.
    """
    source_stream = _overlay_stamp_return_bytes(in_pdf, stamp_image_path, stamp_page, stamp_xywh)

    key = signers.SimpleSigner.load(
        key_file=str(user_key_path),
        cert_file=str(user_cert_path),
        key_passphrase=None
    )
    meta = PdfSignatureMetadata(
        field_name=field_name,
        subfilter=SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        certify=False,                 # 👈 approval signature
        # Không set docmdp_permissions ở đây.
    )
    pdf_signer = PdfSigner(meta, signer=key)

    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    with out_pdf.open('wb') as f_out:
        writer = IncrementalPdfFileWriter(source_stream)
        await pdf_signer.async_sign_pdf(writer, output=f_out)

    return out_pdf

def list_pdf_signatures(pdf_path: Path):
    with open(pdf_path, 'rb') as f:
        reader = HankoPdfReader(f)
        names = []
        for item in enumerate_sig_fields(reader):
            # tuple (name, field_ref, widget_ref) trên 0.23.1
            if isinstance(item, (tuple, list)):
                name = next((x for x in item if isinstance(x, str)), None)
                if name is None:
                    head = item[0]
                    name = getattr(head, 'field_name', None) or getattr(head, 'name', None)
                if name is None:
                    name = str(item)
            else:
                name = getattr(item, 'field_name', None) or getattr(item, 'name', None) or str(item)
            names.append(str(name))
        return sorted(set(names))

async def verify_pdf_signed_async(pdf_path: Path, ca_pem_path: Path):
    root = load_cert_from_pemder(str(ca_pem_path))
    vc = ValidationContext(trust_roots=[root], allow_fetching=False)
    with open(pdf_path, 'rb') as f:
        reader = HankoPdfReader(f)
        result = await async_validate_pdf_signature(reader, -1, vc)
    return {
        "intact": result.bottom_line.valid,
        "signer_subject": result.signer_reported_common_name,
        "signing_time": str(result.signing_time) if result.signing_time else None,
        "explanations": [str(e) for e in (result.pseudo_revinfo or [])]
    }

async def sign_pdf_async(
        in_pdf: Path,
        out_pdf: Path,
        user_key_path: Path,
        user_cert_path: Path,
        field_name: str = "Signature1",
        tsa_url: str|None=None,
        stamp_image_bytes: bytes | None = None,
        stamp_page: int = -1,
        stamp_xywh: tuple[float, float, float, float] = (450, 40, 120, 120),

):
    """
        Overlay stamp (nếu có) rồi ký PAdES trên bản kết hợp.
        """
    # 1) chuẩn bị nguồn dữ liệu PDF sau khi overlay (nếu có)
    source_stream = _overlay_stamp_return_bytes(
        in_pdf=in_pdf,
        stamp_image_bytes=stamp_image_bytes,
        stamp_page=stamp_page,
        stamp_xywh=stamp_xywh,
    )

    # 2) ký
    key = signers.SimpleSigner.load(
        key_file=str(user_key_path),
        cert_file=str(user_cert_path),
        key_passphrase=None
    )
    meta = PdfSignatureMetadata(
        field_name=field_name,
        subfilter=SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
    )
    pdf_signer = PdfSigner(meta, signer=key)

    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    with out_pdf.open('wb') as f_out:
        writer = IncrementalPdfFileWriter(source_stream)
        await pdf_signer.async_sign_pdf(writer, output=f_out)

    return out_pdf


async def verify_pdf_signed_async(pdf_path, ca_cert_path):
    # Load the CA certificate (not the key file)
    ca_cert = load_cert_from_pemder(ca_cert_path)
    vc = ValidationContext(trust_roots=[ca_cert])

    try:
        with open(pdf_path, 'rb') as f:
            reader = HankoPdfReader(f)

            # Find signature fields manually by examining the AcroForm
            if '/AcroForm' not in reader.root:
                raise ValueError("No AcroForm found in PDF - document is not signed.")

            acro_form = reader.root['/AcroForm']
            if '/Fields' not in acro_form:
                raise ValueError("No fields found in AcroForm - document is not signed.")

            fields = acro_form['/Fields']
            signature_found = False

            for field_ref in fields:
                field_obj = reader.get_object(field_ref)

                if '/FT' in field_obj and field_obj['/FT'] == '/Sig':
                    signature_found = True
                    field_name = field_obj.get('/T', 'Signature1')

                    if '/V' not in field_obj:
                        continue

                    sig_obj_ref = field_obj['/V']

                    from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
                    embedded_sig = EmbeddedPdfSignature(reader, field_obj, sig_obj_ref)

                    result = await async_validate_pdf_signature(embedded_sig, vc)

                    return {
                        "valid": result.intact,
                        "trusted": result.trusted,
                        "field_name": str(field_name),
                        "summary": str(result)
                    }

            if not signature_found:
                raise ValueError("No signature fields found in PDF.")
            else:
                raise ValueError("Signature fields found but none contain valid signatures.")

    except Exception as e:
        try:
            with open(pdf_path, 'rb') as f:
                content = f.read()
                if b'/Sig' in content and b'/ByteRange' in content:
                    return {
                        "valid": False,
                        "trusted": False,
                        "field_name": "Unknown",
                        "summary": f"PDF appears to contain signatures but validation failed: {str(e)}"
                    }
                else:
                    raise ValueError(f"PDF does not appear to be signed: {str(e)}")
        except Exception as fallback_error:
            raise ValueError(f"PDF signature verification completely failed: {str(e)}")