from pathlib import Path
from io import BytesIO
from typing import Tuple

from pypdf import PdfReader, PdfWriter # For overlay operations
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

from pyhanko_certvalidator import ValidationContext
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.fields import enumerate_sig_fields
from pyhanko.sign.general import load_cert_from_pemder

from pyhanko.pdf_utils.reader import PdfFileReader as HankoPdfReader
from PIL import Image

from pyhanko import stamp
from pyhanko.pdf_utils import images
from pyhanko.sign import fields, signers
from pyhanko.sign.fields import SigFieldSpec, MDPPerm
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata, SigSeedSubFilter

def _list_sig_field_names_from_reader(reader: HankoPdfReader):
    """
    Get a list of existing signature field names (robust for multiple tuples).
    """
    names = []
    for item in fields.enumerate_sig_fields(reader):
        if isinstance(item, (tuple, list)):
            name = next((x for x in item if isinstance(x, str)), None)
            if name is None:
                head = item[0]
                name = getattr(head, 'field_name', None) or getattr(head, 'name', None)
            names.append(str(name))
        else:
            name = getattr(item, 'field_name', None) or getattr(item, 'name', None) or str(item)
            names.append(str(name))

    seen, out = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out

async def sign_with_png_stamp(
    in_pdf: Path,
    out_pdf: Path,
    key_path: Path,
    cert_path: Path,
    *,
    field_name: str,
    page_index: int,
    box: Tuple[float, float, float, float],  # (llx, lly, urx, ury)
    png_bytes: bytes | None = None,          # None -> only text
    stamp_text: str = "",                    # "" => show only PNG
    certify: bool = False,                   # True if first sign (DocMDP)
    docmdp_perms: MDPPerm | None = None,     # EX: MDPPerm.FILL_FORMS
):
    # 1) Open input by incremental (required to keep old signature)
    in_bytes = in_pdf.read_bytes()
    src = BytesIO(in_bytes); src.seek(0)

    # Reader to check field already exists or not?
    reader_for_check = HankoPdfReader(BytesIO(in_bytes))
    existing_fields = _list_sig_field_names_from_reader(reader_for_check)

    w = IncrementalPdfFileWriter(src)

    # 2) If field not exists -> append field visible in request position
    if field_name not in existing_fields:
        fields.append_signature_field(
            w,
            sig_field_spec=SigFieldSpec(
                sig_field_name=field_name,
                box=box,
                on_page=page_index,
            )
        )
    # If field exists (Example of compensation) don't create again; pyHanko will be signed in to this field_name

    # 3) Create signer & metadata
    simple_signer = signers.SimpleSigner.load(
        key_file=str(key_path),
        cert_file=str(cert_path),
        key_passphrase=None
    )

    meta = PdfSignatureMetadata(
        field_name=field_name,
        subfilter=SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        certify=bool(certify),
        docmdp_permissions=docmdp_perms if certify else None,
    )

    # 4) Create stamp_style: PNG invisible do background of visible signature
    bg_img = None
    if png_bytes:
        # open PNG from bytes, Make sure there is an alpha channel (transparency)
        pil_img = Image.open(BytesIO(png_bytes))
        # If is PNG transparency so should convert to RGBA
        if pil_img.mode not in ("RGBA", "LA"):
            pil_img = pil_img.convert("RGBA")
        bg_img = images.PdfImage(pil_img)
    sig_stamp_style = stamp.TextStampStyle(
        stamp_text=stamp_text,
        background=bg_img
    )

    pdf_signer = PdfSigner(meta, signer=simple_signer, stamp_style=sig_stamp_style)

    # 5) Sign (append-only)
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    with out_pdf.open("wb") as outf:
        await pdf_signer.async_sign_pdf(w, output=outf)

    return out_pdf

def _overlay_stamp_return_bytes(
    in_pdf: Path,
    stamp_image_bytes: bytes | None,
    stamp_page: int,
    stamp_xywh: tuple[float, float, float, float],
) -> BytesIO:
    """
    If has stamp -> Draws an image on the specified page and returns a new PDF stream.
    Elif don't have stamp -> Returns a stream containing the contents of in_pdf.
    """
    with in_pdf.open("rb") as f:
        base_reader = PdfReader(f)
        out_stream = BytesIO()

        if not stamp_image_bytes:
            out_stream.write(f.read())
            out_stream.seek(0)
            return out_stream

        # Page size 1 (assuming pages are the same size)
        page0 = base_reader.pages[0]
        w_page = float(page0.mediabox.width)
        h_page = float(page0.mediabox.height)

        # Create PDF layer containing stamp image placed on correct page
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

        # Merge layer into original document
        writer = PdfWriter()
        for i, page in enumerate(base_reader.pages):
            if i == target_page:
                page.merge_page(layer_reader.pages[i])
            writer.add_page(page)

        writer.write(out_stream)
        out_stream.seek(0)
        return out_stream

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