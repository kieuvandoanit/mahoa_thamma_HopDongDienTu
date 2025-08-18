from pathlib import Path
from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata, SigSeedSubFilter
from pyhanko_certvalidator import ValidationContext
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.general import load_cert_from_pemder

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader as HankoPdfReader

async def sign_pdf_async(in_pdf: Path, out_pdf: Path, user_key_path: Path, user_cert_path: Path, tsa_url: str|None=None):
    key = signers.SimpleSigner.load(
        key_file=str(user_key_path),
        cert_file=str(user_cert_path),
        key_passphrase=None
    )
    meta = PdfSignatureMetadata(
        field_name="Signature1",
        subfilter=SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
    )
    pdf_signer = PdfSigner(meta, signer=key)

    # Quan trọng: dùng IncrementalPdfFileWriter bọc stream đầu vào
    with in_pdf.open('rb') as f_in:
        writer = IncrementalPdfFileWriter(f_in)
        out_pdf.parent.mkdir(parents=True, exist_ok=True)
        with out_pdf.open('wb') as f_out:
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