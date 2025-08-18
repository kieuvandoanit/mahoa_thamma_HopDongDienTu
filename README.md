# E-Contract Demo (Python + FastAPI)

Demo tối giản quy trình **Soạn → Ký số (PAdES) → Lưu trữ → Xác minh** hợp đồng điện tử.

## Tính năng
- Soạn hợp đồng từ HTML → xuất PDF (WeasyPrint)
- Cấp **Demo Root CA**, cấp **chứng thư số người dùng** (self-signed chain) bằng `cryptography`
- Ký PDF theo tiêu chuẩn **PAdES** bằng `pyHanko`
- Xác minh chữ ký PDF (toàn vẹn, chứng thư, thời điểm ký)
- OTP (TOTP) demo, eKYC mock
- Lưu trữ file và metadata tối thiểu

> Lưu ý: Đây là bản **demo học thuật**. Không sử dụng CA tự cấp này cho môi trường sản xuất.

## Cài đặt
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Mở: http://127.0.0.1:8000/

## Luồng demo nhanh
1. Trang chủ có form tạo hợp đồng (HTML → PDF).
2. Bấm “Request OTP” cho hợp đồng có `title` là `sample` (hoặc hợp đồng bạn vừa tạo).
3. Lấy OTP in ở terminal.
4. Nhập OTP và bấm “Sign” để ký → tạo `storage/signed/<title>-signed.pdf`.
5. Gọi `GET /contracts/<title>/verify` để kiểm tra chữ ký.

## Cấu trúc
```
econtract-demo/
  app/
    main.py
    pdf.py
    signer.py
    crypto_ca.py
    auth.py
    routes/
      contracts.py
  storage/        # chứa CA, cert, pdf gốc & đã ký
```

## Nâng cấp gợi ý
- Multi-signer (ký nối tiếp), PAdES-LTV, TSA thật (RFC 3161)
- OCSP/CRL, chain trust chuyên nghiệp
- eKYC thật (OCR, Face match, liveness)
- Audit trail + proof-of-existence (hash on-chain)
```

