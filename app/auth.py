import pyotp, time

OTP_SECRETS = {}  # user_id -> secret

def get_or_create_totp_secret(user_id: str):
    if user_id not in OTP_SECRETS:
        OTP_SECRETS[user_id] = pyotp.random_base32()
    return OTP_SECRETS[user_id]

def generate_otp(user_id: str):
    secret = get_or_create_totp_secret(user_id)
    totp = pyotp.TOTP(secret, interval=120)  # 2 phút
    code = totp.now()
    print(f"[OTP-DEMO] Send OTP to user {user_id}: {code}")  # in ra console để demo
    return code

def verify_otp(user_id: str, code: str):
    secret = get_or_create_totp_secret(user_id)
    totp = pyotp.TOTP(secret, interval=120)
    return totp.verify(code)

def ekyc_mock_review(id_image_path: str, selfie_path: str) -> bool:
    # Thực tế dùng OCR + Face match + Liveness. Ở đây demo "pass".
    time.sleep(0.5)
    return True
