import pyotp, time

OTP_SECRETS = {}  # Store OTP secrets in memory for demo purposes

def get_or_create_totp_secret(user_id: str):
    """
    Get or create OTP secret for a user.
    """
    if user_id not in OTP_SECRETS:
        OTP_SECRETS[user_id] = pyotp.random_base32()
    return OTP_SECRETS[user_id]

def generate_otp(user_id: str):
    """
    Generate a TOTP code for the user and print it to console.
    """
    secret = get_or_create_totp_secret(user_id)
    totp = pyotp.TOTP(secret, interval=120)  # 2 phút
    code = totp.now()
    print(f"[OTP-DEMO] Send OTP to user {user_id}: {code}")  # in ra console để demo
    return code

def verify_otp(user_id: str, code: str):
    """
    Verify the TOTP code for a user.
    """
    secret = get_or_create_totp_secret(user_id)
    totp = pyotp.TOTP(secret, interval=120)
    return totp.verify(code)
