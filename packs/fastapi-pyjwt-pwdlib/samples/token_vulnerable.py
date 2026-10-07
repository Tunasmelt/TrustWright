import jwt

SECRET = "change-me"

def decode_unverified(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_signature": False})

def decode_unverified_via_var(token):
    opts = {"verify_exp": True, "verify_signature": False}
    return jwt.decode(token, SECRET, algorithms=["HS256"], options=opts)

def decode_unverified_positional(token):
    return jwt.decode(token, SECRET, ["HS256"], {"verify_signature": False})
