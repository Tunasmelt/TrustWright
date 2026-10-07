import jwt

def decode_token(token, key, audience):
    return jwt.decode(
        token,
        key,
        algorithms=["HS256"],
        audience=audience,
        options={"require": ["exp", "aud"]},
    )
