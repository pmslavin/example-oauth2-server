from authlib.jose import jwt
from cryptography.hazmat.primitives import serialization

bearer_token = "wdJSyM5VmlIHCd2k7f1J0wSU3H9cwPBpstMOrD8WLq"

pk_file = "/home/paul/client_private.pem"
with open(pk_file, 'rb') as fp:
    pk = serialization.load_pem_private_key(fp.read(), password=None)

header = {"alg": "RS256"}
payload = {"iss": "gaWaGnMwe6B6uFQKFz2M5qAG", "sub": bearer_token}
jt = jwt.encode(header, payload, pk)
print(jt.decode())
