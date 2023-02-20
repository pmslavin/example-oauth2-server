from cryptography.hazmat.primitives import serialization
from authlib.jose import jwt


t = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJoeWRyYSIsInN1YiI6eyJ0b2tlbl90eXBlIjoiQmVhcmVyIiwiYWNjZXNzX3Rva2VuIjoiWTEyVnprSXgwcldZQzZ5TGFoeUFiVktqYXZLd3NPV0JRazVic01MR0dsIiwiZXhwaXJlc19pbiI6MzYwMCwic2NvcGUiOiJwcm9maWxlIn19.Zfuy_ABOerxPjwUBLrB68X6evmxqSUneEcj6H1VYJSw"

pk = "shared-private-key"

print(len(t))
c = jwt.decode(t, pk)
print(c)
