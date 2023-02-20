import base64
import json
from authlib.jose import jwt
from authlib.oauth2.rfc6749 import TokenValidator
from authlib.oauth2.rfc6750.errors import (
    InvalidTokenError,
    InsufficientScopeError
)
from cryptography.hazmat.primitives import serialization


class HydraTokenValidator(TokenValidator):
    TOKEN_TYPE = "hydra"

    def authenticate_token(self, token_string):
        """  Implemented with reference to SQLA session and model."""
        raise NotImplementedError()

    def validate_token(self, token, scopes, request):
        """  Check if token is active and matches the requested scopes."""
        if not token or token.is_expired() or token.is_revoked():
            raise InvalidTokenError(realm=self.realm, extra_attributes=self.extra_attributes)
        if self.scope_insufficient(token.get_scope(), scopes):
            raise InsufficientScopeError()


def create_hydra_token_validator(session, token_model, client_model):
    class _HydraTokenValidator(HydraTokenValidator):
        def authenticate_token(self, jwt_string):
            """
              Decode payload from jwt arg, retrieve client_id, lookup pubkey
              for client_id, verify jwt signature, retrieve bearer token
              from jwt, verify bearer token.
            """
            header_enc, payload_enc, sig_enc = jwt_string.split('.')
            payload_enc = pad_b64urlencoded_string(payload_enc)
            payload_bytes = base64.urlsafe_b64decode(payload_enc)
            payload = json.loads(payload_bytes.decode())
            client_id = payload["iss"]

            pubkey_file = lookup_client_pubkey(session, client_model, client_id)
            with open(pubkey_file, 'rb') as fp:
                pubkey = serialization.load_pem_public_key(fp.read())
            hydra_token = jwt.decode(jwt_string, pubkey)
            print(f"{hydra_token=}, {pubkey_file=}")
            bearer_token_string = hydra_token.sub
            q = session.query(token_model)
            return q.filter_by(access_token=bearer_token_string).first()

        def request_invalid(self, request):
            return False

        def token_revoked(self, token):
            return token.revoked

    return _HydraTokenValidator


def lookup_client_pubkey(session, client_model, client_id):
    client = session.query(client_model).filter_by(client_id=client_id).first()
    return client.client_uri


def pad_b64urlencoded_string(b64string):
    if (pad_mod := (len(b64string) % 4)) != 0:
        if pad_mod == 2:
            b64string += "=="
        elif pad_mod == 3:
            b64string += "="
    return b64string
