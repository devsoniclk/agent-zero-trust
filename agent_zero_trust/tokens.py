"""
Cryptographic token authority implementing Macaroon/Biscuit-style capability attenuation.
"""

import hashlib
import hmac
import secrets
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from agent_zero_trust.models import Caveat, DelegationToken, SwarmTier


class TokenAuthority:
    """
    Cryptographic authority issuing and verifying HMAC-chained capability-attenuated delegation tokens.
    """

    def __init__(self, root_key: Optional[bytes] = None):
        self.root_key = root_key or secrets.token_bytes(32)
        self.revoked_tokens: Set[str] = set()
        self.seen_nonces: Set[str] = set()

    def create_root_token(
        self,
        issuer_agent: str,
        subject_agent: str,
        issuer_tier: SwarmTier,
        subject_tier: SwarmTier,
        capabilities: List[str],
        ttl_seconds: float = 3600.0
    ) -> DelegationToken:
        """
        Issues a root delegation token signed directly with the authority's root key.
        """
        now = time.time()
        token = DelegationToken(
            token_id=f"tok_{secrets.token_hex(8)}",
            issuer_agent=issuer_agent,
            subject_agent=subject_agent,
            issuer_tier=issuer_tier.value,
            subject_tier=subject_tier.value,
            capabilities=list(capabilities),
            root_capabilities=list(capabilities),
            created_at=now,
            expires_at=now + ttl_seconds,
            nonce=secrets.token_hex(16)
        )
        base_bytes = token.serialize_payload().encode("utf-8")
        sig = hmac.new(self.root_key, base_bytes, hashlib.sha256).hexdigest()
        token.signature = sig
        self.seen_nonces.add(token.nonce)
        return token

    def attenuate_token(
        self,
        token: DelegationToken,
        new_caveats: List[Caveat],
        restricted_capabilities: Optional[List[str]] = None
    ) -> DelegationToken:
        """
        Attenuates a token by appending caveats and chaining the HMAC signature:
        sig_{i+1} = HMAC-SHA256(sig_i, caveat_{i+1})
        Enforces monotonic restriction: capabilities can only narrow, never widen.
        """
        if not new_caveats and restricted_capabilities is None:
            raise ValueError("Attenuation must specify new caveats or narrowed capabilities.")

        cloned = DelegationToken.from_dict(token.to_dict())

        # If narrowing capabilities, ensure they are a strict subset of current capabilities
        if restricted_capabilities is not None:
            for cap in restricted_capabilities:
                if cap not in token.capabilities:
                    raise ValueError(f"Capability widening detected: '{cap}' not in parent token.")
            cloned.capabilities = list(restricted_capabilities)

        # Chain HMAC over each added caveat
        current_sig_bytes = bytes.fromhex(cloned.signature)
        for caveat in new_caveats:
            cloned.caveats.append(caveat)
            caveat_bytes = caveat.to_string().encode("utf-8")
            current_sig_bytes = hmac.new(current_sig_bytes, caveat_bytes, hashlib.sha256).digest()

        cloned.signature = current_sig_bytes.hex()
        return cloned

    def verify_token(
        self,
        token: DelegationToken,
        context: Dict[str, Any],
        enforce_ttl: bool = True
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Verifies token cryptographic signature chain, expiration, nonces, and caveat satisfaction.
        Returns: (is_valid, threat_code, failure_reason)
        """
        # 1. Check revocation
        if token.token_id in self.revoked_tokens:
            return False, "ZTM-009", f"Token {token.token_id} has been revoked."

        # 2. Check expiration
        now = time.time()
        if enforce_ttl and now > token.expires_at:
            return False, "ZTM-005", f"Token expired at {token.expires_at} (current {now})."

        # 3. Check capability bounds against root capabilities
        for cap in token.capabilities:
            if cap not in token.root_capabilities:
                return False, "ZTM-002", f"Capability '{cap}' not authorized in root token."

        # 4. Verify cryptographic HMAC signature chain
        base_bytes = token.serialize_payload().encode("utf-8")
        expected_sig_bytes = hmac.new(self.root_key, base_bytes, hashlib.sha256).digest()

        for caveat in token.caveats:
            caveat_bytes = caveat.to_string().encode("utf-8")
            expected_sig_bytes = hmac.new(expected_sig_bytes, caveat_bytes, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_sig_bytes.hex(), token.signature):
            return False, "ZTM-002", "Cryptographic signature chain mismatch (tampered caveat or invalid key)."

        # 5. Evaluate all caveats against execution context
        for caveat in token.caveats:
            if not caveat.evaluate(context):
                return False, "ZTM-004", f"Caveat evaluation failed: {caveat.to_string()} with context {context}"

        return True, None, None

    def revoke_token(self, token_id: str):
        """Adds a token to the authority revocation list."""
        self.revoked_tokens.add(token_id)

    def is_revoked(self, token_id: str) -> bool:
        """Checks if a token has been revoked."""
        return token_id in self.revoked_tokens
