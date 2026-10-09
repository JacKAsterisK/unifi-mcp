"""One TLS and origin policy for every Network controller transport."""

import re
import ssl
from typing import Literal, cast

import aiohttp
from yarl import URL

TLSValue = ssl.SSLContext | aiohttp.Fingerprint | Literal[False]


def controller_tls(verify_ssl: bool, tls_sha256: str = "") -> TLSValue:
    """Use CA verification, an explicitly trusted certificate pin, or legacy insecure mode.

    A pin replaces CA/hostname validation with SHA-256 certificate identity. It
    must be supplied by the owner through a trusted channel, never learned here.
    """
    if tls_sha256:
        if not verify_ssl:
            raise ValueError("TLS_SHA256 requires VERIFY_SSL=true.")
        normalized = tls_sha256.replace(":", "")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", normalized):
            raise ValueError("TLS_SHA256 must be a SHA-256 certificate fingerprint (64 hex digits).")
        return aiohttp.Fingerprint(bytes.fromhex(normalized))
    return ssl.create_default_context() if verify_ssl else False


def sdk_tls(value: TLSValue) -> ssl.SSLContext | Literal[False]:
    """Adapt aiounifi's narrow annotation to its aiohttp-backed runtime contract.

    aiounifi forwards this value unchanged to aiohttp HTTP and websocket calls,
    which accept Fingerprint. The cast changes no runtime behavior; real TLS
    integration tests exercise both paths to catch dependency incompatibility.
    """
    return cast(ssl.SSLContext | Literal[False], value)


def controller_origin(base_url: str) -> aiohttp.ClientMiddlewareType:
    """Refuse cross-origin requests, including authenticated redirect hops."""
    origin = URL(base_url).origin()

    async def enforce(request: aiohttp.ClientRequest, handler):
        target = request.url.with_scheme("https") if request.url.scheme == "wss" else request.url
        if target.scheme != "https" or target.origin() != origin or target.user is not None:
            raise aiohttp.ClientConnectionError("Controller transport refused an unexpected origin.")
        return await handler(request)

    return enforce


async def no_retry_controller_write(
    request: aiohttp.ClientRequest, handler: aiohttp.ClientHandlerType
) -> aiohttp.ClientResponse:
    """Prevent aiohttp from replaying an uncertain idempotent controller write."""
    try:
        return await handler(request)
    except (aiohttp.ClientOSError, aiohttp.ServerDisconnectedError):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            raise aiohttp.ClientConnectionError("Controller write transport failed") from None
        raise
