"""HTTP fetch helpers hardened against SSRF and oversized responses.

These utilities are shared by the parts of trustymail that retrieve
content over HTTPS from hosts that may be influenced by the data being
scanned (for example a domain's MTA-STS policy host).  Every fetch made
through this module:

* refuses to connect to a host that resolves to a non-public address,
  guarding against server-side request forgery (SSRF);
* pins the TCP connection to the address that was validated -- closing
  the DNS-rebinding window between validation and connection -- while
  still using the original hostname for the TLS SNI and certificate
  hostname check, so certificate verification continues to apply;
* requires valid TLS and never follows redirects; and
* caps the size of the response body read into memory.

The module deliberately depends only on the standard library and
``requests`` so that it can be imported from anywhere in the package
without risking an import cycle.
"""

# Standard Python Libraries
import ipaddress
import socket
from urllib.parse import urlparse, urlunparse

# Third-Party Libraries
import requests
from requests.adapters import HTTPAdapter


class SafeFetchError(Exception):
    """Base class for errors raised while fetching a URL safely."""


class HostNotPublicError(SafeFetchError):
    """Raised when a host cannot be resolved to a public address."""


class ResponseTooLargeError(SafeFetchError):
    """Raised when a response body exceeds the configured size cap."""


class HTTPStatusError(SafeFetchError):
    """Raised when a request returns a non-200 HTTP status."""

    def __init__(self, status_code):
        """Store the offending status code."""
        self.status_code = status_code
        super().__init__(f"request returned HTTP {status_code}")


def is_public_ip(ip):
    """Return whether an address is globally routable and safe to fetch from.

    Loopback, private, link-local (which includes the cloud metadata
    address 169.254.169.254), reserved, multicast, and unspecified
    addresses are all rejected.  IPv4-mapped IPv6 addresses are unwrapped
    so the embedded IPv4 address is what gets evaluated.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_public_host(hostname):
    """Confirm a host resolves only to public addresses.

    Parameters
    ----------
    hostname : str
        The host name to validate.

    Returns
    -------
    list of str
        The validated, publicly routable IP addresses for the host.

    Raises
    ------
    HostNotPublicError
        If the host does not resolve, resolves to no addresses, or
        resolves to any non-public address.
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as error:
        raise HostNotPublicError(f"could not resolve {hostname}: {error}")

    addresses = []
    for _family, _type, _proto, _canonname, sockaddr in addrinfo:
        ip = ipaddress.ip_address(sockaddr[0])
        if not is_public_ip(ip):
            raise HostNotPublicError(f"{hostname} resolves to non-public address {ip}")
        addresses.append(str(ip))

    if not addresses:
        raise HostNotPublicError(f"{hostname} did not resolve to any address")

    return addresses


class PinnedIPHTTPSAdapter(HTTPAdapter):
    """A requests adapter that pins HTTPS connections to a fixed IP.

    The TCP connection is made to a pre-validated IP address, but the
    original hostname is used for the TLS SNI and the certificate
    hostname check, so certificate verification still applies.  This
    removes the DNS-rebinding window that would otherwise exist between
    validating the host and connecting to it.
    """

    def __init__(self, hostname, ip_address, **kwargs):
        """Store the hostname to honor and the IP address to connect to."""
        self._hostname = hostname
        self._ip_address = ip_address
        super().__init__(**kwargs)

    def send(self, request, **kwargs):
        """Rewrite the request to connect to the pinned IP, then send it."""
        parsed = urlparse(request.url)
        if parsed.scheme == "https" and parsed.hostname == self._hostname:
            port = parsed.port or 443
            if ":" in self._ip_address:
                # Bracket IPv6 literals in the URL authority.
                netloc = f"[{self._ip_address}]:{port}"
            else:
                netloc = f"{self._ip_address}:{port}"
            request.url = urlunparse(parsed._replace(netloc=netloc))
            # Keep the Host header and TLS identity tied to the original
            # hostname so certificate verification is unaffected.
            request.headers["Host"] = (
                self._hostname if port == 443 else f"{self._hostname}:{port}"
            )
            self.poolmanager.connection_pool_kw["server_hostname"] = self._hostname
            self.poolmanager.connection_pool_kw["assert_hostname"] = self._hostname
        return super().send(request, **kwargs)


def _pinned_session(hostname, ip_address):
    """Build a requests Session that pins HTTPS for hostname to ip_address."""
    session = requests.Session()
    session.mount("https://", PinnedIPHTTPSAdapter(hostname, ip_address))
    return session


def _read_capped(response, max_bytes):
    """Read a streamed response body, enforcing a maximum size.

    Raises
    ------
    ResponseTooLargeError
        If the accumulated (decoded) body exceeds ``max_bytes``.
    """
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise ResponseTooLargeError(
                f"response exceeds the maximum allowed size of {max_bytes} bytes"
            )
        chunks.append(chunk)
    return b"".join(chunks)


def fetch_bytes(url, timeout, max_bytes):
    """Fetch a URL's body as bytes, safely.

    The host is validated and the connection pinned to a validated public
    address; TLS is verified, redirects are refused, and the body is
    capped at ``max_bytes``.

    Parameters
    ----------
    url : str
        The HTTPS URL to fetch.
    timeout : int or float
        The connection/read timeout in seconds.
    max_bytes : int
        The maximum number of body bytes to read.

    Returns
    -------
    bytes
        The response body.

    Raises
    ------
    HostNotPublicError
        If the URL is not HTTPS or its host is not publicly routable.
    HTTPStatusError
        If the response status is not 200.
    ResponseTooLargeError
        If the body exceeds ``max_bytes``.
    requests.RequestException
        Propagated for transport-level failures.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if parsed.scheme != "https" or not hostname:
        raise HostNotPublicError(f"refusing to fetch non-HTTPS URL: {url}")

    addresses = validate_public_host(hostname)
    session = _pinned_session(hostname, addresses[0])
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        with response:
            if response.status_code != 200:
                raise HTTPStatusError(response.status_code)
            return _read_capped(response, max_bytes)
    finally:
        session.close()


def fetch_text(url, timeout, max_bytes, encoding="utf-8"):
    """Fetch a URL's body as decoded text, safely.

    This is a thin wrapper around :func:`fetch_bytes`; see its docstring
    for the safety guarantees and the exceptions that may be raised.
    """
    return fetch_bytes(url, timeout, max_bytes).decode(encoding, errors="replace")
