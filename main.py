import argparse
import datetime
import logging
import os
import socket
import ssl
import sys
import tempfile
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Checks the SSL/TLS certificate of a given host and reports on its validity, expiry, and the negotiated cipher.')
    parser.add_argument('hostname', help='The hostname or IP address to check. A bare host, a host:port pair, or a scheme URL such as https://host:port are all accepted.')
    parser.add_argument('-p', '--port', type=int, default=None, help='The port number to connect to (default: 443, or the port embedded in the hostname argument). Overrides any embedded port.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for debugging.')
    parser.add_argument('-c', '--ciphers', action='store_true', help="List this local TLS client's ciphers (not any server's).")

    return parser.parse_args()


def parse_target(raw, cli_port=None):
    """
    Parse the operator's target into a (host, port) pair.

    Accepts a bare host, a host:port pair, and scheme URLs. A port given
    with -p overrides any port embedded in the input.

    Raises:
        ValueError: When nothing usable as a host remains, or the port is
        out of range.
    """
    text = raw.strip()
    if "://" in text:
        parsed = urllib.parse.urlsplit(text)
        host = parsed.hostname
        try:
            embedded_port = parsed.port
        except ValueError:
            raise ValueError(f"Invalid port in target: {raw}")
    else:
        parsed = urllib.parse.urlsplit("//" + text.split("/")[0])
        host = parsed.hostname
        try:
            embedded_port = parsed.port
        except ValueError:
            raise ValueError(f"Invalid port in target: {raw}")

    if not host:
        raise ValueError(f"Could not parse a hostname from: {raw}")

    port = cli_port if cli_port is not None else (embedded_port if embedded_port is not None else 443)
    if not isinstance(port, int) or port <= 0 or port > 65535:
        raise ValueError(f"Invalid port number: {port}")
    return host, port


def inspection_context():
    """
    Build the non-verifying TLS context used for inspection.

    Certificates are fetched WITHOUT verification (check_hostname off,
    CERT_NONE) purely so that self signed, expired, and mismatched
    certificates can be retrieved and reported as findings. Nothing is
    trusted on the back of these connections; verification problems are
    read from the retrieved certificate and reported, never hidden.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def get_certificate_info(hostname, port=443):
    """
    Retrieves SSL certificate information from the specified host, using a
    non-verifying context for inspection (see inspection_context).

    Returns:
        dict: A dictionary containing certificate information, or None on error.
    """
    try:
        context = inspection_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            logging.error("The server presented no certificate.")
            return None
        # With verification off, the parsed form is empty, so the DER bytes
        # are decoded locally into the usual certificate dictionary.
        pem = ssl.DER_cert_to_PEM_cert(der)
        handle, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(handle, "w") as f:
                f.write(pem)
            return ssl._ssl._test_decode_cert(path)
        finally:
            os.unlink(path)
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return None
    except socket.timeout as e:
        logging.error(f"Connection timeout: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def _parse_cert_date(value):
    parsed = datetime.datetime.strptime(value, '%b %d %H:%M:%S %Y %Z')
    return parsed.replace(tzinfo=datetime.timezone.utc)


def check_certificate_validity(cert, now=None):
    """
    Check both validity dates of a certificate against timezone-aware UTC now.

    Returns:
        dict or None: {"status": "valid", "remaining_days": int},
        {"status": "expired", "remaining_days": int}, or
        {"status": "not_yet_valid", "days_until_valid": int}.
        None when the certificate or its dates cannot be read.
    """
    if not cert:
        return None
    try:
        not_before = _parse_cert_date(cert['notBefore'])
        not_after = _parse_cert_date(cert['notAfter'])
    except (ValueError, KeyError) as e:
        logging.error(f"Error processing certificate dates: {e}")
        return None
    if now is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    if now < not_before:
        return {"status": "not_yet_valid", "days_until_valid": int((not_before - now).total_seconds() / 86400)}
    remaining_days = int((not_after - now).total_seconds() / 86400)
    if now > not_after:
        return {"status": "expired", "remaining_days": remaining_days}
    return {"status": "valid", "remaining_days": remaining_days}


def certificate_findings(cert, hostname):
    """
    Read the verification problems a verifying client would hit, from the
    retrieved certificate itself: self signed (issuer equals subject) and
    a name that does not cover the requested host.
    """
    findings = []
    if not cert:
        return findings
    subject = dict(x[0] for x in cert.get('subject', ()))
    issuer = dict(x[0] for x in cert.get('issuer', ()))
    if subject and subject == issuer:
        findings.append("Certificate is self signed (issuer equals subject); a verifying client would reject it.")

    names = []
    for kind, value in cert.get('subjectAltName', ()):
        names.append(value)
    if not names and subject.get('commonName'):
        names.append(subject['commonName'])

    def covers(name):
        name = name.lower()
        host = hostname.lower()
        if name.startswith("*."):
            return host.endswith(name[1:]) and host.count(".") == name.count(".")
        return name == host

    if names and not any(covers(name) for name in names):
        findings.append(f"Certificate name does not cover the requested host {hostname}.")
    return findings


def get_certificate_ciphers(hostname, port=443):
    """
    Retrieves the cipher negotiated on one connection to the server, using
    the same non-verifying inspection context.

    Returns:
        list: A list holding the single negotiated cipher tuple of that one
        connection, or None if there is an error. This is not the server's
        supported cipher set.
    """
    try:
        ciphers = []
        context = inspection_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                ciphers.append(cipher)
        return ciphers
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return None
    except socket.timeout as e:
        logging.error(f"Connection timeout: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


def list_supported_ciphers():
    """List the ciphers of this machine's local TLS client context.

    These are the local client's ciphers. They say nothing about any
    server's supported set.
    """
    try:
        print("Local client ciphers (this machine's TLS client only, not any server's supported set):")
        context = ssl.create_default_context()
        for cipher in context.get_ciphers():
            print(f"  {cipher['name']} ({cipher['protocol']}, {cipher['strength_bits']} bits)")
    except Exception as e:
        logging.error(f"An error occurred while listing ciphers: {e}")
        return None


def main():
    """
    Main function to execute the SSL certificate check.
    """
    args = setup_argparse()

    verbose = args.verbose
    ciphers_flag = args.ciphers

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    if ciphers_flag:
        list_supported_ciphers()
        sys.exit(0)

    try:
        hostname, port = parse_target(args.hostname, args.port)
    except ValueError as e:
        logging.error(f"Invalid target: {e}")
        sys.exit(1)

    print("Note: the certificate is fetched without verification, for inspection only. Verification problems are reported as findings; nothing is trusted on the back of this connection.")

    cert = get_certificate_info(hostname, port)

    if not cert:
        print(f"Failed to retrieve certificate information for {hostname}:{port}.")
        sys.exit(1)

    logging.info(f"Certificate information for {hostname}:{port}:")
    if verbose:
        logging.debug(f"Certificate details: subject and issuer recorded, {len(cert)} fields.")

    validity = check_certificate_validity(cert)
    if validity is None:
        print(f"Could not determine validity dates for {hostname}.")
    elif validity["status"] == "expired":
        print(f"Finding: certificate for {hostname} has expired ({-validity['remaining_days']} days ago).")
    elif validity["status"] == "not_yet_valid":
        print(f"Finding: certificate for {hostname} is not yet valid (valid in {validity['days_until_valid']} days).")
    else:
        print(f"Certificate for {hostname} is within its validity dates and expires in {validity['remaining_days']} days.")

    for finding in certificate_findings(cert, hostname):
        print(f"Finding: {finding}")

    used_ciphers = get_certificate_ciphers(hostname, port)
    if used_ciphers:
        print("Negotiated cipher of this connection:")
        for cipher in used_ciphers:
            print(f"  Name: {cipher[0]}, Version: {cipher[1]}, Bits: {cipher[2]}")
    else:
        print("Could not determine the negotiated cipher.")


if __name__ == "__main__":
    main()
