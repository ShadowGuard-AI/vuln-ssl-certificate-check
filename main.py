import argparse
import ssl
import socket
import datetime
import logging
import requests
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Checks the SSL/TLS certificate of a given host and reports on its validity, expiry, and used ciphers.')
    parser.add_argument('hostname', help='The hostname or IP address to check.')
    parser.add_argument('-p', '--port', type=int, default=443, help='The port number to connect to (default: 443).')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for debugging.')
    parser.add_argument('-c', '--ciphers', action='store_true', help='List supported ciphers.') # Add a flag to list supported ciphers

    return parser.parse_args()


def get_certificate_info(hostname, port=443):
    """
    Retrieves SSL certificate information from the specified host.

    Args:
        hostname (str): The hostname or IP address of the server.
        port (int): The port number to connect to (default: 443).

    Returns:
        dict: A dictionary containing certificate information, or None on error.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
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



def check_certificate_expiry(cert):
    """
    Checks the expiry date of the SSL certificate.

    Args:
        cert (dict): A dictionary containing certificate information.

    Returns:
        tuple: A tuple containing a boolean indicating if the certificate is expired,
               and the remaining days until expiry. Returns None if cert is invalid
    """
    if not cert:
        return None
    try:
        expiry_date_str = cert['notAfter']
        expiry_date = datetime.datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
        remaining_days = (expiry_date - datetime.datetime.now()).days

        if remaining_days < 0:
            return True, remaining_days
        else:
            return False, remaining_days
    except (ValueError, KeyError) as e:
        logging.error(f"Error processing expiry date: {e}")
        return None



def get_certificate_ciphers(hostname, port=443):
    """
    Retrieves the ciphers used by the SSL/TLS connection.

     Args:
        hostname (str): The hostname or IP address of the server.
        port (int): The port number to connect to (default: 443).

    Returns:
        list: A list of ciphers used by the server, or None if there is an error.
    """
    try:
        ciphers = []
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                ciphers.append(cipher) # Append the tuple of ciphers to list
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
    """Lists the supported ciphers available on the system."""
    try:
        print("Supported ciphers:")
        print(ssl.get_default_verify_paths().openssl_cafile)

        context = ssl.create_default_context()
        print(context.get_ciphers())

    except Exception as e:
        logging.error(f"An error occurred while listing ciphers: {e}")
        return None


def main():
    """
    Main function to execute the SSL certificate check.
    """
    args = setup_argparse()

    hostname = args.hostname
    port = args.port
    verbose = args.verbose
    ciphers_flag = args.ciphers

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    if ciphers_flag:
        list_supported_ciphers()
        sys.exit(0)


    # Input validation for hostname and port
    if not isinstance(hostname, str) or not hostname:
        logging.error("Invalid hostname provided.")
        sys.exit(1)

    if not isinstance(port, int) or port <= 0 or port > 65535:
        logging.error("Invalid port number provided.")
        sys.exit(1)


    cert = get_certificate_info(hostname, port)

    if cert:
        logging.info(f"Certificate information for {hostname}:{port}:")
        if verbose:
           logging.debug(f"Certificate details: {cert}")

        expiry_check = check_certificate_expiry(cert)

        if expiry_check is not None:
            is_expired, remaining_days = expiry_check
            if is_expired:
                print(f"Certificate for {hostname} has expired.")
            else:
                print(f"Certificate for {hostname} expires in {remaining_days} days.")
        else:
             print(f"Could not determine expiry for {hostname}.")


        used_ciphers = get_certificate_ciphers(hostname, port) # Get the ciphers
        if used_ciphers:
            print("Used Ciphers:")
            for cipher in used_ciphers:
                print(f"  Name: {cipher[0]}, Version: {cipher[1]}, Bits: {cipher[2]}")
        else:
            print("Could not determine ciphers used.")

    else:
        print(f"Failed to retrieve certificate information for {hostname}:{port}.")


if __name__ == "__main__":
    main()