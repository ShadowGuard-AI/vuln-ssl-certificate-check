# vuln-SSL-Certificate-Check
Checks the SSL/TLS certificate of a given host and reports on its validity dates (both notBefore and notAfter), whether it is self signed or name mismatched, and the cipher negotiated on the inspection connection. Connections are made without verification, for inspection only: the certificate is fetched with verification off so that self signed, expired, and mismatched certificates can be retrieved and reported as findings, and nothing is trusted on the back of those connections. The target may be a bare host, a host:port pair, or a scheme URL, and -p overrides any embedded port - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-ssl-certificate-check`

## Usage
`./vuln-ssl-certificate-check [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: The port number to connect to (default: 443, or the port embedded in the hostname argument). Overrides any embedded port.
- `-v`: Enable verbose output for debugging.
- `-c`: List this local TLS client's ciphers. These are the local client's ciphers only, not any server's supported set.

## License
Copyright (c) ShadowStrikeHQ
