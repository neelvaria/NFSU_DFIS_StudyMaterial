"""
╔══════════════════════════════════════════════════════════════╗
║       SSL/TLS CERTIFICATE VALIDATION — COMPLETE PRACTICAL    ║
║                                                              ║
║  Tasks:                                                      ║
║    1. Fetch & display the SSL/TLS certificate                ║
║    2. Inspect expiration date, issuer & encryption details   ║
║    3. Validate the certificate chain                         ║
║    4. OpenSSL command reference (auto-generated for domain)  ║
║                                                              ║
║  Usage:                                                      ║
║    python3 ssl_tls_complete.py                (interactive)  ║
║    python3 ssl_tls_complete.py google.com     (argument)     ║
║    python3 ssl_tls_complete.py github.com 443 (custom port)  ║
╚══════════════════════════════════════════════════════════════╝
"""

import ssl
import socket
import datetime
import subprocess
import sys


# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════

def separator(title=""):
    line = "═" * 62
    if title:
        print(f"\n{line}\n  {title}\n{line}")
    else:
        print(line)


def clean_host(raw):
    """Strip protocol prefix and path from any URL or hostname input."""
    return raw.strip().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def days_until(dt_str):
    """Return days remaining until cert expiry date string."""
    fmt = "%b %d %H:%M:%S %Y %Z"
    dt  = datetime.datetime.strptime(dt_str, fmt).replace(tzinfo=datetime.timezone.utc)
    return (dt - datetime.datetime.now(datetime.timezone.utc)).days


def expiry_status(days):
    """Return a status string based on days remaining."""
    if days > 30:
        return f"[VALID]          {days} days remaining"
    elif days > 0:
        return f"[EXPIRING SOON]  {days} days remaining — renew now!"
    else:
        return f"[EXPIRED]        {abs(days)} days ago — certificate invalid!"


def get_certificate(hostname, port=443):
    """
    Open a TLS connection to hostname:port and return:
      cert_dict   — parsed certificate fields as a Python dict
      cert_der    — raw DER bytes of the certificate
      tls_version — negotiated protocol string  (e.g. 'TLSv1.3')
      cipher      — tuple (name, protocol, key_bits)
    """
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls:
            cert_dict   = tls.getpeercert()
            cert_der    = tls.getpeercert(binary_form=True)
            tls_version = tls.version()
            cipher      = tls.cipher()
    return cert_dict, cert_der, tls_version, cipher


def openssl_parse(pem, *flags):
    """Run 'openssl x509 -noout <flags>' on a PEM string and return stdout."""
    result = subprocess.run(
        ["openssl", "x509", "-noout"] + list(flags),
        input=pem.encode(), capture_output=True, text=True
    )
    return result.stdout.strip()


def get_chain_pems(hostname, port=443):
    """
    Use openssl s_client -showcerts to pull every certificate in the chain.
    Returns a list of PEM strings [leaf, intermediate(s), root].
    """
    result = subprocess.run(
        ["openssl", "s_client", "-connect", f"{hostname}:{port}", "-showcerts"],
        input=b"", capture_output=True, timeout=15
    )
    output = (result.stdout + result.stderr).decode(errors="replace")

    pems, current, in_cert = [], [], False
    for line in output.splitlines():
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert, current = True, [line]
        elif "-----END CERTIFICATE-----" in line:
            current.append(line)
            pems.append("\n".join(current))
            in_cert = False
        elif in_cert:
            current.append(line)
    return pems


def verify_chain(hostname, port=443):
    """
    Ask openssl s_client to verify the full chain.
    Returns (trusted: bool, code_string: str).
    """
    result = subprocess.run(
        ["openssl", "s_client", "-connect", f"{hostname}:{port}",
         "-verify", "5", "-verify_return_error"],
        input=b"Q\n", capture_output=True, timeout=15
    )
    output = (result.stdout + result.stderr).decode(errors="replace")
    if "Verify return code: 0 (ok)" in output:
        return True, "0 (ok)"
    for line in output.splitlines():
        if "Verify return code" in line:
            return False, line.split(":", 1)[-1].strip()
    return None, "Unknown"


# ══════════════════════════════════════════════════════════════
#  TASK 1 — Fetch & Display Certificate
# ══════════════════════════════════════════════════════════════

def task1_basic_info(hostname, port):
    separator(f"TASK 1 — SSL/TLS Certificate  [{hostname}:{port}]")

    cert, der, tls_ver, cipher = get_certificate(hostname, port)

    subject = dict(x[0] for x in cert.get("subject", []))
    sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    print(f"\n  {'Hostname':<26}: {hostname}")
    print(f"  {'Port':<26}: {port}")
    print(f"  {'TLS Version':<26}: {tls_ver}")
    print(f"  {'Cipher Suite':<26}: {cipher[0]}")
    print(f"  {'Key Bits':<26}: {cipher[2]}")

    print(f"\n  ── Subject (Owner) ─────────────────────────")
    for k, v in subject.items():
        print(f"  {k:<26}: {v}")

    print(f"\n  ── Subject Alternative Names ({len(sans)} SANs) ───")
    for san in sans[:10]:
        print(f"  {'DNS':<26}: {san}")
    if len(sans) > 10:
        print(f"  {'...':<26}  (+{len(sans) - 10} more domains)")


# ══════════════════════════════════════════════════════════════
#  TASK 2 — Expiration, Issuer & Encryption Details
# ══════════════════════════════════════════════════════════════

def task2_details(hostname, port):
    separator("TASK 2 — Expiration Date, Issuer & Encryption Details")

    cert, der, tls_ver, cipher = get_certificate(hostname, port)
    fmt = "%b %d %H:%M:%S %Y %Z"

    # ── Issuer ──────────────────────────────────────────────
    issuer = dict(x[0] for x in cert.get("issuer", []))
    print(f"\n  ── Issuer (Certificate Authority) ──────────")
    for k, v in issuer.items():
        print(f"  {k:<26}: {v}")

    # ── Validity / Expiry ────────────────────────────────────
    not_before_str = cert.get("notBefore", "")
    not_after_str  = cert.get("notAfter",  "")
    not_before     = datetime.datetime.strptime(not_before_str, fmt)
    not_after      = datetime.datetime.strptime(not_after_str,  fmt)
    days_left      = days_until(not_after_str)

    print(f"\n  ── Validity Period ─────────────────────────")
    print(f"  {'Issued On':<26}: {not_before.strftime('%Y-%m-%d  %H:%M:%S UTC')}")
    print(f"  {'Expires On':<26}: {not_after.strftime('%Y-%m-%d  %H:%M:%S UTC')}")
    print(f"  {'Status':<26}: {expiry_status(days_left)}")

    # ── Encryption Details ───────────────────────────────────
    print(f"\n  ── Encryption Details ──────────────────────")
    print(f"  {'TLS Version':<26}: {tls_ver}")
    print(f"  {'Cipher Algorithm':<26}: {cipher[0]}")
    print(f"  {'Protocol':<26}: {cipher[1]}")
    print(f"  {'Key Length (bits)':<26}: {cipher[2]}")

    pem    = ssl.DER_cert_to_PEM_cert(der)
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-text"],
        input=pem.encode(), capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        line = line.strip()
        if any(k in line for k in ["Public Key Algorithm", "Public-Key", "Signature Algorithm"]):
            k, _, v = line.partition(":")
            print(f"  {k.strip():<26}: {v.strip()}")

    print(f"  {'Serial Number':<26}: {cert.get('serialNumber', 'N/A')}")
    print(f"  {'X.509 Version':<26}: {cert.get('version', 'N/A')}")

    # ── Revocation Info ──────────────────────────────────────
    ocsp = cert.get("OCSP", ())
    crl  = cert.get("crlDistributionPoints", ())
    if ocsp or crl:
        print(f"\n  ── Revocation Info ─────────────────────────")
        for url in ocsp:
            print(f"  {'OCSP URL':<26}: {url}")
        for url in crl:
            print(f"  {'CRL URL':<26}: {url}")

    # ── SHA-256 Fingerprint ──────────────────────────────────
    pem        = ssl.DER_cert_to_PEM_cert(der)
    fp_output  = openssl_parse(pem, "-fingerprint", "-sha256")
    for line in fp_output.splitlines():
        if "Fingerprint" in line:
            k, _, v = line.partition("=")
            print(f"\n  ── Certificate Fingerprint ─────────────────")
            print(f"  {k.strip():<26}: {v.strip()}")


# ══════════════════════════════════════════════════════════════
#  TASK 3 — Certificate Chain Validation
# ══════════════════════════════════════════════════════════════

def task3_chain(hostname, port):
    separator("TASK 3 — Certificate Chain Validation")

    pems = get_chain_pems(hostname, port)
    if not pems:
        print("  [!] Could not retrieve certificate chain.")
        return

    # Build labels
    if len(pems) == 1:
        labels = ["[0] Leaf / Server (self-signed)"]
    else:
        labels = ["[0] Leaf / Server Certificate"]
        for i in range(1, len(pems) - 1):
            labels.append(f"[{i}] Intermediate CA #{i}")
        labels.append(f"[{len(pems)-1}] Root CA")

    print(f"\n  Chain length : {len(pems)} certificate(s)")
    print(f"  Structure    : Leaf  →  Intermediate(s)  →  Root CA\n")

    for pem, label in zip(pems, labels):
        r = subprocess.run(
            ["openssl", "x509", "-noout",
             "-subject", "-issuer", "-dates", "-serial", "-fingerprint", "-sha256"],
            input=pem.encode(), capture_output=True, text=True
        )
        print(f"  ── {label} {'─' * max(0, 44 - len(label))}")
        for line in r.stdout.strip().splitlines():
            k, _, v = line.partition("=")
            v = v.strip()
            if len(v) > 58:
                v = v[:55] + "..."
            print(f"  {k.strip():<28}: {v}")
        print()

    # ── Chain Trust Verdict ──────────────────────────────────
    trusted, code = verify_chain(hostname, port)
    print(f"  ── Chain Trust Verdict {'─' * 37}")
    if trusted is True:
        print(f"  [TRUSTED]    Chain verified by system CA store  (code: {code})")
    elif trusted is False:
        print(f"  [UNTRUSTED]  Verification failed  ({code})")
    else:
        print(f"  [UNKNOWN]    Could not determine trust ({code})")

    # ── Chain Diagram ────────────────────────────────────────
    print(f"""
  ── How the Chain of Trust Works ───────────────────────
  Your Browser / OS
       │  (has Root CA pre-installed in trust store)
       │
  {labels[-1].replace('[','').split(']')[1].strip():<30}   (self-signed, trusted anchor)
       │ signs
       ↓
  Intermediate CA                    (delegates trust down)
       │ signs
       ↓
  {hostname:<30}   (leaf — presented to you)

  Each link is verified cryptographically up the chain.
  If ANY link is broken or expired → connection is rejected.
""")


# ══════════════════════════════════════════════════════════════
#  TASK 4 — OpenSSL Command Reference
# ══════════════════════════════════════════════════════════════

def task4_openssl_commands(hostname, port):
    separator("TASK 4 — OpenSSL Command Reference")

    h = f"{hostname}:{port}"
    cmds = [
        ("View full certificate text",
         f"openssl s_client -connect {h} </dev/null 2>/dev/null \\\n      | openssl x509 -noout -text"),
        ("Check expiry dates",
         f"openssl s_client -connect {h} </dev/null 2>/dev/null \\\n      | openssl x509 -noout -dates"),
        ("Show issuer (CA)",
         f"openssl s_client -connect {h} </dev/null 2>/dev/null \\\n      | openssl x509 -noout -issuer"),
        ("Show subject / Common Name",
         f"openssl s_client -connect {h} </dev/null 2>/dev/null \\\n      | openssl x509 -noout -subject"),
        ("Show Subject Alternative Names",
         f"openssl s_client -connect {h} </dev/null 2>/dev/null \\\n      | openssl x509 -noout -text \\\n      | grep -A1 'Subject Alternative Name'"),
        ("Show full certificate chain",
         f"openssl s_client -connect {h} -showcerts </dev/null 2>/dev/null"),
        ("Validate chain trust",
         f"openssl s_client -connect {h} -verify 5 -verify_return_error </dev/null"),
        ("Get SHA-256 fingerprint",
         f"openssl s_client -connect {h} </dev/null 2>/dev/null \\\n      | openssl x509 -noout -fingerprint -sha256"),
        ("Save certificate to file",
         f"openssl s_client -connect {h} </dev/null 2>/dev/null \\\n      | openssl x509 > cert.pem"),
        ("Inspect saved cert file",
         "openssl x509 -in cert.pem -noout -text"),
        ("Verify cert against CA bundle",
         "openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt cert.pem"),
        ("Check cert & key modulus match",
         "openssl x509 -noout -modulus -in cert.pem | md5sum\n      openssl rsa  -noout -modulus -in key.pem  | md5sum"),
    ]

    for title, cmd in cmds:
        print(f"\n  ▶  {title}")
        for line in cmd.split("\n"):
            print(f"     $ {line}")


# ══════════════════════════════════════════════════════════════
#  DYNAMIC INPUT + MAIN
# ══════════════════════════════════════════════════════════════

def get_input():
    """
    Resolve hostname and port from:
      1. Command-line arguments  →  python3 script.py google.com [443]
      2. Interactive prompt      →  typed at runtime
    """
    if len(sys.argv) >= 2:
        hostname = clean_host(sys.argv[1])
        port     = int(sys.argv[2]) if len(sys.argv) >= 3 else 443
    else:
        print("\n  ┌─────────────────────────────────────────────┐")
        print("  │   SSL/TLS Dynamic Certificate Validator     │")
        print("  └─────────────────────────────────────────────┘")
        raw  = input("\n  Enter domain (e.g. google.com or https://github.com): ").strip()
        p    = input("  Enter port   [press Enter for 443]: ").strip()
        hostname = clean_host(raw)
        port     = int(p) if p.isdigit() else 443

    return hostname, port


def main():
    hostname, port = get_input()

    if not hostname:
        print("  [!] No domain provided. Exiting.")
        sys.exit(1)

    print(f"\n  ╔══════════════════════════════════════════════════════════╗")
    print(f"  ║   SSL/TLS CERTIFICATE VALIDATION PRACTICAL               ║")
    print(f"  ║   Target : {(hostname + ':' + str(port)).ljust(47)}║")
    print(f"  ╚══════════════════════════════════════════════════════════╝")

    try:
        task1_basic_info(hostname, port)
        task2_details(hostname, port)
        task3_chain(hostname, port)
        task4_openssl_commands(hostname, port)
        separator("VALIDATION COMPLETE")

    except socket.timeout:
        print(f"\n  [ERROR] Connection to {hostname}:{port} timed out.")
    except ssl.SSLCertVerificationError as e:
        print(f"\n  [ERROR] Certificate verification failed:\n         {e}")
    except ssl.SSLError as e:
        print(f"\n  [ERROR] SSL error: {e}")
    except socket.gaierror:
        print(f"\n  [ERROR] Cannot resolve hostname '{hostname}'. Check spelling.")
    except ConnectionRefusedError:
        print(f"\n  [ERROR] Connection refused on {hostname}:{port}.")
    except Exception as e:
        print(f"\n  [ERROR] Unexpected error: {e}")


if __name__ == "__main__":
    main()