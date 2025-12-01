---
title: "CVE-2025-66221: Windows Device Name Bypass in Werkzeug's safe_join()"
date: 2025-07-22
tags: ["CVE", "Python", "Flask", "Werkzeug", "PathTraversal", "Windows", "Security"]
---

# CVE-2025-66221: Windows Device Name Bypass in Werkzeug's safe_join()

**TL;DR:** I found that Werkzeug's `safe_join()` function doesn't validate Windows reserved device names (CON, PRN, AUX, etc.), allowing attackers to bypass path validation and cause denial of service. This affects Flask and countless Python web applications running on Windows.

---

## Background

A few months ago, I discovered [CVE-2025-27210](https://nvd.nist.gov/vuln/detail/CVE-2025-27210) — a path traversal vulnerability in Node.js where `path.normalize()` failed to handle Windows device names properly. After that finding, I started wondering: **is this pattern present in other frameworks too?**

Spoiler: yes, it is.

I decided to systematically audit popular web frameworks for the same vulnerability class. Werkzeug was high on my list because it's the WSGI toolkit that powers Flask — one of Python's most widely-used web frameworks. Companies like Netflix, Reddit, Lyft, and Airbnb use Flask in production.

If the same bug existed here, the impact would be massive.

---

## What Are Windows Device Names?

Windows has special reserved device names that date back to DOS compatibility. These include:

- `CON` — Console (stdin/stdout)
- `PRN` — Printer
- `AUX` — Auxiliary device
- `NUL` — Null device (like /dev/null)
- `COM1-COM9` — Serial ports
- `LPT1-LPT9` — Parallel ports

The dangerous thing about these names is that they exist **implicitly in every directory**. You can't create files with these names, and attempting to open them triggers special OS behavior.

For example, trying to read `CON` will wait for console input — hanging your application indefinitely.

---

## Finding the Vulnerability

I started by looking at Werkzeug's path handling functions. The `safe_join()` function in `werkzeug/security.py` is designed to safely join user-provided paths with a base directory:

```python
def safe_join(directory: str, *pathnames: str) -> str | None:
    # ... setup code ...
    for filename in pathnames:
        if filename != "":
            filename = posixpath.normpath(filename)
        
        if (
            any(sep in filename for sep in _os_alt_seps)
            or os.path.isabs(filename)
            or filename.startswith("/")
            or filename == ".."
            or filename.startswith("../")
        ):
            return None
            
    return posixpath.join(*parts)
```

The function checks for:
- Alternative path separators
- Absolute paths
- Parent directory traversal (`..`)

But there's no validation for Windows device names. The function uses `posixpath.normpath()` which is platform-agnostic and doesn't understand Windows-specific restrictions.

---

## Proof of Concept

The exploit is straightforward:

```python
from werkzeug.security import safe_join

# All of these should return None but don't:
print(safe_join('/var/www/uploads', 'CON'))      # Returns: /var/www/uploads/CON
print(safe_join('/var/www/uploads', 'PRN'))      # Returns: /var/www/uploads/PRN  
print(safe_join('/var/www/uploads', 'AUX'))      # Returns: /var/www/uploads/AUX
print(safe_join('/var/www/uploads', 'CON.txt'))  # Returns: /var/www/uploads/CON.txt
```

**Expected behavior:** All should return `None` (blocked)

**Actual behavior:** All return valid paths (vulnerability confirmed)

---

## Real-World Impact: Flask Applications

Werkzeug's `safe_join()` is used internally by Flask's `send_from_directory()` function — a common way to serve user-uploaded files:

```python
from flask import Flask, send_from_directory

app = Flask(__name__)

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory('/var/www/uploads', filename)
```

On a Windows server, an attacker can request:

```
GET /uploads/CON HTTP/1.1
```

The application will attempt to open the `CON` device, which waits for console input — **hanging the request handler indefinitely**. 

With enough concurrent requests to `/uploads/CON`, an attacker can exhaust the application's worker pool and cause a complete denial of service.

---

## The Fix

The Pallets team patched this in Werkzeug 3.1.4. Here's what they changed:

First, they added a set of Windows device names in `security.py`:

```python
_windows_device_files = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(10)),
    *(f"LPT{i}" for i in range(10)),
}
```

Then they added a check in `safe_join()` that only triggers on Windows (`os.name == "nt"`):

```python
if (
    any(sep in filename for sep in _os_alt_seps)
    or (
        os.name == "nt"
        and os.path.splitext(filename)[0].upper() in _windows_device_files
    )
    or os.path.isabs(filename)
    # ... rest of checks
):
    return None
```

They also added a test to verify the fix:

```python
def test_safe_join_windows_special(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows special device name is not allowed on Windows."""
    monkeypatch.setattr("os.name", "nt")
    assert safe_join("a", "CON") is None
    monkeypatch.setattr("os.name", "posix")
    assert safe_join("a", "CON") == "a/CON"
```

Smart fix — it uses `os.path.splitext()` to handle cases like `CON.txt` and only blocks on Windows systems where these device names are actually dangerous.

---

## Cross-Framework Research

This vulnerability demonstrates a **systematic issue** across web frameworks. The same pattern existed in:

| Framework | CVE | Status |
|-----------|-----|--------|
| Node.js `path.normalize()` | CVE-2025-27210 | Fixed |
| Werkzeug `safe_join()` | CVE-2025-66221 | Fixed in 3.1.4 |

When you find a vulnerability pattern in one codebase, always check others. Developers often make the same assumptions, and POSIX-centric thinking leaves Windows-specific edge cases unhandled.

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| July 22, 2025 | Reported to Pallets Security Team via GitHub Security Advisory |
| July 22, 2025 | Added as collaborator, credited as reporter |
| November 2025 | Werkzeug 3.1.4 released with fix |
| November 2025 | CVE-2025-66221 assigned |
| November 2025 | Public disclosure |

Great experience working with the Pallets team on coordinated disclosure.

---

## Remediation

If you're running Flask or Werkzeug on Windows:

```bash
pip install --upgrade werkzeug>=3.1.4
```

---

## Key Takeaways

1. **Platform-specific edge cases matter.** POSIX-style path handling ignores Windows quirks.

2. **Vulnerability patterns repeat.** Finding CVE-2025-27210 in Node.js led directly to finding CVE-2025-66221 in Werkzeug.

3. **Audit widely-used dependencies.** Werkzeug powers Flask, which powers thousands of production applications.

4. **Denial of service is underrated.** It's not RCE, but hanging an entire web application is still a significant impact.

---

## References

- [CVE-2025-66221 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-66221)
- [GitHub Security Advisory - GHSA-hgf8-39gv-g3f2](https://github.com/pallets/werkzeug/security/advisories/GHSA-hgf8-39gv-g3f2)
- [CVE-2025-27210 - Node.js](https://nodejs.org/en/blog/vulnerability/july-2025-security-releases/)
- [Werkzeug Documentation](https://werkzeug.palletsprojects.com/)

---

**CVSS Score:** 6.3 (Moderate)  
**Attack Vector:** Network  
**Attack Complexity:** Low  
**Privileges Required:** None  

---

*This is my fourth published CVE. The cross-framework research approach continues to be productive — sometimes the best way to find new vulnerabilities is to look for old patterns in new places.*
