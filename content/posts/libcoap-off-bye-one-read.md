---
title: "Off-by-One Read in libcoap check_segment() Percent-Encoding Validation"
date: 2025-12-29
tags: ["MemorySafety", "libcoap", "CoAP", "C", "OpenSource", "ASan"]
---

## TL;DR

Found an off-by-one out-of-bounds read in libcoap's `check_segment()` function. The percent-encoding validation checks `length < 2` but accesses `s[2]`, causing a 1-byte OOB read with truncated input like `%A`. Maintainer confirmed and fixed. No CVE , local API misuse only, not remotely exploitable.

## Background

libcoap is a C implementation of the Constrained Application Protocol (RFC 7252). CoAP is basically "HTTP for IoT" lightweight protocol for constrained devices like sensors, actuators, and embedded systems. Used in smart home, industrial IoT, and resource-constrained environments.

The library handles URI parsing, including percent-encoded sequences in paths and queries. During a code audit focusing on memory safety issues in URI handling, I found this bug.

## Finding the Bug

I was reviewing `src/coap_uri.c` looking at percent-encoding handling. The `check_segment()` function validates URI path segments:

```c
// src/coap_uri.c:464-481
static int
check_segment(const uint8_t *s, size_t length, size_t *segment_size) {
  size_t n = 0;

  while (length) {
    if (*s == '%') {
      if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))  // bug here
        return -1;

      s += 2;
      length -= 2;
    }

    ++s;
    ++n;
    --length;
  }
  ...
}
```

Percent-encoding format is `%HH` - 3 bytes total (`%` + 2 hex digits). The check should be `length < 3` but it's `length < 2`. When `length == 2` and first char is `%`:

- `length < 2` → `2 < 2` → false, check passes
- `isxdigit(s[2])` → reads beyond buffer

Interestingly, `coap_replace_percents()` at line 719 does this correctly:

```c
if (optlist->data[i] == '%' && optlist->length - i >= 3)
```

Same codebase, same purpose, different implementation - one correct, one buggy.

## Proof of Concept

Built libcoap with AddressSanitizer:

```bash
git clone https://github.com/obgm/libcoap.git
cd libcoap
./autogen.sh
./configure --disable-doxygen --disable-manpages --disable-dtls \
    CFLAGS="-fsanitize=address -g -O0" \
    LDFLAGS="-fsanitize=address"
make -j$(nproc)
```

PoC using public API:

```c
// poc_uri.c
#include <coap3/coap.h>

int main(void) {
  const uint8_t path[] = { '%', 'A' };  // 2-byte truncated percent-encoding
  size_t path_len = sizeof(path);
  unsigned char buf[128];
  size_t buflen = sizeof(buf);

  coap_startup();
  coap_set_log_level(COAP_LOG_DEBUG);

  coap_split_path(path, path_len, buf, &buflen);

  coap_cleanup();
  return 0;
}
```

Compile and run:

```bash
gcc -fsanitize=address -g -O0 -I./include poc_uri.c \
    -L.libs -lcoap-3-notls -Wl,-rpath,.libs -o poc_uri
./poc_uri
```

ASan output:

<img width="1128" height="969" alt="image" src="https://github.com/user-attachments/assets/17dca0ee-37f8-4bd2-ad14-e631d86d605c" />


ASan confirms exact location , line 469 in `check_segment()`, the `isxdigit(s[2])` call. The 2-byte `path` variable (offset 48-50) was accessed at offset 50, exactly 1 byte overflow

## The Fix

Maintainer pushed fix within 20 minutes. One character change:
```c
- if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))
+ if (length < 3 || !(isxdigit(s[1]) && isxdigit(s[2])))
```

Commit: `dadb9a36f15abea8254be75753298961c64ec7a6` - "coap_uri.c: Fix off by one checking error"

<img width="1041" height="719" alt="image" src="https://github.com/user-attachments/assets/be78a08b-a6a9-4a4e-8c27-9d2e0ce697d8" />


## Disclosure

Reported via email to libcoap-security@tzi.org. Maintainer (Jon Shallow) responded quickly:

<img width="1611" height="319" alt="image" src="https://github.com/user-attachments/assets/aa2fad02-7133-4d95-8dbc-606d75bdedf3" />

Fair assessment. The bug is real but:

- Requires local API misuse
- Not triggerable via network (CoAP packets auto-expand `%` to `%25`)
- Often masked by NUL terminators or non-faulting memory reads

No CVE assigned - local only, not remote

## Conclusion

Real memory safety bug in a widely-used IoT library, but limited practical impact due to:

- Local API misuse required
- Network protocol prevents remote triggering
- Often masked by string terminators

What I learned:

- libcoap architecture and URI handling

**Status:** Fixed in commit `dadb9a36f15abea8254be75753298961c64ec7a6`, merged to develop branch

---

**Timeline:**
- December 28, 2025: Bug discovered during code audit
- December 28, 2025: Reported to libcoap-security@tzi.org
- December 29, 2025: Maintainer response, confirmed bug
- December 29, 2025: Fix merged (20 minutes after report)

**Affected:** libcoap versions with `coap_split_path()` API
**Fix:** Commit `dadb9a3` on develop branch

---
