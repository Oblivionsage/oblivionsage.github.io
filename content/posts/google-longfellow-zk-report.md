---
title: "Finding a DoS in Google's Longfellow-ZK (And Getting Rejected)"
date: 08/09/2025
tags: ["DoS", "MemorySafety", "ZeroKnowledgeProtocol" "ReverseEngineering"]
---


# Finding a DoS in Google's Longfellow-ZK (And Getting Rejected)

## TL;DR

I found a denial of service vulnerability in Google's longfellow-zk cryptographic library where invalid input crashes the entire process. Reported it to Google VDP, they said "won't fix" because it didn't meet their severity threshold. Here's the full story and technical details.

## How It Started

So I was scrolling through GitHub looking for interesting crypto projects to audit, and I stumbled upon [longfellow-zk](https://github.com/google/longfellow-zk) - Google's new zero-knowledge proof library. What caught my attention was this line in the README:

> "This project is currently undergoing two independent security reviews by panels of academic and industry experts"

You know what that means? Fresh code, security reviews still ongoing, perfect timing to dig in.

## Initial Recon

First thing I did was clone the repo and start poking around:
```bash
git clone https://github.com/google/longfellow-zk.git
cd longfellow-zk
tree -d -L 2
```

The library is header-only C++, organized into modules like:
- `algebra/` - field arithmetic
- `ec/` - elliptic curve operations  
- `circuits/` - ZK circuit implementations
- `util/` - utility functions

I started with the usual suspects - searching for common vulnerability patterns:
```bash
grep -r "TODO\|FIXME\|XXX" lib/
grep -r "unsafe\|vulnerable" lib/
```

Nothing super interesting in the TODOs. But then I noticed something in the utility functions...

## The Vulnerable Code

In `lib/util/panic.h`, there's this simple error handling function:
```cpp
inline void check(bool truth, const char* why) {
#if defined(__ABSL__)
  CHECK(truth) << why;
#else
  if (!truth) {
    fprintf(stderr, "%s", why);
    abort();  //  Wait, what?
  }
#endif
}
```

Now, calling `abort()` directly is already a red flag. But where is this being used?
```bash
grep -r "check(" lib/ | wc -l
```

Tons of places. Let me look at one specific case in the field arithmetic code (`lib/algebra/fp_generic.h`):
```cpp
Elt of_scalar_field(const N& a) const {
    check(a < m_, "of_scalar must be less than m");
    return to_montgomery(a);
}
```

So here's what happens: if you try to create a field element with an invalid value, the library doesn't return an error or throw an exception - it just kills your entire process with `abort()`.

That's a textbook denial of service.

---
