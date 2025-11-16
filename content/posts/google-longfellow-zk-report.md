---
title: "Finding a DoS in Google's Longfellow-ZK (And Getting Rejected)"
date: 2025-08-09
tags: ["DoS", "MemorySafety", "ZeroKnowledgeProtocol", "ReverseEngineering"]
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
<img width="376" height="538" alt="image" src="https://github.com/user-attachments/assets/070ce7b8-6897-4068-9b30-eb427f5d991d" />


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
<img width="890" height="325" alt="image" src="https://github.com/user-attachments/assets/7018623d-2b36-4932-82ba-ffb2f0988dda" />


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

<img width="626" height="656" alt="image" src="https://github.com/user-attachments/assets/ca8a1f8f-c160-40a4-9ad0-869cb35353ae" />


Now, calling `abort()` directly is already a red flag. But where is this being used?


```bash
grep -r "check(" lib/ | wc -l
```
<img width="405" height="199" alt="image" src="https://github.com/user-attachments/assets/8e5fa1bd-85e3-40c3-9bc4-7d4c5f1a2cf5" />


173 uses! This `check()` function is all over the codebase. Let me look at some specific cases:

```bash
grep -r "check(" lib/
```

One particular usage caught my eye in the field arithmetic code...

<img width="850" height="699" alt="image" src="https://github.com/user-attachments/assets/5d332208-e832-4ed1-9447-66b9b7d04daf" />

This one immediately caught my attention:

```
lib/algebra/fp_generic.h: check(a < m_, "of_scalar must be less than m");
```

This is doing input validation on field values. Let me look at the actual code:

```bash
cat lib/algebra/fp_generic.h | grep -A 5 "of_scalar_field"
```
<img width="714" height="574" alt="image" src="https://github.com/user-attachments/assets/58eb391c-9409-49f5-a27e-3c17b4a04d80" />

```cpp
Elt of_scalar_field(const N& a) const {
    check(a < m_, "of_scalar must be less than m");
    return to_montgomery(a);
}
```

Wait, so if someone passes an invalid field value... this `check()` function gets called... which calls `abort()`... which **terminates the entire process**?

<img width="512" height="512" alt="c85fcc99-fbf8-4be4-b992-5dfb55183cf3" src="https://github.com/user-attachments/assets/ebcfdc3d-1431-4019-b3ad-97a561e99994" />


---
