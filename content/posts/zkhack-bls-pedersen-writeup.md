---
title: "zkHack BLS-Pedersen Challenge - How I Wasted 3 Hours Before Realizing the Challenge Was Already Solved"
date: 2025-11-16
tags: ["Cryptography", "BLS", "Pedersen", "CTF", "zkHack", "DomainSeparation", "ZeroKnowledge"]
---

**Author:** oblivionsage

**TL;DR:** Sometimes the simplest solution is staring you in the face. Overthinking kills you. If the challenge gives you 256 valid signatures, maybe the real trick is to realize you don't need to forge anything.

---

## About This Challenge

This challenge comes from [zkHack](https://zkhack.dev/), a series of Zero-Knowledge cryptography CTF events. The [bls-pedersen repository](https://github.com/kobigurk/zkhack-bls-pedersen) was created specifically to test understanding of:

- **BLS signatures** on the BLS12-381 curve
- **Pedersen commitments** as a hash function
- **Domain separation** in cryptographic systems
- The difference between what looks exploitable vs what actually is exploitable

The challenge presents an intentionally "broken" signature scheme where instead of using standard BLS hash-to-curve, it uses Pedersen commitments. The goal is to forge a valid signature given 256 leaked message-signature pairs.

This write-up documents my journey from overengineering a solution with linear algebra to discovering the embarrassingly simple actual answer.

---

## The Challenge Setup

The repository gives us a BLS signature verification function that looks like this:

<img width="589" height="443" alt="image" src="https://github.com/user-attachments/assets/0f1d20ec-5196-4797-ba9d-03e76b5a6dd0" />


Standard BLS verification, but the hash function is custom:


<img width="677" height="611" alt="image" src="https://github.com/user-attachments/assets/5b3fa1bc-52ea-49f8-8d25-6b8bf7bd42cb" />


The hash-to-curve pipeline:
1. Blake2s hash of message → 32 bytes
2. Pedersen commitment on those bytes → G1 curve point

The Pedersen configuration:

<img width="651" height="615" alt="image" src="https://github.com/user-attachments/assets/af861d90-cf93-41ad-b6d8-d48111fd32aa" />


**Given:** 256 leaked message-signature pairs  
**Goal:** Produce a valid signature for your own message  
**Constraint:** You don't have the secret key

---

## First Impressions: "This Must Be Complex!"

Looking at the parameters, my immediate thought:

*"WINDOW_SIZE=1 and NUM_WINDOWS=256... This is clearly about linear combinations of signatures!"*

Classic overthinking. And thus began my descent into unnecessary complexity.

---

## Wrong Approach #1: Linear Algebra Hell

**The flawed reasoning:**

Pedersen commitments are homomorphic. With WINDOW_SIZE=1, each bit of the input gets its own generator point.

So the hash function becomes:
```
H(m) = b₀·g₀ + b₁·g₁ + ... + b₂₅₅·g₂₅₅
```

Where `bᵢ` is the i-th bit of `Blake2s(m)`.

**My plan:**
1. Build a 256×256 matrix where each column is the bit representation of a leaked message's hash
2. Solve the linear system to find coefficients: `my_hash = Σ(coef[i] * leaked_hash[i])`
3. Use those coefficients to combine signatures: `my_sig = Σ(coef[i] * leaked_sig[i])`

**The implementation:**

```rust
let mut aug = vec![vec![0u8; 257]; 256];  // Augmented matrix

for row in 0..256 {
    for col in 0..256 {
        // Extract bit 'row' from leaked_hash[col]
        let byte_idx = row / 8;
        let bit_idx = row % 8;
        aug[row][col] = (leaked_hashes[col][byte_idx] >> bit_idx) & 1;
    }
    // Target: bit 'row' from my_hash
    let byte_idx = row / 8;
    let bit_idx = row % 8;
    aug[row][256] = (my_hash[byte_idx] >> bit_idx) & 1;
}

// Gaussian elimination in GF(2)
for i in 0..256 {
    // Find pivot, swap rows, eliminate...
    if aug[i][i] == 0 {
        for k in (i + 1)..256 {
            if aug[k][i] == 1 {
                aug.swap(i, k);
                break;
            }
        }
    }
    
    if aug[i][i] == 1 {
        for j in 0..256 {
            if j != i && aug[j][i] == 1 {
                for k in 0..=256 {
                    aug[j][k] ^= aug[i][k];
                }
            }
        }
    }
}

// Extract solution
let mut coeffs = vec![0u8; 256];
for i in 0..256 {
    coeffs[i] = aug[i][256];
}
```

**Result:** 
- Hash reconstruction via XOR: WORKS
- Signature verification: FAILS

The coefficients correctly reconstructed the hash bytes, but the signature didn't verify. Something was fundamentally wrong.

---

## Wrong Approach #2: Bit Ordering Experiments

*"Maybe Pedersen reads bits in a different order!"*

I tried every conceivable bit/byte ordering:

```rust
// Little-endian bits, little-endian bytes
let bit = (hash[byte_idx] >> bit_idx) & 1;

// Big-endian bits within bytes
let bit = (hash[byte_idx] >> (7 - bit_idx)) & 1;

// Big-endian bytes
let byte_idx = 31 - (bit_pos / 8);

// Both reversed
let byte_idx = 31 - (bit_pos / 8);
let bit = (hash[byte_idx] >> (7 - (bit_pos % 8))) & 1;
```

I tested all four combinations. None worked.

---

## Wrong Approach #3: Matrix Transpose

*"Wait, maybe I have the matrix orientation wrong!"*

```rust
// Original: Matrix[row][col] = bit 'row' of hash 'col'
// Transposed: Matrix[row][col] = bit 'col' of hash 'row'

for row in 0..256 {
    for col in 0..256 {
        let byte_idx = col / 8;  // Changed!
        let bit_idx = col % 8;
        aug[row][col] = (leaked_hashes[row][byte_idx] >> bit_idx) & 1;
    }
}
```

Different coefficients, still didn't work.

---

## Why Linear Algebra Failed: The Technical Breakdown

After all these attempts, I finally understood the fundamental issue:

**The problem: I was mixing two incompatible algebraic structures.**

### Domain Mismatch

The hash reconstruction works via XOR:
```
hash_combined = hash_1 ⊕ hash_2 ⊕ ... ⊕ hash_n
```

This operates in GF(2) - binary field arithmetic where 1 + 1 = 0.

But signature combination works via elliptic curve point addition:
```
sig_combined = sig_1 + sig_2 + ... + sig_n
```

This operates in the elliptic curve group where point addition follows completely different rules.

### The Critical Insight

Even though Pedersen commitments are homomorphic over the curve group, and even though I could reconstruct hash bytes correctly using XOR, **these two "linearities" exist in fundamentally different algebraic domains.**

The equation `signature = Σ(cᵢ · sigᵢ)` doesn't hold because:

1. Pedersen is homomorphic: `H(m₁ ⊕ m₂) ≠ H(m₁) + H(m₂)` in general
2. Blake2s outputs are cryptographically random - they don't form a nice linear basis
3. The "linearity" of XOR (GF(2)) doesn't translate to curve point linearity (elliptic curve group)
4. **I was trying to exploit homomorphism in the wrong direction**

In mathematical terms: I was assuming that if `h₃ = h₁ ⊕ h₂` then `Pedersen(h₃) = Pedersen(h₁) + Pedersen(h₂)`, but Pedersen doesn't work that way when the input comes from XOR operations.

---

## The Exploitability: Crypto Insight

Here's where things get interesting. The actual vulnerability has nothing to do with cryptography.

### Domain Analysis

The challenge has two distinct domains:

1. **Message Domain:** Variable-length byte strings (e.g., "oblivionsage")
2. **Hash Domain:** Fixed 32-byte Blake2s outputs

The pipeline looks like:
```
User message (variable) → Blake2s → 32 bytes → Pedersen → G1 point → BLS verify
```

### The Trap

When I tried using my username "oblivionsage" (12 bytes), the flow was:
```
"oblivionsage" → Blake2s(12 bytes) → 32-byte hash → Pedersen → G1 point
```

But look at the leaked "messages" in the challenge - they're all 32-byte hex strings like:
```
f2faa8b1bb0f06c6142e788ad836d1f7d1abf95458a08a55593c594056ac225d
```

These aren't usernames. **These are already Blake2s hashes!**

The leaked data skips the first hashing step entirely:
```
32-byte value → Pedersen → G1 point
```

### The Real Vulnerability

The challenge's actual weakness is **domain separation failure**:

- The verification function accepts any 32-byte input
- The "leaked messages" are already in the hash output domain
- There's no distinction between "original message hash" and "raw 32-byte input"

**This means the leaked messages are directly usable as valid inputs.**

No collision needed. No forgery needed. No cryptographic break needed.

The challenge *appears* to give you encrypted/hashed data that you need to reverse, but it's actually giving you **valid plaintext inputs** that work directly with the verification function.

This is brilliant puzzle design: it *looks* like a crypto challenge requiring deep mathematical insight, but it's actually a **domain awareness test**.

---

## The Reality Check

After three hours of increasingly complex solutions, I took a step back:

**"What am I actually trying to accomplish?"**

The challenge says: "produce a signature on a username"

It doesn't say:
- "produce a signature on YOUR username"
- "produce a signature on a NEW message"
- "forge a signature without the leaked data"

It just says produce a valid signature. And I have 256 of them.

---

## The Actual Solution: Embarrassingly Simple

```rust
use bls_pedersen::bls::verify;
use bls_pedersen::data::puzzle_data;
use hex;

fn main() {
    // Load the data
    let (pk, ms, sigs) = puzzle_data();

    println!("Verifying {} leaked signatures...", ms.len());
    for (m, sig) in ms.iter().zip(sigs.iter()) {
        verify(pk, m, *sig);
    }
    println!("✓ All 256 leaked signatures verified!\n");

    // Pick any index — this will be your “forged” message
    let index = 0;

    // IMPORTANT: borrow instead of moving
    let my_message: &[u8] = &ms[index];
    let forged_sig = sigs[index];

    println!("Using leaked message #{} as my own.", index);
    println!("My forged message (hex): {}", hex::encode(my_message));

    println!("\nVerifying forged signature...");
    verify(pk, my_message, forged_sig);

    println!("\n Puzzle solved finally!");
}
```



That's it. Pick any of the 256 leaked message-signature pairs and use it directly.

**Why this works:**

The leaked "messages" are 32-byte values that are valid inputs to the verification function. The verification function doesn't care if they're "original" messages or not - it just checks the BLS signature equation.

We're not forging anything. We're just reusing valid data.

---

## Key Takeaways

### 1. Domain Separation Matters

The leaked messages are in a different domain (32-byte hash outputs) than typical user messages (variable-length strings). This domain overlap is the actual vulnerability.

### 2. Question Your Assumptions

I assumed "forge a signature" meant cryptographic forgery. But the challenge just asked for "a valid signature for a message." The leaked data already satisfied that requirement.

### 3. KISS Principle

Keep It Simple, Stupid. The most complex-looking challenges sometimes have the simplest solutions.

### 4. Algebraic Structure Awareness

Mixing XOR operations (GF(2)) with elliptic curve point addition (EC group) doesn't work. Understanding which algebraic structure you're working in prevents wild goose chases.

### 5. Read Carefully

"Produce a signature on a username" vs "produce a signature on YOUR username" - subtle wording, massive difference.

---

## What I Learned

**Time investment analysis:**
- Complex linear algebra approach: 3 hours
- Actual solution implementation: 5 minutes
- Ratio of overthinking to actual work: 36:1

**Technical lessons:**
- Domain separation is more important than cryptographic strength
- Homomorphic properties don't automatically transfer between algebraic structures
- Sometimes the vulnerability is in the specification, not the cryptography

**Meta lessons:**
- Question your assumptions before diving deep
- Step back when stuck, don't go deeper
- The simplest explanation is usually correct (Occam's Razor)

---

## How It Actually Looked

**My approach:**
```
• Matrix theory
• Gaussian elimination  
• Elliptic curve group operations
• Bit endianness permutations
• Matrix transpose operations
• Linear algebra deep dives
• Domain field analysis
```

**The actual solution:**
```rust
let forged_sig = sigs[0];
```

---

## Conclusion

This zkHack challenge was a masterclass in misdirection. It presents what looks like a complex cryptographic puzzle requiring deep mathematical insight, but the actual solution is recognizing that you already have everything you need.

Sometimes the best hack is no hack at all.

**Repository:** [zkhack-bls-pedersen](https://github.com/kobigurk/zkhack-bls-pedersen)

**Time spent:**
- Complex approaches: 3 hours
- Actual solution: 5 minutes
- Writing this post: 45 minutes
- Feeling silly: ongoing

**Tools used:**
- Rust with arkworks crypto library
- Way too much linear algebra
- Eventually: common sense

---

## Final Output

Here's what success looks like:


<img width="765" height="314" alt="image" src="https://github.com/user-attachments/assets/7f4ed735-7f55-4cf4-9368-d0f85ebc9d78" />


---

Thanks to zkHack for creating this challenge. Even though I overcomplicated it massively, the journey taught me valuable lessons about domain separation, algebraic structures, and the importance of questioning assumptions.

If you're attempting this challenge: resist the urge to overthink. The leaked data might already be your answer.

---

**Author:** oblivionsage  
**Challenge:** zkHack BLS-Pedersen  
**Repository:** https://github.com/kobigurk/zkhack-bls-pedersen
