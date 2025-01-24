<head>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/katex.min.css" integrity="sha384-sMefv1J1YJCHsg0mTa9YG+n/9KnJb9lGrJUUY5arg6bAL1qps/oZjmUwaHlX5Ugg" crossorigin="anonymous">
    <!-- The loading of KaTeX is deferred to speed up page rendering -->
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/katex.min.js" integrity="sha384-i9p+YmlwbK0lT9RcfgdAo/Cikui1KeFMeV/0Fwsu+rzgsCvas6oUptNOmo29C33p" crossorigin="anonymous"></script>
    <!-- To automatically render math in text elements, include the auto-render extension: -->
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/contrib/auto-render.min.js" integrity="sha384-hCXGrW6PitJEwbkoStFjeJxv+fSOOQKOPbJxSfM6G5sWZjAyWhXiTIIAmQqnlLlh" crossorigin="anonymous"
        onload="renderMathInElement(document.body);"></script>
</head>

# The Design and Implementation of ShoHmacSha256

**ShoHmacSha256** is a Stateful Hash Object (SHO) that absorbs inputs incrementally, and produces arbitrary-length output when squeezed. Signal protocol defines a simple API for SHO, called ShoApi. This API is designed to mimic the behavior of an *extendable-output function* (XOF). [FIPS 202](#xref-nist-fips-202-xof) defines XOF as *a function on bit strings (also called messages) in which the output can be extended to any desired length*.

FIPS 202 requires XOFs to satisfy the two properties:

1. (One-way) It is computationally infeasible to find any input that maps to any new pre-specified output.
2. (Collision-resistant) It is computationally infeasible to find any two distinct inputs that map to the same output.


HMAC-SHA-256 is a keyed hash function as well as a pseudorandom function (PRF). In addition, it offers immunity against length-extension vulnerabilities of SHA-256. The output of HMAC-SHA-256 is a 256-bit value - a block of 32 bytes.

Since a XOF must produce arbitrary-length output, ShoHmacSha256 uses HMAC-SHA-256 as an entropy source to iteratively produce longer outputs. ShoHmacSha256 is used in parts of the protocol that depend on zero-knowledge proofs (zkp) to maintain privacy and secrecy guarantees. SHO is an essential element in the construction of many other protocols in Signal. Our aim here is to understand the design and implementation of this crucial cryptographic construction.

## ShoApi

[ShoApi trait](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shoapi.rs>) is part of `poksho` library of [libsignal project](<https://github.com/signalapp/libsignal>). The project states that `poksho` stands for "proof-of-knowledge, stateful-hash-object", and is a collection of "*utilities for implementing zero-knowledge proofs (such as those used by `zkgroup`)*";

We present a slightly formatted version of ShoApi below. We have added informal comments stating the general behavior of each function.

```rust
 1 pub trait ShoApi {
 2   // Create a SHO instance with domain-separator 'label'.
 3   fn new(label: &[u8]) -> Self
 4   where
 5       Self: Sized;
 6
 7   // Absorb 'input' incrementally; ingest streaming input.
 8   fn absorb(&mut self, input: &[u8]);
 9
10    // Make the current state of this SHO a one-way hash function of
11    // the preceding inputs. Ratcheting helps in percolating
12    // (pseudo)randomness in steps that squeeze outputs.
13    fn ratchet(&mut self);
14
15    // absorb() and ratchet() in one logical step.
16    fn absorb_and_ratchet(&mut self, input: &[u8]) {
17        self.absorb(input);
18        self.ratchet();
19    }
20
21    // Return a byte sequence of length 'outlen'.
22    // The length of the output could be arbitrarily large.
23    fn squeeze_and_ratchet(&mut self, outlen: usize) -> Vec<u8>;
24
25    // unimplemented; make this more generic later
26    // pub fn squeeze(&mut self, _outlen: usize) -> Vec<u8>;
27 }
```

It is clear from its definition that *ShoApi* is designed to maintain mutable state.

<a id="xref-sho-trait-absorb-and-ratchet"></a>
This trait provides a generic implementation for *absorb_and_ratchet(input)* in terms of the abstract functions *absorb(input)* followed by *ratchet()*.


## ShoHmacSha256

[ShoHmacSha256](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shohmacsha256.rs#L24-L28>) provides a concrete implementation of ShoApi. It is so named because it is constructed using HMAC-SHA-256. In this section we will focus on the type definitions and the creation semantics of ShoHmacSha256. I learnt a great deal referring to the conversations in two related threads: [Stateful Hash Object Proposal](#xref-trevor-sho-proposal) and [Symmetric Crypto overhaul and stateful hashing](#xref-trevor-sym-crypto-sho-proposal).

Let's take a first look at the types:

```rust
 1 pub struct ShoHmacSha256 {
 2     hasher: Hmac<Sha256>,
 3     cv: [u8; HASH_LEN],
 4     mode: Mode,
 5 }

 1 enum Mode {
 2     ABSORBING,
 3     RATCHETED,
 4 }
```
HASH_LEN is constant 32, defined elsewhere, representing the block length (in bytes) of SHA-256.

This construction is based on HMAC-SHA-256 keyed-hashing function. It is useful to recall that HMAC-SHA-256 is a pseudorandom function. As we will see later, SHO operates in two *modes*s: ABSORBING and RATCHETED. While ABSORBING, **hasher** simply ingests its inputs. When SHO is ratcheted, the **chaining variable** *cv* captures *hasher*'s pseudorandom output. We will see more about ratcheting in later sections.

## SHO use cases in *libsignal*

Before diving into the details, it is worthwhile to see how ShoHmacSha256 is used within *libsignal* project. Let us draw a few examples just to prime our mental model.

Our first snippet is from [poksho](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/statement.rs#L188-L195>):

```rust
 1 let mut sho =
 2     ShoHmacSha256::new(b"POKSHO_Ristretto_SHOHMACSHA256");
 3 sho.absorb(&self.to_bytes());
 4 for point in &all_points {
 5     sho.absorb(&point.compress().to_bytes());
 6 }
 7 sho.ratchet();
```

The `point` variable in the above code represents a 256-bit value.

The second example is from [zkcredential](<https://github.com/signalapp/libsignal/blob/main/rust/zkcredential/src/credentials.rs#L46-L48>):

```rust
 1 let mut sho =
 2     ShoHmacSha256::new(b"Signal_ZKCredential_CredentialPrivateKey_generate_20230410");
 3 sho.absorb_and_ratchet(&randomness);
```

The `randomness` argument in this snippet is an array of 32 bytes (a 256-bit value).

The last sample is from [backup auth credential](<https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/api/backups/auth_credential.rs#L140-L142>):

```rust
 1 let mut sho =
 2     poksho::ShoHmacSha256::new(b"20231003_Signal_BackupAuthCredentialRequest");
 3 sho.absorb_and_ratchet(uuid::Uuid::from(aci).as_bytes());
 4 sho.absorb_and_ratchet(&backup_key.0);
```

Take note of the domain separator strings, on line 2 of all three snippets. The second and third use cases make an effort to choose distinct prefixes, highlighting different contexts of the application.

Observe also that the first example absorbs multiple inputs before ratcheting, while the second example absorbs and ratchets in one logical step. The third example shows *absorb_and_ratchet()* used in succession.

## ShoHmacSha256 - Part 1

Let's get a little closer to the definitions of three key functions. For details [see here](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shohmacsha256.rs#L31-L62>):

```rust
 1 impl ShoApi for ShoHmacSha256 {
 2    fn new(label: &[u8]) -> ShoHmacSha256 {
 3        let mut sho = ShoHmacSha256 {
 4            hasher: Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
 5                .expect("HMAC accepts 256-bit keys"),
 6            cv: [0; HASH_LEN],
 7            mode: Mode::RATCHETED,
 8        };
 9        sho.absorb_and_ratchet(label);
10        sho
11    }
12
13    fn absorb(&mut self, input: &[u8]) {
14        if let Mode::RATCHETED = self.mode {
15            self.hasher = Hmac::<Sha256>::new_from_slice(&self.cv)
16                .expect("HMAC accepts 256-bit keys");
17            self.mode = Mode::ABSORBING;
18        }
19        self.hasher.update(input);
20    }
21
22    // currently called only after one or more absorb() calls.
23    fn ratchet(&mut self) {
24        if let Mode::RATCHETED = self.mode {
25            return;
26        }
27        self.hasher.update(&[0x00]);
28        self.cv.copy_from_slice(
29                   &self.hasher.clone().finalize().into_bytes());
30        self.hasher.reset();
31        self.mode = Mode::RATCHETED;
32    }
33 }

```

### Creation Semantics of ShoHmacSha256
The first thing to notice in function *new(label)* is that the HMAC's *key* is a block of zeroes. The *key* length is 32 bytes, which is the block length of SHA-256. This perfectly fits with [HMAC requirements](#xref-hmac-fips-198-1).

The domain separator *label* is not used in initializing the *hasher*. In my first reading, this came as a surprise because I was expecting the *label* value to be a seed to HMAC. Then I stumbled upon [answer 1](https://moderncrypto.org/mail-archive/noise/2018/001892.html) and [answer 2](https://moderncrypto.org/mail-archive/noise/2018/001894.html) which helped me see the thought process behind this construction.

It is not uncommon to use zeroes as HMAC key. In TLS 1.3, HMAC is keyed with a string of zeroes during the key derivation process (aka key schedule). While deriving the `Early Secret` for `client_early_traffic_secret` or `binder_key` in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)(section 7.1, page 93), the HKDF-Extract step explicitly receives a block of zeroes as *salt*. This value, in turn, is passed as HMAC's initial key material within [KHDF-Extract](https://datatracker.ietf.org/doc/html/rfc5869#section-2.2).


The SHO instance (named *sho*) starts off in the RATCHETED mode setting *cv* to a block of zeroes. Again, it is not surprising to see the length of *cv* matches the block length of SHA-256(32 bytes).

Immediately after crafting *sho*, construction proceeds to *absorb_and_ratchet* with passing *label* argument (the domain separator value). As we have already [seen](#xref-sho-trait-absorb-and-ratchet) in the ShoApi trait, this essentially absorbs the customization label and ratchets. Our immediate interest, therefore, is to understand the internals of these two functions.


#### Completing ShoHmacSha256 Construction with *absorb_and_ratchet*
A closer inspection of the call chain `new(label) --> absorb_and_ratchet(label)` reveals that the three functions can be readily inlined with simple renaming of function arguments. The result of such a source transformation is the following inlined function:

```rust
 1 fn _rewrite_inline_ShoHmacSha256_new_absorb_ratchet_(label: &[u8]) {
 2   // new
 3   let mut sho = ShoHmacSha256 {
 4     hasher: Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
 5                               .expect("HMAC accepts 256-bit keys"),
 6     cv: [0; HASH_LEN],
 7     mode: Mode::RATCHETED,
 8   };
 9
10   // sho.absorb_and_ratchet(label);
11   {
12     // absorb(label)
13     // rename "self" as "sho", and "input" as "label"
14     if let Mode::RATCHETED = sho.mode {
15       sho.hasher = Hmac::<Sha256>::new_from_slice(&sho.cv)
16                .expect("HMAC accepts 256-bit keys");
17       sho.mode = Mode::ABSORBING;
18     }
19     sho.hasher.update(label);
20
21     // ratchet()
22     // rename "self" as "sho".
23     if let Mode::RATCHETED = sho.mode {
24       return sho; // code rewrite: return "sho"
25     }
26     sho.hasher.update(&[0x00]);
27     sho.cv.copy_from_slice(
28                 &self.hasher.clone().finalize().into_bytes());
29     sho.hasher.reset();
30     sho.mode = Mode::RATCHETED;
31   }
32
33   sho
34 }
```

Note that *absorb_and_ratchet()* executes *absorb* when *sho* mode is RATCHETED.

The effect of *absorb(label)* on *sho* is the following:

1. *hasher* is replaced by a fresh HMAC-SHA-256 instance primed with the value *cv*.
    - at this point in execution, *cv* is simply a byte array of 32 zeroes.
2. the new *hasher* absorbs the domain separator *label*.
3. *mode* becomes ABSORBING.

In other words, when creating a new instance of SHO

1. *hasher*'s key is a 256 bit block of zeroes
    - it matches the block size of SHA-256.
    - this initializes *hasher* with a well-defined (predictable) state
2. the domain separator is absorbed.
    - the customization label becomes a prefix to context-related inputs absorbed later.
3. *sho* is prepared to absorb more inputs


Following *absorb*, in lines 26-28 actually carry out the crux of *ratchet()*

1. *hasher*'s input is zero-padded
2. *hasher* is finalized, and the pseudorandom output is extracted
    - recall that HMAC-SHA-256 is a PRF
3. *cv* is initialized with the fresh pseudorandom output from *hasher*

Now that *sho* has ratcheted and collected a one-way hash of the current state of *sho*, it reduces *hasher*'s state to a minimum in lines 29-30.

1. *hasher*'s internal state is reset
    - *hasher*'s key is reset to what it was prior to *finalize()* on line 28.
    - *hasher*s inputs are cleared.
2. *sho* enters RATCHETED mode
    - *cv* represents a one-way hash of the past inputs
    - *hasher* state is reset.
    - *hasher* is ready to accept fresh inputs.

In short, ShoHmacSha253 instance creation is operationally equivalent to the following code:

```rust
 1    let hs256 = Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
 2        .expect("HMAC accepts 256-bit keys");
 3    hs256.update(label); // absorb
 4    hs256.update(&[0x00]); // pad
 5
 8    let sho = {
 9        hasher: Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
10            .expect("HMAC accepts 256-bit keys"),
11        cv: hs256.finalize().into_bytes().into(),
12        mode: Mode::RATCHETED,
13    };
```


#### Producing Arbitrary-length Outputs using *squeeze_and_ratchet*

Let us try to read the following listing:

```rust
 1 impl ShoApi for ShoHmacSha256 {
 2    // new(), absorb(), ratchet() are elided.
 3
 4    //
 5    fn squeeze_and_ratchet(&mut self, outlen: usize) -> Vec<u8> {
 6      assert!(self.mode == Mode::RATCHETED);
 7      let mut output = Vec::<u8>::new();
 8      let output_hasher_prefix =
 9            Hmac::<Sha256>::new_from_slice(&self.cv)
10                 .expect("HMAC accepts 256-bit keys");
10      let mut i = 0;
11      while i * HASH_LEN < outlen {
13        let mut output_hasher = output_hasher_prefix.clone();
14        output_hasher.update(&(i as u64).to_be_bytes());
15        output_hasher.update(&[0x01]);
16        let digest = output_hasher.finalize().into_bytes();
17        let num_bytes = cmp::min(HASH_LEN, outlen - i * HASH_LEN);
18        output.extend_from_slice(&digest[0..num_bytes]);
19        i += 1
20      }
21      //
22      // ratchet over inputs, output length, and a padding byte
23      let mut next_hasher = output_hasher_prefix;
24      next_hasher.update(&(outlen as u64).to_be_bytes());
25      next_hasher.update(&[0x02]);
26      self.cv.copy_from_slice(
27                    &next_hasher.finalize().into_bytes()[..]);
28      self.mode = Mode::RATCHETED;
29      output
30    }
31 }
```

##### Squeezing the Output
The first part of this function, specifically lines 6 to 20, represents the *squeeze* step. It resembles the `HKDF-Extract` and the iterative `HKDF-Expand` phase of HKDF with minor differences in their inputs.

In line 6 we see that *squeeze_and_ratchet* is defined only if SHO is already RATCHETED. For illustration, let us assume that the SHO has ratcheted $k$ times so far:
$$
    R_0 \ \text{\textemdash}\text{\textemdash} \ R_1 \ \text{\textemdash}\text{\textemdash} \ R_2 \ \text{\textemdash}\text{\textemdash} \ \dots \ \text{\textemdash}\text{\textemdash} \ R_{k-1} \ \text{\textemdash}\text{\textemdash}\ R_{k}
$$

This means that all inputs absorbed after ratchet ${R_{k-1}}$ have been hashed, and stored in the state variable *cv*. This is equivalent to `HKDF-Extract` because *cv* in ratchet $R_k$ stores the randomness extracted from the inputs since ${R_{k-1}}$.

*output_hasher_prefix* is a fresh HMAC-SHA-256 hasher keyed with the pseudorandom key *cv*. In each iteration, lines 11 to 20 squeeze one block of output and append it to *output*. In the loop, *output_hasher* is simply a clone of *output_hasher_prefix*. The cloning is required because *finalize* consumes *output_hasher*, and so, there's no way to reuse the hasher.

In lines 14 and 15 we see that the newly cloned *output_hasher* works with only two inputs of length 9 bytes in total:
- a 64 bit output-block number
    - starting from zero, each number is 8 bytes in length, stored in big-endian format
- constant 1, serving as a padding byte.


$$
\begin{array}{rll}
    N & = & ceil(\text{outlen/HASH\_LEN}) \\
    \text{output} & = & T_0 \ | \ T_1 \ | \ ... \ | \ T_{N-1} \\
\end{array}
$$

When *outlen* is not a multiple of HASH_LEN, some M initial bytes of the last block, $T_{N-1}$, may be copied to *output* where $0$ < M < HASH_LEN.

We list a few examples showing HMAC's inputs and outputs:

$$
\begin{array}{rll}
    T_0 & = & \text{HMAC-SHA-256}(\text{cv, 0x0000000000000000} \ | \ 1) \\
    T_1 & = & \text{HMAC-SHA-256}(\text{cv, 0x0000000000000001} \ | \ 1) \\
    T_2 & = & \text{HMAC-SHA-256}(\text{cv, 0x0000000000000002} \ | \ 1) \\
    ...\\
    T_{255} & = & \text{HMAC-SHA-256}(\text{cv, 0x00000000000000FF} \ | \ 1) \\
    ...\\
    T_{512} & = & \text{HMAC-SHA-256}(\text{cv, 0x0000000000000200} \ | \ 1) \\
    ...\\
    T_{65535} & = & \text{HMAC-SHA-256}(\text{cv, 0x000000000000FFFF} \ | \ 1) \\
    ...\\
\end{array}
$$

##### Ratcheting the State
Finally, in the ratcheting step (lines 23 to 28), *cv* is updated with a hash computed over 9 bytes representing:
- the length of the output produced in the *squeeze* step
    - this is a 64 bit value (8 bytes in length), stored in the big-endian format
- a padding byte (set to 2)

The SHO then enters RATCHETED mode.

## Terms and Definitions

------------

### Pseudorandom Function

"Generally, a PRF family ${PRF(s, x) | s \in S}$ consists of
polynomial-time computable functions with an index (also called a _seed_) $s$ and input $x$, such that
when $s$ is randomly selected from $S$ and not known to observers, $PRF(s, x)$ is computationally
indistinguishable from a random function defined on the same domain with output to the same
range as $PRF(s, x)$."
([NIST SP 800-108r1-upd1](#xref-nist-sp-800-180r1-prf))

"A family of functions parameterized by a secret key, such that when the key is
unknown, the output upon evaluating an input (a message) is indistinguishable
from a random output of the specified length."
([NIST SP 800-224-ipd](#xref-nist-sp-800-224-ipd-hmac))

------------

## References

<a id="xref-trevor-sym-crypto-sho-proposal"></a>
Symmetric-crypto overhaul and stateful hashing.
<https://moderncrypto.org/mail-archive/noise/2018/001862.html>


<a id="xref-trevor-sho-proposal"></a>
Stateful Hash Object Proposal
<https://moderncrypto.org/mail-archive/noise/2018/001872.html>


<a id="xref-hmac-fips-198-1"></a>
The Keyed-Hash Message Authentication Code (HMAC). Section 4. HMAC SPECIFICATION.
<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf>


<a id="xref-nist-fips-202-xof"></a>
SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. August 2015.
<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>


<a id="xref-rfc4868-hmac-prf"></a>
RFC 4868 (section 2.1.2) approves using HMAC-SHA-256 as a PRF.
<https://datatracker.ietf.org/doc/html/rfc4868>


<a id="xref-serious-crypto-hmac-prf"></a>
<a id="xref-nist-sp-800-224-ipd-hmac"></a>
Serious Cryptography, Jean-Philippe Aumasson. Chapter 7 - Keyed Hashing (section on PRF Security).

- "In fact, many of the MACs deployed or standardized are also secure
PRFs and are often used as either. For example, TLS uses the
algorithm HMAC-SHA-256 both as a MAC and as a PRF."


<a id="xref-nist-sp-800-224-hmac-prf"></a>
NIST SP 800-224 ipd. Keyed-Hash Message Authentication Code (HMAC). Initial Public Draft. June 2024.
<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf>

- "he HMAC tag generation function is
a pseudorandom function (PRF) and may be used for cryptographic
purposes other than the classical example of message authentication
between a sender and a receiver"


<a id="xref-nist-sp-800-180r1-prf"></a>
NIST SP 800-108r1-upd1. Recommendation for Key Derivation Using Pseudorandom Functions.
Pseudorandom Function (PRF), section 3, page 3. August 2022.
<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf>
