
<head>
    <title>ShoHmacSha256 - A Concrete Implementation of ShoAPI</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/katex.min.css" integrity="sha384-sMefv1J1YJCHsg0mTa9YG+n/9KnJb9lGrJUUY5arg6bAL1qps/oZjmUwaHlX5Ugg" crossorigin="anonymous">
    <!-- The loading of KaTeX is deferred to speed up page rendering -->
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/katex.min.js" integrity="sha384-i9p+YmlwbK0lT9RcfgdAo/Cikui1KeFMeV/0Fwsu+rzgsCvas6oUptNOmo29C33p" crossorigin="anonymous"></script>
    <!-- To automatically render math in text elements, include the auto-render extension: -->
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/contrib/auto-render.min.js" integrity="sha384-hCXGrW6PitJEwbkoStFjeJxv+fSOOQKOPbJxSfM6G5sWZjAyWhXiTIIAmQqnlLlh" crossorigin="anonymous"
        onload="renderMathInElement(document.body);"></script>
</head>

**ShoHmacSha256** is a Stateful Hash Object (SHO) that absorbs inputs incrementally, and produces arbitrary-length output when squeezed. Signal protocol defines a simple API for SHO, called ShoApi. This API is designed to mimic the behavior of an extendable-output function (XOF). [FIPS 202](#xref-nist-fips-202-xof) defines an extendable-output function (XOF) as a function on bit strings (also called messages) in which the output can be extended to any desired length. A hash function, on the other hand, is a function on binary data (i.e., bit strings) for which the length of the output is fixed. SHA-256 is a hash function that produces 256-bit output or a block of 32 bytes.

FIPS 202 requires that XOFs satisfy the following two properties:

1. (One-way) It is computationally infeasible to find any input that maps to any new pre-specified output.
2. (Collision-resistant) It is computationally infeasible to find any two distinct inputs that map to the same output.

In Signal protocol, ShoHmacSha256 is a concrete implementation of ShoApi. ShoHmacSha256 uses HMAC-SHA-256 and a small set of creative techniques to create a secure XOF.

HMAC-SHA-256 construction is a keyed hash function as well as a pseudorandom function (PRF). A number of internet protocols and standards have accepted HMAC-SHA-256 as a collision resistant one-way hash function. Further, HMAC-SHA-256 offers immunity against length-extension vulnerabilities of SHA-256.

The output of HMAC-SHA-256 is a 256-bit value - a block of 32 bytes. A XOF, on the other hand, capable of producing arbitrary-length output. Therefore, ShoHmacSha256 employs HMAC-SHA-256 not only as a secure MAC but also as a PRF supplying entropy in a structured manner. It plays on a variation of the algorithmic structure of HKDF. We will understand this better when we dig a little deeper into the design and implementation details of AhoApi as implemented by ShoHmacSha256.

## ShoApi

[ShoApi trait](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shoapi.rs>) is part of `poksho` library of [libsignal project](<https://github.com/signalapp/libsignal>). The project states that `poksho` stands for "proof-of-knowledge, stateful-hash-object", and is a collection of "*utilities for implementing zero-knowledge proofs (such as those used by `zkgroup`)*";

We present a slightly formatted version of ShoApi below. We have added informal comments stating the general behavior of each function.

```rust
 1 pub trait ShoApi {
 2   // Create a SHO instance with 'label' domain-separator (customization label).
 3   // set hasher's initial state.
 4   fn new(label: &[u8]) -> Self
 5   where
 6       Self: Sized;
 7
 8   // Absorb 'input' incrementally; ingest streaming input.
 9   fn absorb(&mut self, input: &[u8]);
10
11    // Make the current state of this SHO a one-way hash function of preceding inputs.
12    // SHO may hash preceding (absorbed) inputs, and update the internal state
13    // with the extracted pseudorandom value.
14    // Reset hasher to its initial state.
15    fn ratchet(&mut self);
16
17    // absorb() and ratchet() in one logical step.
18    fn absorb_and_ratchet(&mut self, input: &[u8]) {
19        self.absorb(input);
20        self.ratchet();
21    }
22
23    // Return a byte sequence of length 'outlen'.
24    // In general, the output is a hash of the domain separator and absorbed inputs.
25    fn squeeze_and_ratchet(&mut self, outlen: usize) -> Vec<u8>;
26
27    // unimplemented; make this more generic later
28    // pub fn squeeze(&mut self, _outlen: usize) -> Vec<u8>;
29 }
```

It is clear from its definition that *ShoApi* is designed to maintain mutable state.

<a id="xref-sho-trait-absorb-and-ratchet"></a>
This trait provides a generic implementation for *absorb_and_ratchet(input)* in terms of the abstract functions *absorb(input)* followed by *ratchet()*.


## ShoHmacSha256

[ShoHmacSha256](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shohmacsha256.rs>) provides a concrete implementation of ShoApi. It is so named because it is constructed using HMAC-SHA-256. In this section we will focus on the type definitions and the creation semantics of ShoHmacSha256. It appears deceptively simple. I read and perused this code multiple times to really understand its design. I learnt a great deal referring to the initial design discussions which appeared in two different but highly-related threads:[Stateful Hash Object Proposal](#xref-trevor-sho-proposal) and [Symmetric Crypto overhaul and stateful hashing](#xref-trevor-sym-crypto-sho-proposal). The curious may notice these discussions were taking place in November 2018.

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

The SHO implementation is based on HMAC-SHA-256 hashing function. It is useful to recall that HMAC-SHA-256 is a pseudorandom function. The SHO instance operates in two modes: ABSORBING and RATCHETED. While ABSORBING, **hasher** simply ingests its inputs. When SHO is ratcheted, the **chaining variable** **cv** captures the MAC output of the hasher. We will learn more about ratcheting in the later sections.

## SHO use cases in *libsignal*

Let's go further and see how a SHO is instantiated and used. We will draw a few tiny snippets from within **libsignal** just to set the context.

Our first example snippet is from [poksho](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/statement.rs#L188-L195>):

```rust
 1 let mut sho = ShoHmacSha256::new(b"POKSHO_Ristretto_SHOHMACSHA256");
 2 sho.absorb(&self.to_bytes());
 3 for point in &all_points {
 4     sho.absorb(&point.compress().to_bytes());
 5 }
 6 sho.ratchet();
```

A `point` in the above snippet is a 256-bit value.

The second example is from [zkcredential](<https://github.com/signalapp/libsignal/blob/main/rust/zkcredential/src/credentials.rs#L46-L48>):

```rust
 1 let mut sho =
 2     ShoHmacSha256::new(b"Signal_ZKCredential_CredentialPrivateKey_generate_20230410");
 3 sho.absorb_and_ratchet(&randomness);
```

The argument `randomness` in this snippet is an array of 32 bytes (a 256-bit value, as in example 1).


And the last one from [backup auth credential](<https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/api/backups/auth_credential.rs#L140-L142>):

```rust
 1 let mut sho = poksho::ShoHmacSha256::new(b"20231003_Signal_BackupAuthCredentialRequest");
 2 sho.absorb_and_ratchet(uuid::Uuid::from(aci).as_bytes());
 3 sho.absorb_and_ratchet(&backup_key.0);
```

These three examples clearly demonstrate that domain separation is an important parameter while creating a ShoHmacSha256 instance. The second and third examples show the importance of not using common prefixes in domain separators. While the domain separator in the second example uses "Signal" as prefix, the in the third it is "20231003".

There is one more difference. The first example absorbs multiple inputs before ratcheting, while the second example absorbs and ratchets in one logical step. The third example shows 'absorb_and_ratchet()' used in succession. We shall recall these flavors when reviewing the implementation details.

## ShoHmacSha256 - Part 1

Let's get a little closer to the [definitions](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shosha256.rs#L31-L62>) of three functions we have seen so far:

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
15            self.hasher =
16                Hmac::<Sha256>::new_from_slice(&self.cv).expect("HMAC accepts 256-bit keys");
17            self.mode = Mode::ABSORBING;
18        }
19        self.hasher.update(input);
20    }
21
22    // called after absorb() only; streaming squeeze not yet supported
23    fn ratchet(&mut self) {
24        if let Mode::RATCHETED = self.mode {
25            return;
26        }
27        self.hasher.update(&[0x00]);
28        self.cv
29            .copy_from_slice(&self.hasher.clone().finalize().into_bytes());
30        self.hasher.reset();
31        self.mode = Mode::RATCHETED;
32    }
33 }

```

### Creation Semantics of ShoHmacSha256
The first thing to notice in function *new(label)* is that the *key* value passed to HMAC-SHA-256 is a block of zeroes. The domain separator *label* is not used in initializing the *hasher*. In my first reading of the code, this came as a surprise because I was expecting the customization label to be used as a seed for HMAC. However, after reading [answer 1](https://moderncrypto.org/mail-archive/noise/2018/001892.html) and [answer 2](https://moderncrypto.org/mail-archive/noise/2018/001894.html) I began to see the thought process behind this construction.

In TLS 1.3, HMAC is keyed with a string of zeroes during the key derivation process (aka key schedule). While deriving the `Early Secret` for `client_early_traffic_secret` or `binder_key` in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446#section-7.1)(section 7.1, page 93), the HKDF-Extract step explicitly receives a block of zeroes for its salt. This value, in turn, is passed as HMAC's initial key material within [KHDF-Extract](https://datatracker.ietf.org/doc/html/rfc5869#section-2.2).


The SHO instance (named *sho*) starts off in the RATCHETED mode setting *cv* to a block of zeroes. It is important to keep in mind that the size of *cv* equals the length of SHA-256 block (which is 32 bytes).

Immediately after crafting *sho*, construction proceeds t0 *absorb_and_ratchet* with *label* (the domain separator value). As we have already [seen](#xref-sho-trait-absorb-and-ratchet) in a previous section, this essentially absorbs the customization label and ratchets. Our immediate interest, therefore, is to understand what actually happens in these two functions.


#### Completing ShoHmacSha256 Construction with absorb_and_ratchet
A closer inspection of the call chain `new(label) --> absorb_and_ratchet(label)` reveals that the three functions can be readily inlined with simple renaming of function parameters. The result of such a source transformation is this inlined function:

```rust
 1 fn _rewrite_inline_ShoHmacSha256_new_absorb_and_ratchet_(label: &[u8]) {
 2    // new
 3    let mut sho = ShoHmacSha256 {
 4        hasher: Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
 5            .expect("HMAC accepts 256-bit keys"),
 6        cv: [0; HASH_LEN],
 7        mode: Mode::RATCHETED,
 8    };
 9
10    // sho.absorb_and_ratchet(label);
11    {
12        // absorb(label)
13        // rename identifiers: "self" as "sho", and "input" as "label".
14        if let Mode::RATCHETED = sho.mode {
15            sho.hasher =
16                Hmac::<Sha256>::new_from_slice(&sho.cv).expect("HMAC accepts 256-bit keys");
17            sho.mode = Mode::ABSORBING;
18        }
19        sho.hasher.update(label);
20
21        // ratchet()
22        // rename identifiers: "self" as "sho".
23        if let Mode::RATCHETED = sho.mode {
24             return sho; // code rewrite: return "sho"
25        }
26        sho.hasher.update(&[0x00]);
27        sho.cv
28            .copy_from_slice(&self.hasher.clone().finalize().into_bytes());
29        sho.hasher.reset();
30        sho.mode = Mode::RATCHETED;
31    }
32
33    sho
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

We can now summarize the state of *sho* like so:

```rust
 1    let hs256 = Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
 2        .expect("HMAC accepts 256-bit keys");
 3    hs256.update(label);
 4    hs256.update(0x00);
 5
 6    let prv = hs256.finalize().into_bytes();
 7
 8    let sho = {
 9        hasher: Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
10            .expect("HMAC accepts 256-bit keys"),
11        cv: hs256.finalize().into_bytes(),
12        mode: Mode::RATCHETED,
13    };
```




SHO instances operate in one of the two states: ABSORBING and RATCHETED. While ABSORBING, `hasher` is updated with new input of arbitrary length. This is the "streaming" feature of SHO allowing it to absorb inputs at different stages of protocol execution. The current implementation does not impose any logical limit on the total length of inputs supplied to `hasher`. In Signal's use cases, ABSORBING ingests not more than a few hundred bytes.


ShoHmacSha256 is equipped with a special operation named `ratchet()` that uses HMAC-SHA-256 as a PRF. It extracts 256-bits of randomness out of HMAC, and stores it in a *chaining variable* (`cv`, for short). This pseudorandom value, in turn, can be fed as a pseudorandom key into a KDF. This is the key insight (pun intended!) behind the `squeeze()` operation that feeds `cv` into a KDF, producing arbitrary length outputs.

The KDF, in our case, is not a straightforward instantiation of HKDF or some other standard KDF. In ShoHmacSha256, `squeeze()` produces blocks of 256-bits till the required output-length is reached. In each iteration, `squeeze()` instantiates a new HMAC-SHA-256 `hasher` with the pseudorandom key `cv`, uses the current block number as a 64-bit input, adds a padding byte (0x01), and produces the next block of output (which, in fact, is a 256-bit MAC).


In the RATCHETED state, `hasher`'s digest output is collected in a *chaining variable* `cv`, and the `hasher` is reset to its initial state. Recall that `hasher` is a HMAC-SHA-256 object, and it takes a *key* argument for its initialization.





The *absorb* and *squeeze* functions on a SHO mimic the behavior of an extendable-output function (XOF). The *ratchet* function plays an important role in the lifecycle of SHO.


| Function Name | Description                                                 |
|---------------|:-------------------------------------------------------------|
| `absorb(`*input*`)`      | In the ABSORBING mode <br> - updates `hasher` input, and <br> - remains in ABSORBING mode.<br> <br> In RATCHETED mode, <br> - SHO gets a new `hasher` instantiated with `cv` as MAC key <br> - `hasher` is updated with the new input, and <br> - SHO enters ABSORBING mode.|
| `ratchet()`     | In the ABSORBING mode <br> - adds a padding zero byte to the input <br> - initializes `cv` with `hasher`'s 256-bit output (aka digest) <br> - resets `hasher` to its initial state, and <br> - enters RATCHETED mode. <br><br> In RATCHETED state, `ratchet()` is a no-op. |
| `squeeze(`*out_len*`)`     |  MUST be called only in the RATCHETED mode.|


A SHO can `absaorb()` new inputs in both . However, it can `squeeze` HMAC-SHA-256 outputs only in the RATCHETED state.




| Field Name | Description                                                 |
|------------|:-------------------------------------------------------------|
|`hasher`    | HMAC-SHA-256 object. <br>While instantiating, `cv` serves the MAC key. <br> A new instance is created only when SHO enters ABSORBING mode. <br> - `update()` accepts new input. <br> - `reset()` clears HMAC's state; leaves the MAC key unchanged.|
|`cv`        | *chaining variable* used to store `hasher` output when SHO is RATCHETED. <br> - stores HMAC-SHA-256 output, a 256-bit digest (32 bytes).|
|`mode`      | SHO is either `ABSORBING` or `RATCHETED.` |


## Terms and Definitions

------------

### Pseudorandom Function

"Generally, a PRF family ${PRF(s, x) | s ∈ S}$ consists of
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


<a id="xref-nist-fips-202-xof"></a>
SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. August 2015.
<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>


<a id="xref-rfc4868-hmac-prf"></a>
RFC 4868 (section 2.1.2) approves using HMAC-SHA-256 as a PRF.
<https://datatracker.ietf.org/doc/html/rfc4868>


<a id="xref-serious-crypto-hmac-prf"></a>
<a id="xref-nist-sp-800-224-ipd-hmac"></a>
Serious Cryptography, Jean-Philippe Aumasson. Chapter 7 - Keyed Hashing (section on PRF Security).

        "In fact, many of the MACs deployed or standardized are also secure
        PRFs and are often used as either. For example, TLS uses the
        algorithm HMAC-SHA-256 both as a MAC and as a PRF."


<a id="xref-nist-sp-800-224-hmac-prf"></a>
NIST SP 800-224 ipd. Keyed-Hash Message Authentication Code (HMAC). Initial Public Draft. June 2024.
   <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf>

        "Other applications of HMAC. The HMAC tag generation function is
        a pseudorandom function (PRF) and may be used for cryptographic
        purposes other than the classical example of message authentication
        between a sender and a receiver"


<a id="xref-nist-sp-800-180r1-prf"></a>
NIST SP 800-108r1-upd1. Recommendation for Key Derivation Using Pseudorandom Functions.
Pseudorandom Function (PRF), section 3, page 3. August 2022.
<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf>
