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

FIPS 202 requires XOFs to satisfy the two properties (*emphasis ours*):

1. One-way: It is computationally infeasible to find *any input* that maps to *any new pre-specified* output.
2. Collision-resistant: It is computationally infeasible to find *any two distinct inputs* that map to *the same output*.


HMAC-SHA-256 is a keyed hash function as well as a cryptographically secure pseudorandom function (PRF). The output of HMAC-SHA-256 is a 256-bit value - a block of 32 bytes.

Because a XOF must produce arbitrary-length output, ShoHmacSha256 relies on HMAC-SHA-256 for entropy when producing an output longer than 256 bits. ShoHmacSha256 is used in parts of Signal protocol that use zero-knowledge proofs (zkp) to ensure privacy and secrecy of the users' identity. Our aim here is to understand the design of this cryptographic construction as well as its implementation.

## ShoApi {#xref-sho-trait-absorb-and-ratchet}
<a id="xref-sho-trait-absorb-and-ratchet"></a>
[ShoApi trait](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shoapi.rs>) is part of `poksho` library of [libsignal project](<https://github.com/signalapp/libsignal>). The project states that `poksho` stands for "proof-of-knowledge, stateful-hash-object", and is a collection of "*utilities for implementing zero-knowledge proofs (such as those used by `zkgroup`)*";

We present a slightly edited version of ShoApi below. We have added informal comments stating the general behavior of each function.

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
$$ \text{Listing 1. ShoApi} $$

It is obvious from the signatures of functions that *ShoApi* is designed to maintain mutable state.

This trait provides a default, generic implementation for *absorb_and_ratchet(input)* in terms of the abstract functions *absorb(input)* and *ratchet()*. We will see this function in action shortly.


## ShoHmacSha256  {#xref-shohamcsha256-struct}

[ShoHmacSha256](<https://github.com/signalapp/libsignal/blob/main/rust/poksho/src/shohmacsha256.rs#L24-L28>) provides a concrete implementation of ShoApi. It is so named because it is based on HMAC-SHA-256. In this section we will focus on type definitions and a way of reasoning about ShoHmacSha256. I personally learnt a great deal referring to the conversations in two related threads: [Stateful Hash Object Proposal](#xref-trevor-sho-proposal) and [Symmetric Crypto overhaul and stateful hashing](#xref-trevor-sym-crypto-sho-proposal).

<a id="xref-shohamcsha256-struct"></a>
```rust
 1 pub struct ShoHmacSha256 {
 2    hasher: Hmac<Sha256>,
 3    cv: [u8; HASH_LEN],
 4    mode: Mode,
 5 }

 1 enum Mode {
 2    ABSORBING,
 3    RATCHETED,
 4 }
```
$$ \text{Listing 2. ShoHmacSha256 Type Definition} $$

HASH_LEN is constant 32, representing the block length of SHA-25.

This construction is based on HMAC-SHA-256, a keyed-hashing function. Notice ShoHmacSha256 operates in two *modes*s: **ABSORBING** and **RATCHETED**. We will see in later sections that while ABSORBING, **hasher** simply ingests its inputs, and when RATCHETED, the **chaining variable** *cv* captures *hasher*'s (pseudorandom) output.

It is useful to recall that HMAC-SHA-256 *hasher* is a PRF.

Since there are only two modes of operation, we will denote RATCHETED and ABSORBING states using two simple terms:

$$
\begin{array}{l}
    {\small{\text{RATCHETED}}} \langle H_{k}^{[\,]}, \ r \rangle \\
    \\
    {\small{\text{ABSORBING}}} \langle H_{k}^{m}, \ r \rangle \\
\end{array}
$$

where the two crucial state variables appear inside matching angle brackets $\langle \, \rangle$.

ShoHmacSha256 state consists of two components:

- a HMAC-SHA-256 instance, *hasher*, represented by the letter $H$, and
- the randomness extracted so far, *cv*, represented by lower case letters $r$ and $k$.

In general, $H_k^{m}$ represents a *hasher* keyed with $k$, updated with an arbitrary length message $m$.

If we know $|m| = 0$ (that is, the length of $m$ is zero), we write $H_k^{[\,]}$.

We assume HMAC-SHA-256 exposes a streaming interface, meaning we can *update* $H$ incrementally so the
inputs are appended to an internal buffer. Note that the two sets of streaming commands
$$
    H_k^{[\,]}.update(``a").update(``bc").update(``xyz")\\
$$
and
$$
    H_k^{[\,]}.update(``ab").update(``cx").update(``y").update(``z")\\
$$
yield the same result
$$
    H_k^{``abcxyz"}
$$

This is all the machinery we need to describe the complete behavior of ShoHmacSha256!

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
$$ \text{Listing 3. ShoHmacSha256 - Example 1} $$

The `point` variable in the above code represents a 256-bit value.

The second example is from [zkcredential](<https://github.com/signalapp/libsignal/blob/main/rust/zkcredential/src/credentials.rs#L46-L48>):

```rust
 1 let mut sho =
 2     ShoHmacSha256::new(b"Signal_ZKCredential_CredentialPrivateKey_generate_20230410");
 3 sho.absorb_and_ratchet(&randomness);
```
$$ \text{Listing 4. ShoHmacSha256 - Example 2} $$

The `randomness` argument in this snippet is an array of 32 bytes (a 256-bit value).

The last sample is from [backup auth credential](<https://github.com/signalapp/libsignal/blob/main/rust/zkgroup/src/api/backups/auth_credential.rs#L140-L142>):

```rust
 1 let mut sho =
 2     poksho::ShoHmacSha256::new(b"20231003_Signal_BackupAuthCredentialRequest");
 3 sho.absorb_and_ratchet(uuid::Uuid::from(aci).as_bytes());
 4 sho.absorb_and_ratchet(&backup_key.0);
```
$$ \text{Listing 5. ShoHmacSha256 - Example 3} $$

Take note of the domain separator strings, on line 2 of all three snippets. The second and third use cases  (Listing 4 and 5, respectively) make an effort to choose distinct prefixes, emphasizing the need to distinguish different contexts of the application.

Observe also that the first example absorbs multiple inputs before ratcheting, while the second example absorbs and ratchets in one logical step. The third example shows *absorb_and_ratchet()* used in succession.

<a id="shohmacsha256-listing-6"></a>

## ShoHmacSha256 - Part 1 {#shohmacsha256-listing-6}

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
$$ \text{Listing 6. ShoHmacSha256 -} \textit{new, absorb, and ratchet} $$

The functions are deceptively simple. The creation of a new instance is defined in terms of *absorb* and *ratchet*. These functions behave differently depending upon the current state of SHO. It is very clear this code is carefully balancing a few invariants, preconditions and post-conditions over the state variables *mode*, *hasher* and *cv*.

To understand this better, and also to avoid re-narrating the source code, we introduce a simple notation to describe how the action unfolds linearly. This notation succinctly captures the state of a SHO making it easier to reason about its mutation over time.

### Typing ShoHmacSha256

We will informally define a few constructs to describe the state machine. The notation is simple and direct. The idea is to ensure that the state of a SHO is always well-typed.

SHO state is well-typed.

$$
\begin{array}{rll}
r &: \{0, 1\}^{256} & \text{256 bit pseudorandom value} \\
k &: \{0, 1\}^{256} & \text{256 bit key} \\
m &: \{0, 1\}^{*}  & \text{message of arbitrary length} \\
\langle H_{k}^{m}, \ r \rangle &: ({\normalsize{\text{HMAC-SHA-256}}_{\{0,1\}^{256}}^{\{0,1\}^*}}, \, \{0, 1\}^{256}) & \textit{hasher} \ \text{and} \ \textit{cv}\\
\end{array}
$$

These are equivalent to the type definition of ShoHmacSha256 in *libsignal*. We have already seen the Rust definition in an earlier [section](#xref-shohamcsha256-struct).

A SHO in RATCHETED state is denoted by the term

$$ {\small{\text{RATCHETED}}} \langle H_{k}^{[\,]}, \ r \rangle\\ $$

indicating that the *hasher* is keyed with $k$ and its input is empty. The SHO is said to be in *minimal* state for this reason.

It helps to remember that in RATCHETED state, *hasher*'s input is empty.

A SHO in ABSORBING state is denoted by writing

$$ {\small{\text{ABSORBING}}} \langle H_{k}^{m}, \ k \rangle\\ $$

indicating that the *hasher* is keyed with $k$, and has been updated with an arbitrary length input $m$ (for *message*). In the ABSORBING mode, *hasher*'s key is same as SHO's pseudorandom state (usually represented by $r$). While ABSORBING, $k$ is the extracted randomness that is also used to key HMAC-SHA-256.

It helps to remember that in ABSORBING state, SHO's $r$ is used to key *hasher*, and *hasher* is updated with an arbitrary length input.

### Describing ShoHmacSha256 Implementation
In this section we will use our notation to capture the semantics of three functions shown in Listing 6. In the following, in each step the part which is modified (within a term) is drawn enclosed in a box. We hope this helps in recognizing elements that change as the state machine evolves.

We will start by considering the two cases of *absorb* function. We will then turn our attention to *ratchet* and *new*.

#### ShoHmacSha256 *absorb* {#shohmacsha256-absorb}
Notice that *absorb* has a branching behavior depending on the current state of SHO. Let's first describe the case which we will call *Absorb After Ratchet*. We will then see *Update While Absorbing* case.

Recall that SHO in RATCHETED mode has empty input:

<a id="absorb-after-ratchet"></a>

##### Case 1.1. Absorb After Ratchet. {#absorb-after-ratchet}

$$
\begin{array}{c|l}
{\small{\text{RATCHETED}}} \langle H_{k}^{[\,]}, \ r \rangle & \text{lines 13-19}\\
{\begin{CD}
    @V{\small{absorb(l)}}VV \\
\end{CD}}\\
{\small\text{PRF\_UPDATE}} \langle H_{\boxed{{r}}}^{[\,]}, \ r \rangle & \text{lines 14-18}\\
{\begin{CD}
    @V{\small{(l)}}VV \\
\end{CD}}\\
{\small\text{ABSORB}} \langle H_{\small{r}}^{\boxed{l}}, \ r  \rangle & \text{line 19}\\
{\begin{CD}
    @V VV \\
\end{CD}}\\
{\small\text{ABSORBING}} \langle H_{{r}}^{l}, \ r  \rangle & \text{Final State}\\
\end{array}
$$

<a id="update-input-in-absorbing-mode"></a>

##### Case 1.2. Update Input In Absorbing Mode {#update-input-in-absorbing-mode}

$$
\begin{array}{c|l}
{\small{\text{ABSORBING}}} \langle H_{k}^{m}, \ k \rangle & \text{lines 13-19}\\
{\begin{CD}
    @V{\small{absorb(l)}}VV \\
\end{CD}}\\
{\small\text{UPDATE}} \langle H_{k}^{\boxed{\footnotesize\text{m||l}}}, k \rangle & \text{line 19}\\\
{\begin{CD}
    @V VV \\
\end{CD}}\\
{\small\text{ABSORBING}} \langle H_{{k}}^{m'}, \ k  \rangle & \text{Final State}\\
\end{array}
$$


<a id="shohmacsha256-ratchet"></a>

#### ShoHmacSha256 *ratchet* {#shohmacsha256-ratchet}
Recall when SHO is ratcheted, the randomness component $r$ is produced by hashing the preceding inputs to the *hasher*. And then, *hasher*' is reset meaning its input is cleared.

$$
\begin{array}{c|l}
{\small{\text{ABSORBING}}} \langle H_{k}^{m}, \ k \rangle\\
{\begin{CD}
    @V{\small{rachet}}VV \\
\end{CD}}\\
{\small\text{EXTRACT\_RANDOM}} \langle H_{k}^{m}, \ \boxed{\footnotesize\text{HMAC-SHA-256(k, m||0)}} \rangle & \text{lines 27-29}\\
{\begin{CD}
    @V VV \\
\end{CD}}\\
{\small\text{RATCHETED}} \langle H_{{k}}^{[\,]}, \ r  \rangle & \text{line 30; $hasher$ reset. Final State}\\
\end{array}
$$

#### Description 3 - Handcrafting ShoHmacSha256 Instance
Let's try to capture meaning of statements lines 3-8 in function *new* of Listing 6 above. This code handcrafts a new instance assigning default values to the state variables. In short, it puts SHO in RATCHETED state with *hasher* in minimal state, and *cv* (randomness value) 0.

$$
\begin{array}{l}
   {\small{\text{RATCHETED}}} \langle H_{k_0}^{[\,]}, \ r_0 \rangle \ \  where \  k_0 = 0^{32} \ and \ r_0  = 0^{32}\\
\end{array}
$$

Where $k_0$ is a string of 32 zeroes, and so is $r_0$.

Immediately after handcrafting the new instance, *new* calls *absorb* and *ratchet* (line 9) taking SHO to a well-defined state. Now that we have seen how these two functions behave, we should be able sequence [Case 1.1. Absorb After Ratchet](#absorb-after-ratchet) and [Ratchet](#shohmacsha256-ratchet). We will do this in the next section.


### Creation Semantics of ShoHmacSha256
We can now define the semantics of ShoHmacSha256 instance creation in terms of states and state modifications. The meaning of function *new* shown in lines 2-11 of Listing 6 is captured in the following description:

$$
\begin{array}{c|l}
{\small{\text{RATCHETED}}} \langle H_{k_0}^{[\,]}, \ r_0 \rangle & \text{lines 13-19}\\
{\begin{CD}
    @V{\small{absorb(l)}}VV \\
\end{CD}}\\
{\small\text{PRF\_UPDATE}} \langle H_{\boxed{{r_0}}}^{[\,]}, \ r_0 \rangle & \text{lines 14-18}\\
{\begin{CD}
    @V{\small{(l)}}VV \\
\end{CD}}\\
{\small\text{ABSORB}} \langle H_{\small{r_0}}^{\boxed{l}}, \ r_0  \rangle & \text{line 19}\\
{\begin{CD}
    @V VV \\
\end{CD}}\\
{\small\text{ABSORBING}} \langle H_{{r_0}}^{l}, \ r_0  \rangle & \text{post-absorb, before calling $ratchet$}\\
{\begin{CD}
    @V{\small{rachet}}VV \\
\end{CD}}\\
{\small\text{EXTRACT\_RANDOM}} \langle H_{k_0}^{l}, \ \boxed{\small\text{HMAC-SHA-256($k_0, \, l||0$)}} \rangle & \text{lines 27-29}\\
{\begin{CD}
    @V VV \\
\end{CD}}\\
{\small\text{RATCHETED}} \langle H_{{k_0}}^{[\,]}, \ r  \rangle & \text{line 30; $hasher$ reset. Final State}\\
\end{array}
$$


At this stage, it is fairly easy to transform the above description into a short snippet in Rust. We informally claim that the following snippet is behaviorally equivalent to ShoHmacSha256 instance creation code shown in Listing 6:

```rust
 1  let hs256 = Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
 2      .expect("HMAC accepts 256-bit keys");
 3  hs256.update(label); // absorb
 4  hs256.update(&[0x00]); // pad
 5
 8  let sho = {
 9      hasher: Hmac::<Sha256>::new_from_slice(&[0; HASH_LEN])
10            .expect("HMAC accepts 256-bit keys"),
11      cv: hs256.finalize().into_bytes().into(),
12      mode: Mode::RATCHETED,
13  };
```
$$ \text{Listing 7 - ShoHmacSha256 Object Creation in Short} $$


### Some Observations About the Design Choices
Notice in function *new(label)* on line 4 of [Listing 6](#shohmacsha256-listing-6), HMAC's *key* is a 256-bit block of zeroes. This is a common practice in many internet protocols. In TLS 1.3, for instance, while deriving the `Early Secret` for `client_early_traffic_secret` as shown in [RFC 8446, page 93](<https://datatracker.ietf.org/doc/html/rfc8446#section-7.1>), `HKDF-Extract`'s *salt* is a block of zeroes, which becomes HMAC's initial key material in [KHDF-Extract](https://datatracker.ietf.org/doc/html/rfc5869#section-2.2).

It is interesting that the domain separator string *label* is not used in initializing the *hasher*. The design conversations [here](https://moderncrypto.org/mail-archive/noise/2018/001892.html) and [here](https://moderncrypto.org/mail-archive/noise/2018/001894.html) reveal the thought process behind this construction.


## ShoHmacSha256 - Part 2 {#shohmacsha256-listing-8}

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
$$ \text{Listing 8 - Squeeze Outputs and Ratchet} $$

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

##### Symmetric-crypto overhaul and stateful hashing {#xref-trevor-sym-crypto-sho-proposal}

<a id="xref-trevor-sym-crypto-sho-proposal"></a>
<https://moderncrypto.org/mail-archive/noise/2018/001862.html>


##### Stateful Hash Object Proposal {#xref-trevor-sho-proposal}
<a id="xref-trevor-sho-proposal"></a>
<https://moderncrypto.org/mail-archive/noise/2018/001872.html>


<a id="xref-hmac-fips-198-1"></a>
The Keyed-Hash Message Authentication Code (HMAC). Section 4. HMAC SPECIFICATION.
<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf>


##### SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions. August 2015 {#xref-nist-fips-202-xof}
<a id="xref-nist-fips-202-xof"></a>
<https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf>


<a id="xref-rfc4868-hmac-prf"></a>
RFC 4868 (section 2.1.2) approves using HMAC-SHA-256 as a PRF.
<https://datatracker.ietf.org/doc/html/rfc4868>


##### Serious Cryptography, Jean-Philippe Aumasson. {#xref-nist-sp-800-224-ipd-hmac}
<a id="xref-serious-crypto-hmac-prf"></a>
<a id="xref-nist-sp-800-224-ipd-hmac"></a>
Chapter 7 - Keyed Hashing (section on PRF Security).

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


##### NIST SP 800-108r1-upd1 {#xref-nist-sp-800-180r1-prf}
<a id="xref-nist-sp-800-180r1-prf"></a>
Recommendation for Key Derivation Using Pseudorandom Functions.
Pseudorandom Function (PRF), section 3, page 3. August 2022.
<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf>
