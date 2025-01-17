
<head>
    <title>ShoHmacSha256 - A Concrete Implementation of ShoAPI</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/katex.min.css" integrity="sha384-sMefv1J1YJCHsg0mTa9YG+n/9KnJb9lGrJUUY5arg6bAL1qps/oZjmUwaHlX5Ugg" crossorigin="anonymous">
    <!-- The loading of KaTeX is deferred to speed up page rendering -->
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/katex.min.js" integrity="sha384-i9p+YmlwbK0lT9RcfgdAo/Cikui1KeFMeV/0Fwsu+rzgsCvas6oUptNOmo29C33p" crossorigin="anonymous"></script>
    <!-- To automatically render math in text elements, include the auto-render extension: -->
    <script defer src="https://cdn.jsdelivr.net/npm/katex@0.16.20/dist/contrib/auto-render.min.js" integrity="sha384-hCXGrW6PitJEwbkoStFjeJxv+fSOOQKOPbJxSfM6G5sWZjAyWhXiTIIAmQqnlLlh" crossorigin="anonymous"
        onload="renderMathInElement(document.body);"></script>
</head>

**ShoHmacSha256** is a Stateful Hash Object (SHO) that absorbs inputs incrementally, and produces arbitrary-length output when squeezed. It uses the HMAC-SHA-256 construction as a keyed hash function since it offers immunity against length-extension vulnerabilities of SHA-256. In the rest of this document, we will refer to the HMAC-SHA-256 instance as `hasher`.

SHO instances operate in one of the two states: ABSORBING and RATCHETED. While ABSORBING, `hasher` is updated with new input of arbitrary length. This is the "streaming" feature of SHO allowing it to absorb inputs at different stages of protocol execution. The current implementation does not impose any logical limit on the total length of inputs supplied to `hasher`. In Signal's use cases, ABSORBING ingests not more than a few hundred bytes.

In the RATCHETED state, `hasher`'s digest output is collected in a *chaining variable* `cv`, and the `hasher` is reset to its initial state. Recall that `hasher` is a HMAC-SHA-256 object, and it takes a *key* argument for its initialization. 

```rust
enum Mode {
    ABSORBING,
    RATCHETED,
}

pub struct ShoHmacSha256 {
    hasher: Hmac<Sha256>,
    cv: [u8; HASH_LEN],
    mode: Mode,
}

```


| Field Name | Description                                                 |
|------------|:-------------------------------------------------------------|
|`hasher`    | HMAC-SHA-256 object. <br>While instantiating, `cv` serves the MAC key. <br> A new instance is created only when SHO enters ABSORBING mode. <br> - `update()` accepts new input. <br> - `reset()` clears HMAC's state; leaves the MAC key unchanged.|
|`cv`        | *chaining variable* used to store `hasher` output when SHO is RATCHETED. <br> - stores HMAC-SHA-256 output, a 256-bit digest (32 bytes).| 
|`mode`      | SHO is either `ABSORBING` or `RATCHETED.` |


The *absorb* and *squeeze* functions on a SHO mimic the behavior of an extendable-output function (XOF). The *ratchet* function plays an important role in the lifecycle of SHO.


| Function Name | Description                                                 |
|---------------|:-------------------------------------------------------------|
| `absorb(`*input*`)`      | In the ABSORBING mode <br> - updates `hasher` input, and <br> - remains in ABSORBING mode.<br> <br> In RATCHETED mode, <br> - SHO gets a new `hasher` instantiated with `cv` as MAC key <br> - `hasher` is updated with the new input, and <br> - SHO enters ABSORBING mode.|
| `ratchet()`     | In the ABSORBING mode <br> - adds a padding zero byte to the input <br> - initializes `cv` with `hasher`'s 256-bit output (aka digest) <br> - resets `hasher` to its initial state, and <br> - enters RATCHETED mode. <br><br> In RATCHETED state, `ratchet()` is a no-op. |
| `squeeze(`*out_len*`)`     |  MUST be called only in the RATCHETED mode.|


A SHO can `absaorb()` new inputs in both . However, it can `squeeze` HMAC-SHA-256 outputs only in the RATCHETED state.


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

<a id="xref-rfc4868-hmac-prf"></a>
[1] RFC 4868 (section 2.1.2) approves using HMAC-SHA-256 as a PRF. <https://datatracker.ietf.org/doc/html/rfc4868>

<a id="xref-serious-crypto-hmac-prf"></a>
<a id="xref-nist-sp-800-224-ipd-hmac"></a>
[2] Serious Cryptography, Jean-Philippe Aumasson. Chapter 7 - Keyed Hashing (section on PRF Security).

        "In fact, many of the MACs deployed or standardized are also secure
        PRFs and are often used as either. For example, TLS uses the
        algorithm HMAC-SHA-256 both as a MAC and as a PRF."

<a id="xref-nist-sp-800-224-hmac-prf"></a>
[3] NIST SP 800-224 ipd. Keyed-Hash Message Authentication Code (HMAC). Initial Public Draft. June 2024.
   <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-224.ipd.pdf>

        "Other applications of HMAC. The HMAC tag generation function is
        a pseudorandom function (PRF) and may be used for cryptographic
        purposes other than the classical example of message authentication
        between a sender and a receiver"

<a id="xref-nist-sp-800-180r1-prf"></a>
[4] NIST SP 800-108r1-upd1. Recommendation for Key Derivation Using Pseudorandom Functions.
Pseudorandom Function (PRF), section 3, page 3. August 2022.
<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf>

