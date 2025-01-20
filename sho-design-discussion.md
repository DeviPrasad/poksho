

https://moderncrypto.org/mail-archive/noise/2018/001881.html
Some post-quantum KEMs need multiple hash functions, i.e., they would
need such a StatefulHashObject to be domain-separated. Is the idea that
the caller needs to first absorb the domain-separation string then?

I'm not sure how you want to do domain separation in the Squeeze'
function. This wouldn't really be (input) domain separation but some
sort of output separation?

About instantiating Squeeze for SHA-2: Wouldn't the "standard" way to
build a XOF from SHA-2 be to use MGF1 [1]?

https://moderncrypto.org/mail-archive/noise/2018/001885.html
    If you want a longer domain-separation string (e.g. including the name
    "FrodoKEM" and other parameters) then you might choose to Ratchet()
    after absorbing the domain-separation string(s).  This would enable
    implementers to store the precalculated chaining variable, so they
    could skip re-calculating the Absorb(domain_separator)+Ratchet
    operations for every PQ operation.

    If that's the only reason to put the domain-separation string in a
    separate hash block, then I think Ratchet() supports it adequately?
    (and for SHA2, Ratchet would just zero-pad the block, like you want).


https://moderncrypto.org/mail-archive/noise/2018/001892.html
Dodis et al. [2] have pointed out some minor issues
with the H^2 structure under unkeyed settings, which I think would be
fixed if the input is padded with a 0-block beforehand, as done in the
HMAC-but-not-really-HMAC of [3, §3.5].

[1] https://doi.org/10.1007/978-3-642-04474-8_35
[2] https://cs.nyu.edu/~dodis/ps/h-of-h.pdf
[3] https://iacr.org/archive/crypto2005/36210424/36210424.pdf


https://moderncrypto.org/mail-archive/noise/2018/001894.html
I suppose Dodis's points are worth
considering and "indifferentiability" is good to have.  Hopefully
padding with a zero-block, per HMAC-but-not-really-HMAC from ([1],
more complete paper) would get us there?

Incorporating that plus replacing varints with simpler uint64 would
give us candidate constructions like below.

SHA2 / BLAKE2 (not xof, owf):
  Init()       : init(zero_block)
  Absorb(data) : update(data)
  Ratchet()    : update(pad_to_block); f()
  Squeeze(len) : h = finalize(); return HASH(h || uint64(0))  || HASH(h || uint64(1)) ...

SHAKE (xof, not owf):
  Absorb(data) : update(data)
  Ratchet()    : update(pad_to_block); f(); zeroize_rate()
  Squeeze(len) : return finalize(len)

BLAKE2X (xof, owf):
  Absorb(data) : update(data)
  Ratchet()    : update(pad_to_block); f();
  Squeeze(len) : finalize(len)


https://moderncrypto.org/mail-archive/noise/2018/001893.html
> Shouldn't Absorb and Squeeze know when to ratchet internally? I think
> this boils down to how much the caller knows (and has to know) about the
> details of the underlying hash function inside the SHO. To me it feels
> more clean to abstract those away, deal with padding, ratcheting, etc.
> inside the object.

If Absorb always ratcheted, then it wouldn't behave like a typical
streaming API where Absorb("abc") == Absorb("a) followed by
Absorb("bc").

I think that's a useful API, so it's good to give callers explicit
control on "Ratcheting", rather than have it happen on every Absorb.
Callers would Ratchet:
 -  to make sure that any "buffered" state is flushed through a 1-way
function for compromise resistance (so the buffered data gets mixed
with old entropy)
 - to compress the SHO state (clearing the buffer and the Sponge
"rate") to save space in RAM or ROM (e.g. if storing a
domain-separated SHO state - like a cSHAKE state after processing the
initial block - it would be better to Ratchet so you're storing a 32
or 64-byte Keccak capacity rather than a 200-byte full state).

For example, Noise would call Ratchet after sending each message, for
forward-security (a compromise won't find useful data in the SHO input
buffer), and to minimize the state that has to be kept around
in-between messages.


https://moderncrypto.org/mail-archive/noise/2018/001923.html

> I wouldn't expose Ratched() as a method on the SHO, but handle
> ratcheting internally.

Ratchet() is useful in a protocol like Noise which is going to use a
single SHO over some period of time, and wants to periodically ratchet
it for forward-secrecy, and perhaps to reduce the amount of state
stored between handling each message (since after Ratchet() the "rate"
would be erased, so doesn't need to be stored).

But Noise also wants to efficiently/incrementally call Absorb(), so we
don't want the cost of ratcheting for each Absorb().

So I think Ratchet() makes sense in the SHO API.  But for your case (a
PQ algorithm at a single point in time), you wouldn't need it.


https://moderncrypto.org/mail-archive/noise/2018/001950.html

>
> I understand the first reason, but not so much the second one. The SHO
> can easily keep track of how many more bytes can be absorbed before it
> has to ratchet; that's quite standard in incremental hash APIs.

I haven't been clear enough what Ratchet() does and why it would be
used.  Let me explain more, and see if that clarifies the reason to
expose it to the caller:

Ratchet() would do this:
 (1) if some input has been Absorb()'d but not yet processed via a
compression function (or permutation function for sponges), it would
pad out the current block, then apply the compression function.
 (2) it would apply any other processing to make the current state
noninvertible and minimum-sized (i.e. delete the sponge's rate).

So this accomplishes making the state a 1-way function of its inputs,
if there was sufficient absorbed entropy, and also making the state
minimum-sized.

The caller would use this when it wants to keep a SHO state around for
awhile and wants this state to be small, and to be noninvertible in
case it is compromised.

Only the caller would know when this is required - e.g., after sending
a Noise handshake message the caller would Ratchet(), since it might
wait for the response handshake message for a long time so it would
prefer to store a small and noninvertible SHO state.

But this decision needs to be made by the caller based on application
logic (after each Noise handshake message), rather than after any
fixed number of bytes.