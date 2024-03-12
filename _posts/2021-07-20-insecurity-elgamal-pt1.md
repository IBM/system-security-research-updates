---
title: On the (in)security of ElGamal in OpenPGP - Part I
tags: cryptanalysis
authors: ["Luca De Feo",  "Bertram Poettering", "Alessandro Sorniotti"]
websites: ["https://defeo.lu/", "https://researcher.watson.ibm.com/researcher/view.php?person=zurich-POE", ""]
bibtex: |
    @INPROCEEDINGS{CCS2021ElGamal,
        author={De Feo, Luca and Poettering, Bertram and Sorniotti, Alessandro},
        booktitle={2021 ACM Conference on Computer and Communications Security (ACM CCS'21)},
        title={On the (in)security of ElGamal in OpenPGP},
        year={2021},
        volume={},
        number={},
        pages={},
        doi={}
    }
---

# On the (in)security of ElGamal in OpenPGP – Part I

In this two-parts post we dissect the paper ["On the (in)security of
ElGamal in OpenPGP"](https://eprint.iacr.org/2021/923), to be
presented at [ACM CCS'21](https://www.sigsac.org/ccs/CCS2021/index.html).

**TL;DR:** we found two types of vulnerabilities in the way OpenPGP
implementations handle ElGamal encryption.  We call the first type
*cross-configuration attacks*, where two otherwise secure PGP
implementations interact in an insecure way, leading to plaintext
recovery given a single ciphertext.  Luckily, the majority of PGP
users seems to be unaffected, nevertheless we found more than 2000
vulnerable public keys. The second type of vulnerability, to be
described in [Part II](../../09/06/insecurity-elgamal-pt2) of this
post, is a classical
*side-channel vulnerability* leading to secret key recovery, however
we argue there that the cross-configuration scenario makes it worse.

This write-up is intended for a technical audience who wants to understand 
the attacks without the clout of academic papers.  If you're simply 
interested in understanding whether you might be affected, jump straight to 
the [FAQ](#faq).


## 50 shades of ElGamal

In 1985, Taher ElGamal described the [first public key encryption
scheme based on discrete
logarithms](https://en.wikipedia.org/wiki/ElGamal_encryption). The
scheme represented an alternative to the patented RSA cryptosystem and
has since become a staple of any course on cryptography.  For such a
venerable, well known and, after all, simple scheme, you'd expect
little room for interpretation or doubt. And yet, do you think you
could fully specify all the details without making mistakes?

Ask two cryptographers to implement ElGamal, and chances are they will
make radically different choices in the way parameters are set up.  In
the best case, the two implementations will simply be incompatible.
In the worst case, they may be compatible, but...  Let's pretend we
are one of those cryptographers tasked with implementing ElGamal, and
let's go over the various choices in front of us.


### Prime modulus generation

We are talking about classic ElGamal, not variants based on elliptic
curves.  The first thing we need is a finite field with a hard
discrete logarithm problem.  Given the [current state of discrete log
cryptanalysis](https://eprint.iacr.org/2020/697), this means a 2048
bit prime at the very least.  We have two choices, already:

- **Some standardized prime**, such as those defined in [RFC
  2526](https://datatracker.ietf.org/doc/html/rfc3526);
- **Generate a prime** such that *p – 1* contains a *large enough* prime
  factor.

The first option is probably okay, but some users may be worried about
[backdoored primes](https://eprint.iacr.org/2016/961).  Another
argument against standard primes is that [it facilitates bulk
interception](https://weakdh.org/).  Although it would be possible in
principle to define trustworthy standard primes, as a matter of fact
they do not appear to be very popular for ElGamal.

The second option leads to more choices.  The goal is to generate a
prime *p* such that *p – 1* contains one large prime factor, call it
*q*.  Here is a list of the most sensible choices:

- Generate a **safe prime**, i.e., such that *q = (p – 1)/2* is prime;
- Generate a **DSA-like prime**, i.e., first choose *q*, then try
  *p = qf + 1* for random *f* until a prime is found.
- Generate a **Lim–Lee prime**[^1], i.e., one such that **all** prime
  factors of *(p – 1)/2* are large.

[^1]: Chae Hoon Lim, Pil Joong Lee. ["A key recovery attack on
    discrete log-based schemes using a prime order
    subgroup"](https://doi.org/10.1007/BFb0052240).
	
How large is "large" depends on the target security.  [NIST's FIPS-186
specification of
DSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
requires *q* to be 224 or 256 bits long, for a prime *p* of 2048 bits.
Of course, in safe primes *q* is as large as it can be.  Why, exactly,
*q* needs to be large is something we will come back to soon.


### Defining a group generator

The multiplicative group of integers modulo *p* contains several
subgroups: one for each divisor of *p – 1*.  Of these, the most
important one is the subgroup of order *q*.  To instantiate ElGamal we
need to specify a group generator, call it *g*, but again we have
at least two choices:

- A **generator of the full group** of invertible integers modulo *p*,
  which has order *p – 1*;
- A **generator of the prime order subgroup** of order *q*.

For efficiency, it may be interesting to find a small *g*.  In the
first case this is always possible: start from *g = 2*, and increase
until a generator of the full group is found, which should happen
pretty fast.  In the second case this is only possible for safe
primes: *g = 4* always works for safe primes, while for the two other kinds
of prime the subgroup of order *q* is unlikely to contain any small
elements other than *1*.


### Creating a key pair

The last step in key generation is to choose a secret exponent *x* and
form the public key *X = g<sup>x</sup> mod p*.  For mathematical
soundness, *x* should be a uniformly random integer between *1* and
the order of *g* (so, either *p – 1* or *q*), thus ensuring that the
public key is a uniformly random element of the group generated by
*g*.

In some cases it is possible to forego some mathematical rigor and
draw *x* from a smaller interval.  We shall call **"short exponents"**
secrets drawn this way.  This speeds up key generation and decryption,
however we shall see that it is a risky choice.  In no case shall *x*
be drawn from too small an interval, lest key recovery become feasible
via exhaustive search or [Pollard's Lambda
algorithm](https://en.wikipedia.org/wiki/Pollard%27s_kangaroo_algorithm).


### Encryption

To encrypt to a public key *X* a message *M*, assumed to be an integer
modulo *p*, draw a random "ephemeral" exponent *y*, compute
*Y = g<sup>y</sup> mod p*, and form the ciphertext
*(Y, M·X<sup>y</sup> mod p)*.

The exponent *y* can be sampled from the same intervals as the secret
key *x*.  Use of **short exponents** in this case is even riskier,
as we shall see.


### Decryption

Decryption is the only routine where every choice is pre-determined.
Upon receiving a ciphertext *(Y, Z)*, the original message is
recovered as *M = Z/Y<sup>x</sup> mod p*.

Note how each decryption involves an exponentiation by the secret
exponent *x*.  This will be important later when we discuss
side-channel attacks.


## ElGamal in PGP

OpenPGP is a very popular standard aimed to promote consumable, 
interoperable email security. The standard is defined in [RFC 
4880](https://datatracker.ietf.org/doc/html/rfc4880), which dictates 
message formats, operations and certain cryptographic aspects of the 
standard. According to section 9.1 of the RFC, ElGamal is the only public 
key encryption algorithm required for an implementation of the OpenPGP 
standard, RSA being only recommended:[^2]

> Implementations MUST implement DSA for signatures, and Elgamal for
> encryption.  Implementations SHOULD implement RSA keys.

[^2]: In practice, RSA appears to be the most popular encryption
    scheme in the OpenPGP ecosystem, and ElGamal is expected to be
    eventually deprecated.

So, what flavour of ElGamal do you think the OpenPGP standard
mandates?  The RFC is quite vague in that respect, only specifying the
public key format, and pointing to external references for algorithmic
details.  Unsurprisingly, implementations have freely interpreted the
standard, leading to several interoperable but diverging realizations.

To get a picture of what variants of ElGamal are implemented in the
OpenPGP ecosystem, we studied three of the most popular RFC 4880
compliant implementations: [GPG](https://gnupg.org/),
[Crypto++](https://cryptopp.com/), and the [Go standard
library](https://golang.org/).  Given that many lesser-known and
closed-source libraries also contribute to the ecosystem, we further
analyzed a dump of OpenPGP public keys obtained from an official key
server.


### OpenPGP key format

The only common denominator among all libraries is the key format,
which is thoroughly specified in RFC 4880 (Key ID `0x10`).  In
particular, an OpenPGP ElGamal subkey is a triple made of:

- the prime modulus *p*,
- the (sub)group generator *g*,
- the public key *g<sup>x</sup>*.

An ElGamal secret key consists of the subkey data above together with
the secret exponent *x*.

Without surprise, we found all libraries follow the standard in this
respect.


### GPG's Libgcrypt

[Libgcrypt](https://dev.gnupg.org/source/libgcrypt/) is the C library
doing the crypto heavy-lifting for GPG.  The roots of its ElGamal
implementation go as far back as 1997.  The relevant ways in
which Libgcrypt interprets the standard are as follows:

- It generates **Lim–Lee primes**, with the size *q* of the
  **smallest** odd factor of *p – 1* chosen as a function of the size of
  *p*.  In particular, when *p* is 2048 bits long, *q* is 225 bits
  long.
  
- It takes *g* to be the smallest integer *≥ 2* that **generates the
  full group** of invertible integers modulo *p*.
  
- It uses **short exponents** both for the secret key *x* and the
  ephemeral exponent *y*.  The size of *x* and *y* is [roughly *3/2*
  that of
  *q*](https://github.com/gpg/libgcrypt/blob/1a83d/cipher/elgamal.c#L312-L315),
  with *y* usually ending up being a few bits longer than *x*.  For
  *p* of 2048 bits, *x* has 340 bits and *y* has 344.

The algorithm to generate Lim–Lee primes was published in 1997, at a
time when people started being wary of attacks based on small
subgroups (more on them later), and when safe primes were still
considered to be too expensive to generate.  It is thus not so
surprising that Libgcrypt uses this relatively little-known prime
modulus generation.  The choice of using both small generators and
short exponents appears to have been dictated mainly by efficiency
considerations.


### Crypto++

Crypto++ has implemented ElGamal since version 1.0.  Source code
history only goes as far back as version 5.0, released in 2002, and by
that time the ElGamal implementation had already crystallized.  These
are the choices made by Crypto++ by default:

- The modulus *p* is a random **safe prime** *p = 2q + 1*.
- The generator *g* is the **smallest quadratic residue**, i.e., the
  smallest generator of the subgroup of order *q*, i.e., one of *2*,
  *3* or *4*.
- It uses **short exponents** both for *x* and *y*.  Both are sampled
  uniformly at random between *1* and *2<sup>n</sup>*, with [*n*
  depending on the size of
  *p*](https://github.com/weidai11/cryptopp/blob/434e3/nbtheory.cpp#L1045-L1050).
  When *p* is 2048 bits long, *n = 226*.


### Go standard library

Go only implements ElGamal encryption and decryption, but no key
generation, it is thus not fully RFC 4880 compliant, for better or for
worse. The only choice it has to make is the size of the ephemeral
exponent *y*, and it makes a pretty boring (*i.e.*, safe) one: **_y_
is sampled uniformly between *0* and _p – 1_**.


### OpenPGP public keys in the wild

Open source libraries only make a fraction of the OpenPGP ecosystem.
To get a richer picture, we obtained a public key dump from
<https://pgp.key-server.io/dump/>, dated Jan 15, 2021, containing
2,721,869 keys, out of which 835,144 had ElGamal subkeys.

It is impossible to know everything about how a library implements
ElGamal by only looking at the public keys it produces.  For example,
it is (hopefully) impossible to know what intervals *x* and *y* are
sampled from.  However, just by looking at *p* and *g*, some
information can still be gained.

Safe primes are easy to recognize, as it is sufficient to test whether
*(p – 1)/2* is prime.  For other primes, even a partial factorization of
*p – 1* can give a deal of information.  Note that it is in general
difficult to completely factor integers of 2048 bits.  We classified
primes into four categories:

- **Safe primes**.
- Non-safe primes for which we could not find any factor other than
  *2*.  These are likely to be **Lim–Lee primes**.
- Non-safe primes for which we could complete the factorization of
  *p – 1*.  These have unusually large *q* (within 99% the size of *p*),
  and for this reason we call them **quasi-safe primes**.
- Non-safe primes for which we could find some non-trivial factors,
  but we couldn't complete the factorization.  These are likely to
  have been generated **_à la_ DSA**.

An interesting finding is that the vast majority of public keys only
used **one of 16 "standard" primes**.  None of these primes appears to
have been defined in an RFC, and, while we could [track some of them
down](https://github.com/openvswitch/ovs/blob/master/lib/dhparams.c),
we're still unable to explain all of them.

A few more bribes of information can be gleaned from *g*.  First, we
ran a [quadratic residuosity
test](https://en.wikipedia.org/wiki/Quadratic_residue).  For safe
primes this tells everything: if *g* is a square it generates the
subgroup of order *q*, if not it generates the full group.  For other
primes, where we could find non-trivial factors, we ran [higher
residuosity
tests](https://en.wikipedia.org/wiki/Higher_residuosity_problem),
giving at least a hint to what group *g* generates.  For all
categories of primes, we found the full spectrum of possibilities:

- *g* generates the full group (or at least nothing contradicts this
  hypothesis),
- *g* generates the subgroup of order *q* (or at least nothing
  contradicts this hypothesis),
- none of the above.[^3]

[^3]: This last one is an unusual choice, which an implementation
    could end up doing if it was simply taking a fixed *g* or drawing
    it at random, without further checks.  Although unusual, it is
    unlikely to compromise security.


### Summary

That was pretty wild!  Let's try to systematize our findings via a
sort of ElGamal bingo card.  In the table below we classify both
libraries and keys found in the wild according to how they select
parameters *p*, *g*, *x* and *y*.  For some entries, we do not have
enough information to pin down the exact features, but we give our
best guess based on the data we have.


<style>
  #bingo { margin: auto; }
  #bingo td, #bingo th { text-align: center; }
  #bingo th { padding: 0 2px; }
  #bingo td:nth-child(11), #bingo td:last-child { text-align: right; }
  #bingo td:first-child { text-align: left; }
  #bingo td:nth-child(1),
  #bingo td:nth-child(5),
  #bingo td:nth-child(8),
  #bingo td:nth-child(10),
  #bingo tr:last-child th:nth-child(1),
  #bingo tr:last-child th:nth-child(5),
  #bingo tr:last-child th:nth-child(8),
  #bingo tr:last-child th:nth-child(10),
  #bingo tr:first-child th:not(:last-child) { border-right: solid thin; }
  #bingo { border-collapse: collapse; }
  #bingo tbody { border-top: solid thin; }
  #bingo .weak { color: red; font-weight: bold; }
</style>
<figure>
  <table id="bingo">
    <thead>
      <tr>
	<th></th>
	<th colspan="4">Prime category</th>
	<th colspan="3">Generated group size</th>
	<th colspan="2">Short exponents?</th>
	<th colspan="2">Quantity</th>
      </tr><tr>
	<th></th>
	<th>SP</th><th>LL</th><th>DSA</th><th>QS</th>
	<th><em>p – 1</em></th><th><em>q</em></th><th>other</th>
	<th>short <em>x</em></th><th>short <em>y</em></th>
	<th>total</th><th>s. 2016</th>
      </tr>
    </thead>
    <tbody>
      <tr>
	<td>Libgcrypt</td>
	<td></td><td>×</td><td></td><td></td>
	<td>×</td><td></td><td></td>
	<td>×</td><td>×</td>
	<td>–</td><td>–</td>
      </tr><tr>
	<td>Crypto++</td>
	<td>×</td><td></td><td></td><td></td>
	<td></td><td>×</td><td></td>
	<td>×</td><td>×</td>
	<td>–</td><td>–</td>
      </tr><tr>
	<td>Go</td>
	<td>–</td><td>–</td><td>–</td><td>–</td>
	<td>–</td><td>–</td><td>–</td>
	<td></td><td></td>
	<td>–</td><td>–</td>
      </tr>
    </tbody><tbody>
      <tr>
	<td>Safe prime I</td>
	<td>×</td><td></td><td></td><td></td>
	<td>×</td><td></td><td></td>
	<td>–</td><td>–</td>
	<td>472,518</td><td>783</td>
      </tr><tr>
	<td>Safe prime II</td>
	<td>×</td><td></td><td></td><td></td>
	<td></td><td>×</td><td></td>
	<td>–</td><td>–</td>
	<td>107,339</td><td>219</td>
      </tr><tr>
	<td>Lim–Lee I</td>
	<td></td><td>?</td><td></td><td></td>
	<td>?</td><td></td><td></td>
	<td>–</td><td>–</td>
	<td>211,271</td><td>6003</td>
      </tr><tr>
	<td>Lim–Lee II</td>
	<td></td><td>?</td><td></td><td></td>
	<td></td><td>?</td><td></td>
	<td>–</td><td>–</td>
	<td>47</td><td>24</td>
      </tr><tr>
	<td>Quasi-safe I</td>
	<td></td><td></td><td></td><td>×</td>
	<td>×</td><td></td><td></td>
	<td>–</td><td>–</td>
	<td>15,592</td><td>89</td>
      </tr><tr>
	<td>Quasi-safe II</td>
	<td></td><td></td><td></td><td>×</td>
	<td></td><td>×</td><td></td>
	<td>–</td><td>–</td>
	<td>20</td><td>3</td>
      </tr><tr>
	<td>Quasi-safe III</td>
	<td></td><td></td><td></td><td>×</td>
	<td></td><td></td><td>×</td>
	<td>–</td><td>–</td>
	<td>26,199</td><td>125</td>
      </tr><tr class="weak">
	<td>DSA-like I</td>
	<td></td><td></td><td>×</td><td></td>
	<td>?</td><td></td><td></td>
	<td>–</td><td>–</td>
	<td>828</td><td>810</td>
      </tr><tr>
	<td>DSA-like II</td>
	<td></td><td></td><td>×</td><td></td>
	<td></td><td>?</td><td></td>
	<td>–</td><td>–</td>
	<td>27</td><td>26</td>
      </tr><tr class="weak">
	<td>DSA-like III</td>
	<td></td><td></td><td>×</td><td></td>
	<td></td><td></td><td>×</td>
	<td>–</td><td>–</td>
	<td>1,304</td><td>1300</td>
      </tr>
    </tbody>
  </table>
  <caption><strong>Table 1:</strong> Features of ElGamal
  implementation found in libraries and public keys in the
  wild. The last two columns give the number of non-expired keys 
  in total and since 2016. <strong>Legend:</strong> × = has feature,
  ? = likely has feature, – = not applicable; SP = Safe prime, LL = Lim–Lee
  prime, DSA = DSA-like prime, QS = Quasi-safe prime.</caption>
</figure>


As messy as this may look, we haven't uncovered any specific issues so
far.  All the configuration in the table are sound, interoperable, and
safe... if taken in isolation!  Notice however the two lines in bold
red in the table: DSA-like I and III.  We shall now see why these two
"perfectly fine" types of keys are to be considered vulnerable in the
OpenPGP ecosystem.


## Computing discrete logarithms

The attacks we are going to describe require minimal understanding of
discrete logarithm computations.  In their simplest form, they are a
combination of the [Pohlig–Hellman
algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm)
for discrete logarithms in groups of composite order, and of Shanks'
[Baby-step giant-step
algorithm](https://en.wikipedia.org/wiki/Baby-step_giant-step).[^4]

[^4]: In the [CCS '21 paper](https://eprint.iacr.org/2021/923) we use
	the more specialized [Pollard
	Lambda](https://en.wikipedia.org/wiki/Pollard%27s_kangaroo_algorithm)
	and van Oorschot and Wiener's ["Parallel collision
	search"](https://doi.org/10.1007/PL00003816) algorithms to analyze
	the impact of our attacks.  These can save a considerable amount
	of memory compared to Baby-step giant-step, and parallelize
	better, but they are not essential to understanding the attacks.

As usual, we are given *g* and *h = g<sup>z</sup>*, and our goal is to
find *z*.  If *z* is drawn from a set *Z* of size *N*, Baby-step
giant-step finds it in roughly *N<sup>½</sup>* operations.  Its
strength is in requiring roughly the same amount of work no matter how
complicated the set *Z* is.  For example, we will use it in the [next
part](../../09/06/insecurity-elgamal-pt2) of this blog post to **find
*z* when some of its bits are known** via a side-channel.

Pohlig–Hellman will be useful in a slightly more involved scenario,
based on two key assumptions:

1. The order of the group generated by *g* contains some **small
   factors**,
2. *z* is a **short exponent**.

To fix ideas, let's say that *p* is a 2048 bits prime, that *(p – 1) =
2qf₀f₁f₂···* with *f<sub>i</sub>* "small", that *g* generates the full
group of invertible integers modulo *p*, and that *z* is *224* bits
long.  The bitlength of *z* is supposedly set large enough that none
of the known discrete log algorithms could find *z* in a feasible
amount of time.  In particular, Baby-step giant-step, with its
square-root complexity, would roughly take *2¹¹²* operations.

Without going into details, the Pohlig–Hellman algorithm reduces the
problem of computing discrete logs in the group of order *p – 1* to that
of computing discrete logs in each of the groups of order *2*, *q*,
*f₀*, *f₁*, etc.  Another way to look at it is that, by solving a
discrete logarithm in the subgroup of order *f<sub>i</sub>*,
Pohlig–Hellman finds *log₂(f<sub>i</sub>)* bits of *z*.[^5] If *z* were
2048 bits long, this wouldn't help us at all: after learning

*1 + log₂(f₀) + log₂(f₁) + ···*
{: style="text-align: center" }

bits we would still be left with *log₂(q)* unknown bits, which,
assuming *p* was constructed correctly, would still be too much.

[^5]: These are not *literally* the bits of *z* seen as an integer in
    base 2, but rather bits of information that are learned.

But we assumed that *z* is 224 bits long.  Then, by solving a discrete
log in each of the "small" subgroups, we are left with only

*u = 224 – 1 – log₂(f₀) – log₂(f₁) – ···*
{: style="text-align: center" }

unknown bits.  If this number is small enough, we can finish off the
computation with Baby-step giant-step, which takes roughly
*2<sup>u/2</sup>* operations.


## Cross-configuration attacks on OpenPGP

The algorithms above highlight some dangerous combinations of ElGamal
options.  Specifically, if after key generation:

1. *p – 1* contains small factors,
2. *g* generates the full group of invertible elements, or at least a
   subgroup with enough small factors in the order,
3. *x* is a short exponent,

then secret key recovery may be possible at a significantly lower cost
than intended.  This attack was already described in the 90s,[^6] so
it is no surprise that it does not apply to any of the libraries we
analyzed: indeed, both safe primes and Lim–Lee primes block it,
because their only small factor is *2*.[^7]

[^6]: Paul C. van Oorschot, Michael J. Wiener. ["On Diffie–Hellman Key
	Agreement with Short
	Exponents"](https://doi.org/10.1007/3-540-68339-9_29).
	
[^7]: We did not thoroughly test the harvested public keys for this
    weakness, but we dare hope that no library would make such a
    mistake today.

But the same idea can be applied to the ephemeral exponent *y*, and it
appears that this risk was overlooked in the OpenPGP ecosystem.  In
practice, this leads to plaintext recovery in a context where two
OpenPGP libraries, one sender and one receiver, interact, and:

1. The receiver's public key defines a prime such that **_p – 1_ contains
   small factors**;
2. The receiver's public key defines a generator *g* that generates the 
   full group of invertible elements, or at least a **subgroup with enough
   small factors in the order**;
3. The sender's library uses **short ephemeral exponents** *y*.

After computing the discrete log *y* as previously sketched,
recovering the plaintext message is an easy exercise.

Looking at [Table 1](#bingo) we see that two libraries, Libgcrypt and
Crypto++, can play the role of the sender, and that two types of
public keys, those named "DSA-like I" and "DSA-like III" can play the
role of the receiver in this attack.[^8] Let that sink in: **any
message sent by GPG or Crypto++ in the past 20-something years to one
of 2,132 registered public PGP keys had weak or nonexistent security!**
Fortunately, that's a quite small number of keys, but it accounts for
a good fraction of keys registered since 2016, and it is impossible to
say how many more unregistered keys may be at risk.

[^8]: The quasi-safe primes we observed do contain some small factors,
    but not enough to significantly affect security.

The feasibility of the attack depends on the number and size of the
small factors in the group order, as well as on the size of the short
exponents.  So, for example, Crypto++ encrypted messages are always
more vulnerable than GPG messages.  The [CCS '21
paper](https://eprint.iacr.org/2021/923) contains a careful analysis
of the computational effort expected for each of the affected keys.
As a proof of concept, we picked the weakest key we could find in the
key dump and we encrypted a message to it using Crypto++.  We were
able to **recover the plaintext in 2.5 hours on a single Intel
E5-2640 core**.


## Disclosure timeline and mitigations

* **Feb 24:** Notified Libgcrypt developers.
* **May 1:** Notified owners of affected public keys, with suggestion to
migrate to RSA or ECC encryption keys if possible.
* **May 24:**
[CVE-2021-33560](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33560)
assigned.
* **Jun 2:** Libgcrypt 1.8.8 [released](https://dev.gnupg.org/T5466),
fixes the vulnerability by sampling large ephemeral exponents *y* with
as many bits as *p*.
* **Jul 10:** Notified Crypto++ developers.
* **Jul 10:** [Paper](https://eprint.iacr.org/2021/923) online.

## FAQ

### What kind of vulnerability did you find?

In this first part we described a plaintext recovery attack on OpenPGP
ciphertexts encrypted with ElGamal.  Only certain combinations of
sender and receiver software are exposed.  We found that GPG (via
Libgcrypt) and Crypto++ are affected when acting as sender, while Go
is not.

We could not identify a specific library that would be affected when
acting as receiver, but an analysis of registered PGP public keys
shows that such libraries exist.  Any message encrypted to their keys
by one of the weak sender libraries is at risk of being exposed.

### What is the attack scenario?

This is a mathematical attack, thus it only requires interception of
ciphertexts.  For example, ciphertexts may be gathered through a data
breach, or by snooping on an insecure network.

### Is the attack practical?

Running times for the attack vary depending on the sender's software
and the receiver's public key.  They can go from a few hours on
commodity hardware to several CPU-years.

### How many people are affected?

The attack is a combination of a specific behaviour of the software on the 
sender side and certain mathematical properties of the public key of the 
recipient of the encrypted transmission. While the weakness appears to be 
very common on the sender side, we only found 2,132 registered public keys 
to be affected, among more than 2 millions.  It is likely that the 
vulnerability only affects a small proportion of all OpenPGP 
communications, however we cannot know how frequent the weakness is among 
unregistered public keys.

### Am I affected?

If you are a GPG (Libgcrypt) or Crypto++ user, the messages you send
or have sent may be at risk.  Update to the latest version of GPG.  A
fix for Crypto++ is upcoming.  If you are unsure which library you are
using, or if you want to check whether your software has been patched,
you can use the [tool we provide
here](https://github.com/IBM/PGP-client-checker-CVE-2021-33560).

However, public keys generated by GPG and Crypto++ are not at risk, so
you do not need to revoke your ElGamal keys if you know they were
generated by one of these software.

If you are unsure which software generated your ElGamal key, read on.

### How do I tell if my ElGamal key is affected?

It takes some computational resources to tell, with a reasonable
degree of confidence, whether a public key is affected or not. Thus we
are not able at the moment to provide a simple tool to test your keys.

If you cannot confirm that your key was safely generated, then we
recommend that you revoke it.  To generate a new key we recommend
either GPG or Crypto++, and/or to use a different algorithm altogether
(*e.g.*, RSA or ECC).

## Endnotes
