# Understanding Banderwagon: High Level

## Why are we using Banderwagon?

Certainly one curve is less complex than two, and Ethereum already uses the bls12-381 curve, so why introduce another curve? Good question, I'm glad you have the mental fortitude to challenge me so early in the article.

**TLDR: It allows us to create efficient zero knowledge proofs in a snark.**

**Proof of execution**

A proof of execution is an protocol that allows you to prove that some function $f$ executed correctly with some input $x$ and produced some output $y$. Upon receiving the proof, one can quickly verify the claim $y=f(x)$ quicker than it takes to execute $f(x)$. If one decides that they want to hide the value of $x$, then one usually calls this a _zero knowledge proof_.

**Embedded curves**

Although the verification of such proof is usually quick no matter the size of $f$, creating such a proof can be very expensive. The problem becomes worse if $f$ involves elliptic curve arithmetic or bit-string hash functions like sha256. For elliptic curve arithmetic, we can alleviate this problem by choosing curves whose elliptic curve arithmetic is efficient inside of the proof of execution. These are known as _embedded curves_ and bandersnatch is one of those.

## Difference between bandersnatch and banderwagon

The astute reader may notice that I used the term bandersnatch in the last sentence, but the title says banderwagon. To explain the difference, lets build an analogy with a simpler example.

**`Uint32` vs `NonZeroUint32`**

A `uint32` is a data type that is able to store a number between $0$ and $2^{32}-1$, ie $[0, 2^{32})$

Now consider the data type `NonZeroUint32`. It is a `uint32` but it disallows the value zero. The way it does this is not important, it could be that upon creation, the number is checked to not be zero.

A `NonZeroUint32` is able to store a number between $1$ and $2^{32}-1$, ie $[1, 2^{32})$. One can say that a `NonZeroUint32` is a safety invariant over a `uint32` as its safe to use it if you need the number to never be zero.

**Bandersnatch vs Banderwagon**

Similarly, one can view banderwagon as a safety invariant over bandersnatch. There are points in the bandersnatch group that are disallowed in the banderwagon group. The way it does this, is what we will build up to in the following documents.

*Why do we want to avoid certain points with banderwagon?*

There are two types of points that one generally wants to avoid:

- _Special Points_: These are points that would lead one to divide by zero. Sometimes called points at infinity or exceptional points.
- _Low order points_: These are points which reduce the security of the group. Using a low order point as your Ethereum public key would allow an attacker to guess your private key in the time it takes to say, _there goes my life savings_. Moreover, replacing an otherwise good public key $P$ with a public key $P+S$ where $S$ lies in a small order subgroup, can allow an attacker to deduce information about your private key.

> **Note:** Banderwagon does not _avoid_ points of low order, instead they are _merged_ or quotiented out into points of prime of order.

**Credit**

The technique used to transform bandersnatch into banderwagon existed in the literature for almost a decade and was adapted to bandersnatch by Gottfried Herold.
