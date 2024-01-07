# Vector Commitment Scheme - High Level

_Familiarity with binary merkle trees is assumed._

## Commitment Scheme

Commitment schemes in general are at the heart of every scenario where you want to prove something to another person. Lets list two examples from our daily lives.

**Lottery**

Before you are able to see the winning results of a lottery, you must first commit to your choice of numbers. This commitment will allow you to prove that you did indeed choose these numbers _before_ seeing the results. This commitment is often referred to as a lottery ticket.

> We cannot trust people to be honest about their results, or more generously, we cannot trust people to attest to the truth; they could have bad memory.

If you trust everyone to tell the truth or if it is not advantageous for a rational actor to lie, then you _might_ be able to omit the commitment scheme. This is not usually the case, especially in a scenario where it may be impossible to find out the truth.

> Sometimes we cannot even assume that actors will behave rationally!

> There are certain features that a lottery ticket must have like not being able to edit it after the fact. Many of these features draw a parallel with vector commitment schemes.

**Registration and Login**

A lot of social applications require you to prove your digital identity to use them. There are two stages;

- **Registration**: This is where you put in your details such as your email address, name, password and phone number. You can think of this as a commitment to a particular identity.
- **Login**: This is where you use the email address and password from registration to prove that you are the same person. Ideally, only you know these login details.

> Without the registration phase, you would not be able to later prove your digital identity.

As you can see, commitment schemes are crucial where one needs to prove something after an event has happened. This analogy also carries over to the cryptographic settings we will consider.

## Why do we need a commitment scheme?

- For the lottery example, one could call it a **ticket commitment scheme**.
- For the registration example, one could call it an **identity commitment scheme**.
- For verkle trees and indeed merkle trees, we need a **vector commitment scheme**.

Analogously, this means that we need to commit to a vector and later attest to values in that vector.

> As a spoiler, with verkle/merkle trees, when one is tasked with proving that a particular value is in the tree, we can reduce this to many instances of proving that particular values are in a vector.

## Brief overview of a vector

Think of a vector as a list of items where the length of the vector and the position of each item is also a part of the definition.

**Example 1**

$v_1 =<a,b,c>$

$v_2 =<b,a,c>$

Here the vectors $v_1$ and $v_2$ are not equal because the first and second items in the vectors are not equal. This may seem obvious but it is not true for mathematical objects such as sets.

**Example 2**

$v_1 = <1,2,3>$

$v_2 =<1,2,3,3>$

Here the vectors are also not equal, because their lengths are not equal. Note also that as a set, they would be considered equal.

> We will later see that vector commitment schemes, must encode both of these properties (position of each item and length of the vector) when committing to a vector.

## Binary Merkle Tree as a vector commitment scheme

![](https://i.imgur.com/bnCVsy0.png)
*Figure1: Image of a binary merkle tree*

First bring your attention to $H_a, H_b$ in Figure 1. One can define some function $f_c$ which takes both of these values as inputs and transforms them into a single output value $H_{ab}$.

**Encoding the position**

We specify that $f_c(H_a,H_b)$ should not be equal to $f_c(H_b, H_a)$. This means that the function $f_c$ implicitly encodes the positions of its input values. In this case $H_{ab}$ conveys the fact that $H_a$ is first and $H_b$ is second.

**Encoding the length**

Another property of $f_c$ is that $f_c(H_a, H_b,k)$ should not equal $f_c(H_a, H_b)$, meaning that $f_c$ should also encode the number of inputs, which is conversely the length of the vector. (Even if $k$ has a value of $0$)

Elaborating, if there are two items as inputs, one should not get the same answer when there are three items. No matter what the third input is.

**Committing to a vector**

We now ask the reader to view $H_a$ and $H_b$ as two elements in a vector; ie $<H_a, H_b>$. The function $f_c$ allows us to commit to such a vector, encoding the length of the vector and the position of each element in the vector. In the above merkle tree, one can repeatedly use $f_c$ until we arrive at the top of the tree. The final output at the top is denoted as the _root_.

By induction, we can argue that the root is summary of all of the items below it. Whether the summary is succinct, depends on $f_c$.

> Popular choices for $f_c$ include the following hash functions: sha256, blake2s and keccak. But one could just as easily define it to be the concatentation of the input.

**Opening a value**

Say we are given the root $H_{abcdefgh}$ in Figure 1 and we want to show that $H_b$ is indeed a part of the tree that this root represents.

To show that $H_b$ is in the tree with root $H_{abcdefgh}$, we can do it by showing:

- $H_{abcd}$ is the first element in the vector $<H_{abcd}, H_{efgh}>$ and applying $f_c$ to this vector yields $H_{abcdefgh}$
- Then we can show that $H_{ab}$ is the first element in the vector $<H_{ab}, H_{cd}>$ and applying $f_c$ to the vector yields $H_{abcd}$
- Finally, we can show that $H_b$ is the second element in the vector $<H_a, H_b>$ and applying $f_c$ to the vector yields $H_{ab}$

We now define a new function $f_o$ to *show that an element is in a certain position in a vector and that when $f_c$ is applied to said vector, it yields an expected value*

$f_o$ takes four arguments:

- A commitment to a vector $C_v$. This is the output of $f_c$ on a vector.
- An index, $i$
- An element in some vector, $e_v$
- A proof $\pi$ attesting to the fact that $C_v$ is the commitment to $v$, and $e_v$ is the element at index $i$ of $v$.

$f_o$ returns true if for some vector $v$:

- $C_v$ is the commitment of $v$. i.e. $f_c(v) = C_v$
- The i'th element in $v$ is indeed $e_v$. i.e. $v[i] = e_v$

**Example**

Lets use $f_o$ to demonstrate us checking:

> $H_{abcd}$ is the first element in the vector $<H_{abcd}, H_{efgh}>$ and applying $f_c$ to this vector yields $H_{abcdefgh}$

$C_v= H_{abcdefgh}$
$i = 0$ (zero indicates the first element)
$e_v = H_{abcd}$

if $f_o(H_{abcdefgh}, 0, H_{abcd}, \pi)$ returns true, then we can be sure that $H_{abcdefgh}$ commits to some vector $v$ using $f_c$ and at the first index of that vector, we have the value $H_{abcd}$.

> We must trust that $H_{abcdefgh}$ was computed correctly, ie it corresponds to the tree in question. This is outside the scope of verkle/merkle trees in general and is usually handled by some higher level protocol.

**What is $\pi$ ?**

For a binary merkle tree, $\pi$ would be $H_{efgh}$. Now given $H_{abcd}$ and $\pi$, we can apply $f_c$ to check that $C_v = f_c(H_{abcd}, \pi)$ . This also allows us to check that $H_{abcd}$ is the first element in the vector.

**Proof cost For Binary Merkle Tree**

For a binary merkle tree, our vectors have size $2$ and so $\pi$ only has to contain 1 extra element to show $C_v = f_c(a, \pi)$. If we had a hexary merkle tree, where our vector had 16 elements, $\pi$ would need to contain 15 elements. Hence the proof grows in proportion to the vector sizes that we are using for merkle trees.

Even more disparaging, is that fact that there is not just one $\pi$. In our case there is actually 3 $\pi$ to show $H_b$ is in the tree. The overall proof size thus also grows, with the amount of vectors/levels/depths.

In general, we can compute the overall proof size by first defining the number of items in the tree, this is also known as the tree width $t_w$, we then define the size of our vectors, this is sometimes referred to as the node width $n_w$: We can compute the proof size with : $$log_{n_w}(t_w) * (n_w) = \text{depth} * n_w$$

## Verkle Tree Improvements

The problem with $f_c$ being a hash function like sha256 in the case of a merkle tree is that in order to attest to a single value that was hashed, we need to reveal everything in the hash. The main reason being that these functions by design do not preserve the structure of the input. For example, $\text{sha256(a)}$ + $\text{sha256(b)}$ != $\text{sha256(a + b)}$.

Fortunately, we only require a property known as collision resistance and there are many other vector commitment schemes in the literature which are more efficient and do not require all values for the opening. Depending on the one you choose, there are indeed different trade offs to consider.

Some trade offs to consider are:

- Proof creation time; How long it takes to make $\pi$
- Proof verification time; How long it takes to verify $\pi$

Moreover, with some of the schemes in the wider literature, it is possible to aggregate many proofs together so one only needs to verify a single proof $\pi$. With this in mind, it may be unsurprising that with verkle trees, the node width/vector size has increased substantially, since the proof size in the chosen scheme does not grow linearly with the node width.

## Summary

- Merkle trees use a vector commitment scheme which is really inefficient.
- Verkle trees use a commitment scheme which has better efficiency for proof size and allows one to minimise the proof size using aggregation.
- Verkle trees also increase the node width, which decreases the depth of the tree.
