# Vector Commitment Scheme - Multipoint/Index

## Vector Commitment Scheme vs Polynomial Commitment Scheme

We may use these two terms interchangeably however they are not the same, a vector commitment scheme is strictly more powerful than a polynomial commitment scheme. One can take the dot product between two vectors and if one vector is of the form $<1, t, t^2, t^3,..., t^n>$ then one can realise the dot product as the evaluation of a polynomial in monomial basis at the point $t$.

Converting a vector to a polynomial can be done by either interpreting the elements in the vector as the coefficients for the polynomial or interpreting the elements as evaluations of the polynomial. Hence, we can state our schemes in terms of a polynomial commitment scheme and the translation would be done as mentioned above.

Similarly, the term multipoint will be used when referring to a polynomial commitment scheme and multi-index when referring to a vector commitment scheme. they mean the same thing, but just in different contexts.

## Introduction

A vector commitment scheme allows you to prove that an element $e$ in a vector $v$ is indeed at some specific index $i$, ie the fact that $v[i]=e$.

A multi-index vector commitment scheme, takes in a list of vectors $v_k$, a list of indices $i_k$ and a list of values $e_k$ and produces a proof that for all $k$ the following holds : $v_k[i_k]=e_k$.

One could simply call a single index vector commitment scheme $k$ times and produce $k$ proofs in order to simulate a multi-index vector commitment scheme. However we are interested in multi-index vector commitment schemes which are more efficient than doing this. The most common strategy to do this, is to call a function which aggregates all of the tuples $(v_k, i_k, e_k)$ into a single tuple and calls the single index vector commitment scheme on the aggregated tuples.

This is the strategy that our specific algorithm will also follow.

## Assumptions

The particular single index vector commitment scheme being used does not matter. We only require it to be homomorphic.

This means that commitments to polynomials can be summed, and the result will be a commitment to the sum of polynomials.

> KZG and IPA/bulletproofs both have this property. Hash based commitment schemes do not have this property.

# Multipoint scheme

## Singlepoint scheme

We describe a singlepoint polynomial scheme using the following algorithms:

- $\text{Commit}$
- $\text{Prove}$
- $\text{Verify}$

**Commit**

Input: A univariate polynomial, $f(X)$
Output: A commitment to $f(X)$ denoted $[f(X)]$ or $C$

**Prove**

Input: A polynomial $f(X)$, an evaluation point $z$ and a purported evaluated point $y=f(z)$
Output : A proof $\pi$ that the polynomial $f(X)$ gives a value of $y$ when evaluated at $z$

**Verify**

Input: A proof $\pi$, a commitment $C$ to a polynomial, an evaluation point $z$ and a purported evaluation $y$
Output: True if the committed polynomial in $C$ does indeed evaluate to $y$ on $z$

## Quotient styled commitment schemes

A quotient styled polynomial commitment scheme is one which uses the factor theorem, in order to provide opening proofs. The factor theorem, is well known, so the proof is omitted for brevity.

*Theorem 1:* Given a polynomial $p(X)$, if $p(t)=0$ then $(X-t)$ factors $p(X)$.

*Theorem 2: Given a polynomial $p(X)$, if $p(k) = r$, then there exists a polynomial $q(X) = \frac{p(X)-r}{X-k}$*

- If $p(k) = r$, then this implies that $p(k)-r = 0$
- Let $p_1(X) = p(X)-r$, this means we have $p_1(k)=0$
- Using Theorem 1, this implies that $(X-k)$ factors $p_1(X)$
- Which implies the following equation $p_1(X) = q(X)(X-k)$ for some $q(X)$
- Rearranging, we have $q(X)= \frac{p_1(X)}{X-k} = \frac{p(X)-r}{X-k}$

Observe that $q(X)$, the quotient, is only a polynomial, if $p(k) = r$. If it is not, then $q(X)$ will be a rational function. We then use the fact that a polynomial commitment scheme is only able to commit to polynomials, in order to provide soundness guarantees.

---

In what follows, we will describe the multipoint scheme using the singe point scheme as an opaque algorithm.

---  

## Statement

Given $m$ commitments $C_0 = [f_0(X)] ... C_{m-1} = [f_{m-1}(X)]$, we want to prove evaluations:

$$
    f_0(z_0) = y_0 \\\vdots \\f_{m-1}(z_{m-1}) = y_{m-1}
$$

where $z_i \in \{0,...,d-1\}$

**Observations**

- $C_0 = [f_0(X)]$ refers to a commitment to the univariate polynomial $f_0(X)$
- The evaluation points must be taken from the domain $[0,d)$, we can apply this restriction without loss of generality. Noting that $d$ will be the length of our vectors.
- It is possible to open the same polynomial at different points and different polynomials at the same points.
- It is also possible to open the same polynomial twice at the same point, it would only be wasting time.

## Proof

We will first detail two sub-optimal proofs for explanation purposes and optimise after. For the final proof, you can click [here](#proof---final)

---

We use $H(\cdot)$ to denote a hash function which can heuristically be realised as a random oracle.

---

1. Let $r \leftarrow H(C_0,...C_{m-1}, z_0, ..., z_{m-1}, y_0, ..., y_{m-1})$

$$
g(X) =  r^0 \frac{f_0(X) - y_0}{X-z_0} + r^1 \frac{f_1(X) - y_1}{X-z_1} + \ldots +r^{m-1} \frac{f_{m-1}(X) - y_{m-1}}{X-z_{m-1}}
$$

The prover starts off by committing to $g(X)$ using the commit function from the single point commitment scheme, we denote this by $D$ or $[g(X)]$.

The prover's job is to now convince the verifier that $D$ is a commitment to a polynomial $g(X)$. We do this by evaluating $g(X)$ at some random point $t$. If $g(X)$ is not a polynomial, then it is not possible to commit to it.

2. Let $t \leftarrow H(r,D)$

We split the evaluation of $g(X)$ into two parts $g_1(t)$ and $g_2(t)$, $g_2(t)$ can be computed by the verifier, while $g_1(t)$ cannot, because it involves random evaluations at the polynomials $f_i(X)$.

> - The verifier is able to compute the $g_2(t)$.
> - The prover will compute $g_1(t)$ and send a proof of it's correctness.

$$
g_1(t) = \sum_{i=0}^{m-1}{r^i \frac{f_i(t)}{t-z_i}}
$$

$$
g_2(t) = \sum_{i=0}^{m-1} {r^i \frac{y_i}{t-z_i}}
$$

We note that $g_1(X) = r^i \frac{f_i(X)}{X-z_i}$, however, we specify it as $r^i \frac{f_i(X)}{t-z_i}$ because the latter is also able to prove an opening for $g_1(t)$ **and** the verifier is able to compute the commitment for it.

Now we form two proofs using a single point polynomial commitment scheme:

- One for $g_1(X)$ at $t$. We call this $\pi$. This is computed using $\text{Prove}(g_1(X), t, g_1(t))$
- One for $g(X)$ at $t$. We call this $\rho$. This is computed using $\text{Prove}(g(X), t, g(t))$

The proof consists of $D, (\pi, g_1(t)), \rho$

## Verification

The Verifier ultimately wants to verify that $D$ is the commitment to the polynomial $g(x)$.

The verifier computes the challenges $r$ and $t$.

The verifier also computes $g_2(t)$, we mentioned above that they can do this by themselves.

### Computing $g(t)$

The verifier now needs to compute $g(t)$:

$g(t) = g_1(t) - g_2(t)$

- $g_1(t)$ was supplied in the proof.
- $g_2(t)$ can be computed by the verifier.

Hence the verifier can compute $g(t)$.

**Note however, the verifier cannot be sure that $g_1(t)$ is the correct computation by the prover ie they cannot be sure that it is indeed the evaluation of $g_1(X)$ at $t$. They need to build $[g_1(X)]$ themselves and verify it against $g_1(t)$**

#### Computing $[g_1(X)]$

Consider $g_1(X)$:

$$
g_1(X) = r^i \frac{f_i(X)}{t-z_i}
$$

$[g_1(X)]$ is therefore:

$$
[g_1(X)] = \frac{r_i}{t-z_i}C_i
$$

The verifier is able to compute this commitment themselves, and so is able to verify that $g_1(t)$ was computed correctly using the $\text{Verify}$ function .

The verifier now calls $\text{Verify}([g_1(X)], g_1(t), \pi)$ and aborts if the return value is false.

#### Correctness of $g(t)$

Since $g_1(t)$ was verified to be correct and $g_2(t)$ was computed by the verifier, $g(t)$ is correct.

## Verify $g(x)$ at $t$

The verifier now calls $\text{Verify}(D, g(t), \rho)$ and aborts if the return value is false.

## Aggregated Proof

In the above protocol, the prover needed to compute two proofs, one for $g(X)$ and another for $g_1(X)$. We now present a protocol which aggregates both proofs together.

---

3. Let $q \leftarrow H(t, [g_1(X)])$

> The prover no longer computes an IPA proof for $g_1(X)$ and $g(X)$ instead they combine both polynomials using a new random challenge $q$.

$g_3(X) = g_1(X) + q \cdot g(X)$

Now we form an single polynomial commitment scheme proof for $g_3(X)$ at $t$. Lets call this $\sigma$. This is computed using $\text{Prove}(g_3(X), t, g_3(t))$

The prover still computes $g_1(t)$.

The proof consists of $D, \sigma, g_1(t)$

## Aggregated Verification

In the previous step, the verifier called $\text{Verify}([g_1(X)], g_1(t), \pi)$. Instead they now delay this verification and instead compute the commitment to the aggregated polynomials and the evaluation of the aggregated polynomial at $t$:

- $[g_3(X)] = [g_1(X)] + q \cdot [g(X)]$
- $g_3(t) = g_1(t) + q \cdot g(t)$

The verifier now computes $\text{Verify}([g_3(X)], g_3(t), \sigma)$

> With overwhelming probability over $q$ this will only return true iff $[g_1(X)]$ and $[g(X)]$ opened at $t$ are $g_1(t)$ and $g(t)$ respectively.

## Opening $g_2(X)$

This optimization allows us to reduce the proof size by one element, by revisiting $g(X)$ and opening at $g_2(X)$. The gist is that if we open at $g_2(X)$ then we do not need to send any evaluations since the verifier can compute this themselves.  

In particular, we opened the polynomial : $g_3(X) = g_1(X) + q \cdot g(X)$

- First note that $g(X) = g_1(X) - g_2(X)$ which implies that $g_2(X) =g_1(X) - g(X)$
- It is argued that if the verifier can open $g_2(X)$ at $t$ using $D = [g(X)]$, then this implies that $g(X)$ can be correctly opened at $t$ using $[g(X)]$.

We now list out the full protocol using this optimization.

## Proof - Final

1. Let $r \leftarrow H(C_0,...C_{m-1}, z_0, ..., z_{m-1}, y_0, ..., y_{m-1})$

$$
g(X) =  r^0 \frac{f_0(X) - y_0}{X-z_0} + r^1 \frac{f_1(X) - y_1}{X-z_1} + \ldots +r^{m-1} \frac{f_{m-1}(X) - y_{m-1}}{X-z_{m-1}}
$$

The prover starts off by committing to $g(X)$ using the commit function from the single point commitment scheme, we denote this by $D$ or $[g(X)]$.

The prover's job is to now convince the verifier that $D$ is a commitment to a polynomial $g(X)$. We do this by indirectly evaluating $g(X)$ at some random point $t$. If $g(X)$ is a rational function, then it is not possible to commit to it as a polynomial, and consequently, it is not possible to prove that $g(t)= k$ using $D$.

2. Let $t \leftarrow H(r,D)$

$\text{Define } g_1(X):$

$$r^i \frac{f_i(X)}{t-z_i}$$

$\text{Define } g_2(X):$

$$r^i \frac{y_i}{X-z_i}$$

It is clear to see that $g(t) = g_1(t) - g_2(t)$.

$g_2(t)$ can be computed by the verifier, while $g_1(t)$ cannot, because it involves random evaluations at the polynomials $f_i(X)$.

> We note that the natural definition for $g_1(X)$ would be $r^i \frac{f_i(X)}{X-z_i}$, however, we specify it as $r^i \frac{f_i(X)}{t-z_i}$ because the latter is also able to prove an opening for $g_1(t)$ **and** the verifier is able to compute the commitment for it.

- The prover will compute an opening proof for $g_2(X)$. Correctness of $g_2(X)$ implies correctness for $g(X)$ since $g_2(t) = g_1(t) - g(t)$.

The prover forms an opening proof for $g_2(X)$ using a single point polynomial commitment scheme:

- We call this $\pi$. This is computed using $\text{Prove}(g_2(X), t, g_2(t))$

The proof consists of $(D, \pi)$

## Verification - Final

The Verifier ultimately wants to verify that $D$ is the commitment to the polynomial $g(x)$.

The verifier computes the challenges $r$, $t$ and $g_2(t)$

#### Computing $[g_1(X)]$

Consider $g_1(X)$:

$$
g_1(X) = r^i \frac{f_i(X)}{t-z_i}
$$

$[g_1(X)]$ is therefore:

$$
[g_1(X)] = \frac{r_i}{t-z_i}C_i
$$

Noting that the verifier is able to compute this value themselves.

### Verifying $g_2(t)$

Since : $g_2(t) = g_1(t) - g(t)$

The commitment to $g_2(X)$ with respects to $t$* is therefore:

$[g_2(X)] = [g_1(X)] - D$

> *We again note that $[g_1(X)]$ is only valid, if the point being evaluated is $t$ because $g_1(X)$ has already been partially evaluated at $t$.

Since the verifier computed $[g_1(X)]$ , if $D$ is indeed a commitment to $g(X)$, then $[g_1(X)] -D$ is a commitment to $g_2(X)$.

Now if $[g_2(X)]$ is a commitment to $g_2(X)$, then it will pass the following verification check $\text{Verify}([g_2(X)], t, g_2(t))$.

## Summary

- We describe the multipoint commitment scheme which we will use for verkle trees.
- We did not describe the exact single point commitment scheme being used, however we note that at the time of writing this document, the bulletpoofs variant described in section A.1 of [BCMS20](https://eprint.iacr.org/2020/499.pdf) is what has been implemented.
