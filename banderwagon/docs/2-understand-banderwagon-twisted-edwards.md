# Understanding Banderwagon : Twisted Edwards Curves

## Introduction

Bandersnatch is an incomplete Twisted Edwards Curves, so here we learn the basics about Twisted Edwards curves; the group law, the special points and base points.

## Twisted Edwards Curve

A General Twisted Edwards Curve is given as:

$$ E_{a,c, d} : ax^2 + y^2 = c(1 + dx^2y^2)$$

- $x, y, a, d, c, \in F_p^*$
- $cd(1 - c^4d) \neq 0$
- p $\neq 2$

Without loss of generality, we usually set $c=1$ since any non-zero value for $c$ will induce an isomorphic curve over $F_p^*$. The equation one is accustomed to is:

$$ E_{a,d} : ax^2 + y^2 = 1 + dx^2y^2$$

- $x, y, a, d \in F_p^*$
- $d \neq 1$
- p $\neq 2$

**Remark**: When $a=1$ we call this an Edwards curve, even if $c \neq 1$.

## Group Law

We define the addition of two points $(x_1,y_1)$, $(x_2, y_2)$ to be:

$$ (x_1, y_1) + (x_2, y_2) = (\frac{x_1y_2+y_1x_2}{1+dx_1y_2y_1y_2},\frac{y_1y_2 - ax_1x_2}{1-dx_1x_2y_1y_2}) = (x_3,y_3)$$

We define the doubling of a point as:

$$2(x_1,y_1) = (\frac{2x_1y_1}{1+dx_1^2y_1^2},\frac{y_1^2-ax_1^2}{1-dx_1^2y_1^2}) = (x_2, y_2)$$

It is possible to replace the denominator in the doubling formula using the curve equation, note that this _will_ speed up the doubling of a point relative to using the point addition formula. However, this consequently can lead to side-channel attacks during scalar multiplication since a doubling can now be differentiated from a addition.

The fact that we can use one formula for both point addition and point doubling is known as _unification_.

(Reference: Wikipedia)

## Base points

Twisted Edwards curves have 4 base points, which can be found by setting $x=0$ and $y=0$

$x=0$:

Yields two points $(0,1), (0,-1)$. $(0,1)$ is the identity element according to the group law and $(0,-1)$ is a point of order two, which one can also be verified using the group law.

$y=0$:

Yields two points $(\sqrt\frac{1}{a}, 0), (-\sqrt\frac{1}{a}, 0)$. These rational points have order 4 and only exist if $a$ is a square.

- We now refer to $(0,-1)$ as $D_0$
- We refer to $(\sqrt\frac{1}{a}, 0)$ and $(-\sqrt\frac{1}{a}, 0)$ as $F_0$ and $F_1$ respectively

**Remark:** All edwards curves have at least 2 rational points of order 4, since $a=1$ is always a square.
**Remark:** All twisted edwards curves have an order 2 point $(0,-1)$.

## Special points

These points are referred to as points at infinity or exceptional points. Generally one wants to avoid these points during elliptic curve cryptography. It is analogous to avoiding $\frac{1}{0}$.

To find these points, we deduce from the curve equation:

$$x^2 = \frac{1-y^2}{a-dy^2}$$

$$ y^2 = \frac{1-ax^2}{1-dx^2}$$

- The first equation is undefined when $y=\pm\sqrt\frac{a}{d}$
- The second equation is undefined when $x=\pm\sqrt\frac{1}{d}$

This perfectly describes the points at infinity on the twisted edwards curve which cannot be represented using just $(x,y)$. It is customary to describe these points using what is known as the projective co-ordinates.

However, we ~~ab~~use the following the notation from Bessalov. Whenever we have $\frac{1}{0}$ we simply write $\infty$ to note that the co-ordinate is undefined.

We therefore describe these special points as $(\infty, \pm\sqrt\frac{a}{d})$, $(\pm\sqrt\frac{1}{d}, \infty)$

- The points $(\infty, \pm\sqrt\frac{a}{d})$ have order 2
- The points $(\pm\sqrt\frac{1}{d}, \infty)$ have order 4

This can be verified by using projective co-ordinates. _This is omitted for succintness_.

We now refer to $(\infty, \sqrt\frac{a}{d})$ and $(\infty, -\sqrt\frac{a}{d})$ as **$D_1$** and $D_2$ respectively.

We refer to $(\sqrt\frac{1}{d}, \infty)$ and $(-\sqrt\frac{1}{d}, \infty)$ as $F_2$ and $F_3$ respectively.

#### Theorem: The exceptional points only exist when either $(\frac{ad}{p}) = 1$ or $(\frac{d}{p}) = 1$

*Proof.*

*Case1:*

- When $(\frac{d}{p}) = 1$ this means that $d$ is a square
- If $d$ is a square, so is $\frac{1}{d}$
- This means that the x-coordinate for $F_2$ and $F_3$ are in the field $F_p$, hence the point exists.

*Case2:*

This follows the same logic as _Case1_ for $(\frac{ad}{p})=1$ and $D_1, D_2$

*Proof done.*

**Remark:** If these special points cannot occur, we refer to the curve as being _complete_.

### Cosets with special points

In this section, we explore the effects of adding a special point to some arbitrary point $P = (x,y)$. This can be verified using projective co-ordinates, we leave this out for succintness.

$$ (x,y) + D_1 = (\frac{1}{\sqrt{ad}}x^{-1}, \sqrt\frac{a}{d}y^{-1})$$
$$ (x,y) + D_2 = (-\frac{1}{\sqrt{ad}}x^{-1}, -\sqrt\frac{a}{d}y^{-1})$$
$$ (x,y) + F_2 =(\frac{1}{\sqrt{d}}y^{-1}, -\frac{1}{\sqrt{d}}x^{-1})$$
$$ (x,y) + F_3 =(-\frac{1}{\sqrt{d}}y^{-1}, \frac{1}{\sqrt{d}}x^{-1})$$

Observe, adding $D_1$ or $D_2$ to a point, inverts the original co-ordinates and multiplies each co-ordinate with a weighted value. Adding $F_2$ or $F_3$ swaps and inverts the co-ordinates, then multiplies each co-ordinate by a weighted value.

**Why is this important?**

When proving statements, it is fruitful to know what the effect these special points have on an arbitrary point. One example for those that are aware is the exceptional point when using a weistrass curve. The effect of adding the exceptional point on the weierstrass curve to an arbitrary point $(x,y)$ is that we get back $(x,y)$ and hence it serves as the identity point!

## Bandersnatch parameters

Bandersnatch has $(\frac{a}{p}) = (\frac{d}{p}) = -1$. This means that $D_1$ and $D_2$ are points which exist. We will only consider these points moving forward.
