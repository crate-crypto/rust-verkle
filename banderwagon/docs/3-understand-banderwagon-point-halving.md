# Halving a point on the bandersnatch curve

## Introduction

Considering the case of when $(\frac{a}{p})=(\frac{d}{p})=-1$ and $p \equiv \text{1 mod 4}$. This document derives the halving formula and its necessary conditions.

This is derived from [Bessalov's work](https://core.ac.uk/download/pdf/146445895.pdf). Some of his work has been translated to English, however it is unfortunately behind a paywall, so we link his monograph.

## What does it mean to halve a point?

For a twisted Edwards curve, the formula for doubling a point $(x, y)$ is:

$$2(x,y) = (\frac{2xy}{1+dx^2y^2},\frac{y^2-ax^2}{1-dx^2y^2}) = (X, Y) \text{  (0)}$$

This formula states that given a point $(x, y)$, we can produce $(X,Y)$ such that $2(x,y) = (x,y) +(x,y) = (X, Y)$

Halving a point is the opposite. ie given a point $(X, Y)$ we can compute a point $(x,y)$ such that $(X, Y) = 2(x,y)$.

We will see later on that there can be multiple points $(x_i,y_i)$ for a given $(X,Y)$ if we are not in a prime order group; *halving is analogous to taking the square root, while doubling is analogous to squaring a number. The square root can have multiple results, while squaring a number has one result.*

### Theorem 1: $(\frac{1-dX^2}{p}) = (\frac{1-aX^2}{p})$ when $X$ is on the curve

*Proof.*

The curve equation is given as: $ax^2 + y^2 = 1+dx^2y^2$

$$ \rightarrow 1-ax^2 = y^2 - dx^2y^2$$

$$ \rightarrow 1-ax^2 = y^2(1-dx^2)$$

Hence for a point on the curve, $1-dx^2$ and $1-ax^2$ are either both squares or both non-squares.

*Proof done.*

# Outline

We will first solve for the $X$ co-ordinate in equation 0. This will give us two quadratic equations that are only solvable when $1-aX^2$ and $1-dX^2$ are squares. This will be our first condition for a point to be halvable. By Theorem 1, either both equations are solvable or none of them are.

The quadratic equations will give us 8 solutions that are all on the curve, but not all will be solutions to the doubling formula. We will narrow our solutions to 4 when we notice that one point being a solution, necessarily means that two points cannot be a solution.

At this point, we can conclude that when $1-aX^2$ is a square, there are four solutions which when doubled will give a point with x co-ordinate $X$.

$1-aX^2$ is a necessary condition to find solutions, however it is not a sufficient one since the $Y$ co-ordinate has not been used to constrain the solutions and the sign of the $X$ co-ordinate is ignored.

$1-aX^2$ is nonetheless useful because if it is not a square, then the point is not halvable. The only points which are halvable on a non-cyclic twisted edwards curve of order $4p$, are points of order $p$. This check therefore can serve as a quick way to reject *some* points of order $2p$. This will be important for banderwagon.

One can substantiate the previous paragraph by noting that if $(X,Y)$ has order $p$ and thus passes the $1-aX^2$ check, then the points $(\pm X, \pm Y)$ will also pass the check and so with probability of a $\frac{1}{2}$ one can guess the point has order $p$ or $2p$.

The second condition for determining whether $(X,Y)$ is halvable can be derived by plugging in the solutions from the quadratic equations into the doubling formula's $Y$ co-ordinate in equation 0. If a point $(X,Y)$ passes both conditions, then it has order $p$.

## Methodology

### Solving for $X$

The doubling formula has two equations for the $x$ co-ordinate we will use these to create two quadratic equations.

The two equations are $\frac{2xy}{1+dx^2y^2}$ and $\frac{2xy}{ax^2 + y^2}$.

**Case1:**

Suppose:

$$\frac{2xy}{1+dx^2y^2} = X$$

$\text{let } k = xy$

$$\rightarrow X(1 + dk^2) = 2k $$

$$\rightarrow  (Xd)k^2 - 2k + X = 0 \text{  (1)}$$

Note that $X$ is a constant here, so we have a quadratic equation where the indeterminate variable is $k$, using the quadratic formula, we can write out the solutions as:

$$
k_{1,2}= \frac{2 \pm \sqrt{4 - 4dX^2}}{2dX}
$$
$$
\rightarrow \frac{1 \pm \sqrt{1 - dX^2}}{dX} \text{  (2)} $$

For the equation to be solvable $1-dX^2$ needs to be a square, ie $(\frac{1-dX^2}{p}) \neq -1$.

**Case2:**

Suppose:

$$\frac{2xy}{ax^2 + y^2} = X$$

$\text{let } t = \frac{y}{x}$

$$ \frac{2\frac{y}{x}}{a + (\frac{y}{x})^2} = X$$

$$ \rightarrow \frac{2t}{a+t^2} = X$$

$$\rightarrow Xt^2 - 2t + aX = 0 \text{  (3)}$$

Similarly, we have a quadratic equation in $t$, we write out the solutions as:

$$ t_{1,2} = \frac{2\pm\sqrt{4-4aX^2}}{2X}$$

$$ \rightarrow \frac{1\pm\sqrt{1-aX^2}}{X} \text{  (4)} $$

For the equation to be solvable $1-aX^2$ needs to be a square.

For both equations 2 and 4 to be simultaneously solvable, we need $1-aX^2$ and $1-dX^2$ to be non-squares. Theorem 1 shows that this is the case when $X$ is on the curve, so either both equations are solvable or both equations are not solvable.

*Note*

$$t_1t_2 =a$$ $$k_1k_2 = \frac{1}{d}$$

Since $(\frac{a}{p})=(\frac{d}{p})=-1$, then $t_1$ or $t_2$ must be a non-residue, similarly $k_1$ or $k_2$ must be a non-residue.
>Without loss of generality, we can assume that $t_1$ and $k_1$ are residues while $t_2$ and $k_2$ are non-residues.

### Summary so far

If we have a random point $(X,Y)$ and we want to find a point $(x,y)$ which when doubled gives $(X,Y)$. At the very least $1-aX^2$ and $1-dX^2$ needs to be a square for such a point $(x,y)$ to even exist.

## Solving for Y

From the doubling formula, we know that:

$$ \frac{y^2-ax^2}{1-dx^2y^2} = Y$$

Expressing the above equation in terms of $t_{1,2}$ and $k_{1,2}$ will give us the second condition needed to determine if a point $(X,Y)$ can be halvable.

$$ \frac{x^2(\frac{y^2}{x^2}-a)}{1-dx^2y^2} = Y$$

$$\rightarrow \frac{x^2(t_1^2-a)}{1-dk_1^2} = Y$$

$$\rightarrow (\frac{k_1}{t_1})\frac{t_1^2-a}{1-dk_1^2} = Y$$

Using equation 1 and 3, we know that $(Xd)k^2 - 2k + X = 0$ and $Xt^2 - 2t + aX = 0$ which implies that $2(1-\frac{k}{X}) = 1-dk^2$ and $t^2 -a = 2(\frac{t}{X} - a)$. Substituting:

$$\rightarrow (\frac{k_1}{t_1})\frac{2(\frac{t_1}{X} - a)}{2(1-\frac{k_1}{X})} = Y$$

$$\rightarrow (\frac{k_1}{t_1})\frac{\frac{t_1}{X} - a}{1-\frac{k_1}{X}} = Y$$

$$\rightarrow (\frac{k_1}{t_1})\frac{t_1 - aX}{X-k_1} = Y$$

$$\rightarrow k_1(t_1 - aX) = Yt_1(X-k_1)$$

The last equation is the second check needed to ensure that a point is halvable. ie given an $(X,Y)$ if $1-aX^2$ is a square, then we have solutions. If those solutions also pass the $k_1(t_1 - aX) = Yt_1(X-k_1)$ check, then they are solutions to the doubling formula.

## Finding solutions

After checking that a point $(X,Y)$ is halvable and finding the solutions $t_{1,2}, k_{1,2}$ to the quadratic equations. We find 8 potential solutions using the following two equations:

$$(x_1^2,y_1^2) = (t_1k_1,\frac{k_1}{t_1})$$

$$(x_2^2,y_2^2) = (t_2k_2,\frac{k_2}{t_2})$$

They will be of the form $(\pm x_1, \pm y_1)$, $(\pm x_2, \pm y_2)$ but note that not all of these solutions will be valid at the same time.

Assume that $(x_1,y_1)$ is valid, then $x_1y_1 = k_1$. This cannot simultaneously be true for $(-x_1, y_1), (x_1, -y_1)$. It can still be true for $(-x_1, -y_1)$. This is intuitive since, if $(x,y)$ is a solution then any other solution can only differ by order 2 points.

This implies that there are only four valid solutions $\{(x_1, y_1), (-x_1,-y_1), (x_2,y_2), (-x_2, -y_2)\}$.

These points all satisfy the following relation: $2(x_1,y_1)=2(-x_1,-y_1)=2(x_2,y_2)=2(-x_2,-y_2) = (X, Y)$ due to the fact that they are solutions to the doubling formula and pass both checks.

> **Remark**: To find all solutions we only need one solution. When examining the solutions, one shall see that $(x_1,y_1)$ and $(x_2,y_2)$ differ by $D_1$ or $D_2$

## Examining the Four solutions

Given that when $a$ and $d$ are non-squares and $p \equiv \text{ 1 mod 4}$, there are no points of order 4.

One can see that the small order subgroup of such an edwards curve will be $E[2] =\{(0,1), D_0, D_1, D_2\}$. $D_0$ is the rational point of order 2, $D_1, D_2$ are exceptional points of order 2. $E[2]$ is then isomorphic to the Klein-4 group or $\mathbb{Z_2} \times \mathbb{Z_2}$.

It follows that we can express the four solutions concretely as $P + E[2] = \{P, P+D_0, P+D_1, P+D_2 \}$.

>**Remark**: If $[2]P = (X,Y)$ then doubling any of the points in $P + E[2]$ gives $(X,Y$)

> **Note**: One only requires one solution in order to generate the others.
## What points are halvable?

*For a twisted edwards curve of order $4n$ where $n$ is an odd prime. We will show that if the small order subgroup is non-cyclic, then only the points of order $n$ are halvable.*

If the subgroup of size 4 is non-cyclic, then there are 3 points with order 2. The curve therefore contains $3(n-1)$ points with order $2n$ and $n-1$ points with order $n$.

One can see that there exists exactly 3 points with order $2n$ that when doubled produces a point $P$ of order $n$.  

Moreover, there exists a single point in the subgroup of size $n$ that when doubled, gives you $P$. This follows from the fact that halving in a prime order group is the same as multiplying by a half, and also that doubling is injective when the group has an odd order. See [here](https://math.stackexchange.com/questions/522273/if-a-group-g-has-odd-order-then-the-square-function-is-injective/522277#522277).

The above argument shows that there are always four points on the curve that will double to give a point of order $n$. One of the points will have order $n$ and the other $3$ will have order $2n$.

Now lets say we have the following $2T_1 = T_2$. If we now assume that $T_2$ has order $2n$, then $T_1$ must have order $4n$. This is not possible as we know that all points have at most order $2n$, showing that points with order $2n$ are not halvable in the group, only points of order $n$.  

## What does $(\frac{1-aX^2}{p})=1$ tell us about $(X,Y)$?

**Non-square**

If $1-aX^2$ is not a square, then $1-dX^2$ is not a square. This then means that there are no solutions for equations 2 and 4, and hence one cannot produce points which satisfy the doubling formula; $(X,Y)$ is not halvable. Moreover, when the subgroup of size 4 is non-cyclic, it implies that $(X,Y)$ does not have prime order $n$ by the previous section.

**Square**

If $1-aX^2$ is a square, then since $(\frac{1-aX^2}{p})=(\frac{1-dX^2}{p})$. This means that we can find solutions to the quadratics in equations 2 and 4. It does not mean that the point has order $n$.
Observe that if this check passes for a point of order $n$ $(X,Y)$, it also passes for $\{(-X,-Y), (-X,Y), (X, -Y)\}$ , so with probability of $\frac{1}{2}$, the point has order $n$.

Hence $(\frac{1-aX^2}{p})=1$ is true for $(\pm X,\pm Y)$ if $(X,Y)$ has prime order. It is easy to manually check that it is also true for the identity $(0,1)$ and the order 2 point $(0,-1)$. We can conclude that it is true for all points which do not differ by the points at infinity, and one is able to use it to reject points of the form $P+D_1$ or $P+D_2$

Assuming that $1-aX^2$ is a non-square for a point of order $n$, immediately arises a contradiction to the doubling formula for prime order groups.

One can also check $P+E[2]$ and note the effect that adding $D_1$ or $D_2$ has on a point $(x,y)$:

$$ P + E[2] = \{ P, P+ D_0, P+D_1, P+D_2\}$$

$$ P + E[2] = \{(x,y), (-x,-y), (\frac{1}{\sqrt{ad}}x^{-1}, \sqrt\frac{a}{d}y^{-1}),(-\frac{1}{\sqrt{ad}}x^{-1}, -\sqrt\frac{a}{d}y^{-1}) $$

## Relevance to banderwagon

The fact that $1-aX^2$ rejects the exceptional points and the fact that the elements in each set $\{(X,Y), (-X,-Y)\}$, $\{(-X,Y), (X,-Y)\}$ differ by only $D_0$ will allows us to create a quotient group of prime order.
