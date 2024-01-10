# Dividing In Lagrange basis when one of the points is zero - Generalised

## Reference

The formulas were derived by reading the following academic article [here](https://people.maths.ox.ac.uk/trefethen/barycentric.pdf)

## Problem

In the multipoint protocol, we had a polynomial of the form:

$$
g(X) =  r^0 \frac{f_0(X) - y_0}{X-z_0} + r^1 \frac{f_1(X) - y_1}{X-z_1} + \ldots +r^{m-1} \frac{f_{m-1}(X) - y_{m-1}}{X-z_{m-1}}
$$

In our context, $z_i$ is an element in the domain, so naively we cannot compute this division in lagrange form. We also do not want to use monomial form, as we would need to interpolate our polynomials, which is exp  

Simplifying the problem:

We have $\frac{f(X)}{g(X)} = \frac{f(X)}{X - x_m} = \sum_{i=0}^{d-1} {f_i\frac{\mathcal{L_i(X)}}{X - x_m}}$

In what follows, we re-derive all of the necessary formulas that will allows us to divide by a linear polynomial that vanishes on the domain in lagrange basis, where the domain can be arbitrary.

## Lagrange polynomial

We briefly restate the formula for a lagrange polynomial:

$$
\mathcal{L_i}(X) = \prod_{j \neq i, j = 0}\frac{X -x_j}{x_i - x_j} 
$$

> The i'th lagrange polynomial evaluated at $x_i$ is 1 and 0 everywhere else **on the domain**

## First form of the barycentric interpolation formula

We introduce the polynomial $A(X) = (X - x_0)(X - x_1)...(X-x_n)$.

We also introduce the derivative of $A'(X) = \sum_{j=0}^{d-1}\prod_{i \neq j}(X - x_i)$ . 

> You can derive this yourself by generalising the product rule: https://en.wikipedia.org/wiki/Product_rule#Product_of_more_than_two_factors


In general this derivative does not have a succinct/sparse form. We do however have a succinct form if the domain is the roots of unity!

Now note that $A'(x_j) = \prod_{i=0,i \neq j}(x_j - x_i)$

> If we plug in $x_k$ into $A'(X)$ all the terms with $X - x_k$ will vanish, this is why the sum disappears into a single product.

We can use $A$ and $A'$ to re-define our lagrange polynomial as :

$$
\mathcal{L_i}(X) = \frac{A(X)}{A'(x_i) (X - x_i)}
$$

>Looking at the original lagrange formula, $A'(x_i)$ is the denominator and $\frac{A(X)}{X - x_i}$ is the numerator.

The first barycentric form for a polynomial $f(X)$ can now be defined as :


$$
f(X) = \sum_{i=0}^{d-1}{\frac{A(X)}{A'(x_i) (X - x_i)} f_i}
$$

#### Remarks

- $A(X)$ is not dependent on the values of $f_i$ and so can be brought out of the summation.
- $A'(X)$ is only dependent on the domain, so it can be precomputed, along with $A(X)$

## Re-defining the quotient

Note that our original problem was that the polynomial:

$$\sum_{i=0}^{d-1} {f_i\frac{\mathcal{L_i(X)}}{X - x_m}}$$

Had a $X - x_m$ term in the denominator. We will use the first barycentric form as a way to get rid of this.

First we rewrite $\frac{\mathcal{L_i(X)}}{X - x_m}$ using the first form:

$$
\frac{\mathcal{L_i}(X)}{X - x_m} = \frac{A(X)}{A'(x_i) (X - x_i)(X-x_m)}
$$

We then note that:

$$
A(X) = \mathcal{L_m}(X) \cdot A'(x_m) \cdot (X - x_m)
$$

> I just re-arranged the formula for the first form to equal $A(X)$ for $\mathcal{L_m}(X)$

We can hence plug this into our previous equation:

$$
\frac{\mathcal{L_i}(X)}{X - x_m} = \frac{\mathcal{L_m}(X) \cdot A'(x_m) \cdot (X - x_m)}{A'(x_i) (X - x_i)(X-x_m)}
$$

Simplifying since we have a $X - x_m$ in the numerator and denominator:

$$
\frac{\mathcal{L_i}(X)}{X - x_m} = \frac{A'(x_m) \cdot \mathcal{L_m}(X) }{A'(x_i)\cdot (X - x_i)}
$$

> Note that when the elements in the domain are roots of unity; $A'(x_k) = d(x^k)^{d-1} = dx^{-k}$ 
>
> The nice simplification here is due to two reasons: roots of unity form a cyclic group, and we can succinctly represent the d'th roots of unity in a sparse equation $X^d -1$ which is nice to derivate.

We have now re-defined $q(X)$ to not include $X-x_m$ !

We now summarise and state that:

$$
q(X) = \sum_{i=0}^{d-1} f_i \frac{\mathcal{L_i}(X)}{X - x_m} = f_i \frac{A'(x_m) \cdot \mathcal{L_m}(X) }{A'(x_i)\cdot (X - x_i)}
$$

## Explicit formulas for each case

### Computing $q_m$

When dealing with the point which vanishes on zero, the above formula becomes:

> Note: $\mathcal{L_m}(x_m) = 1$

$$
q_m = q(x_m) = \sum_{i=0}^{d-1}\frac{A'(x_m)}{A'(x_i)} \frac{f_i}{x_m - x_i} 
$$

### Computing $q_j$

For the case that the evaluation does not vanish on the domain, we can use the original formula.

For all $j \neq m$

$$
q_j = q(x_j) = \sum_{i=0}^{d-1} f_i \frac{\mathcal{L_i}(x_j)}{x_j - x_m}
$$

We note that the terms of the sum are zero, except for when $i=j$ from the definition of the lagrange polynomial , hence we can simplify this to be:

$$
   q_j = \frac{f_j}{x_j - x_m}
$$

## optimizations

If we use the formulas as shown above, $q_m$ will take $d$ steps due to the sum, and $q_j$ will take $d-1$ steps. We describe a way to reduce this complexity in the code.


### 1. Rewrite $q_m$ in terms of $q_j$

Note that if we multiply $q_m$ by $\frac{-1}{-1}$ we get:

$$
q_m = q(x_m) = -\sum_{i=0}^{d-1}\frac{A'(x_m)}{A'(x_i)} \frac{f_i}{x_i - x_m} 
$$

We can now substite in $q_i$

$$
q_m = q(x_m) = -\sum_{i=0}^{d-1}\frac{A'(x_m)}{A'(x_i)} q_i 
$$



### 2. Removing field inversions in $q_j$

Note that $q_j$ has a division which is many times more expensive than a field multiplication. We now show a way to precompute in such a way that we do not need to invert elements.

> With the roots of unity, we were able to use the fact that they formed a group.

Again note that:

$$
    q_j = \frac{f_j}{x_j - x_m}
$$

The expensive division occurs here $\frac{1}{x_j-x_m}$. In our particular case, we note that the domain is the discrete interval $[0,255]$ this means we need only to precompute $\frac{1}{x_i}$ for $x_i \in [-255, 255]$. This is 510 values, so we would store $510 * 32 = 16Kb$. If this is too much space, one could halve the storage by not storing the negated points.

**How would I lookup and store these values in practice?**

First we imagine that we have stored the values in an array as such:

$[\frac{1}{1}, \frac{1}{2}, \frac{1}{3}, \frac{1}{4}... \frac{1}{255},\frac{1}{-1},\frac{1}{-2},...\frac{1}{-255}]$

We first note that we can easily get from $\frac{1}{k}$ to $\frac{1}{-k}$ in the array by jumping forward 255 indices. Our strategy will be to find $\frac{1}{k}$ then jump to $\frac{1}{-k}$ if we need to.

**Example**

We want to compute $\frac{1}{0 - 255}$.

- Compute the $abs(0-255) = 255 = i$ 

> In practice, we can use an if statement to check whether 255 or 0 is larger, and subtract accordingly.

- Note that $\frac{1}{i}$ is at index $i-1$
- Since our original computation was $0 - 255$ which is negative, we need to get the element at index: $(i - 1) + 255$ where $i=255$.

### 3. Precompute $\frac{A'(x_m)}{A'(x_i)}$

> With the roots of unity, we did not need this optimization as $\frac{A'(x_m)}{A'(x_i)}$ equaled $\frac{\omega^i}{\omega^m}$ which was trivial to fetch from the domain due to the roots of unity forming a domain.

For our case, we will need to store precomputed values, if we want to efficiently compute $q_m$ in $O(d)$ steps, and to also avoid inversions.

The strategy is that, we precompute $A'(x_i)$ and $\frac{1}{A'(x_i)}$. Given that we have 256 points in the domain. This will cost us $256 * 2 * 32 \text{ bytes} = 16kB$.

**How would I lookup and store these values in practice?**

Similar to the previous optimization, we store $A'(x_i)$ in an array as such:

$[A'(0), A'(1), A'(2), A'(3)... A'(255),\frac{1}{A'(0)},\frac{1}{A'(1)},\frac{1}{A'(2)},...\frac{1}{A'(255)}]$


**Example**

We want to compute $\frac{A'(0)}{A'(5)}$

- We can fetch $A'(0)$ by looking up the element at index $0$ in the array.
- We can fetch $\frac{1}{A'(5)}$ by looking up the element at index 5, then jumping forward 256 positions.

In general:

- To fetch $A(x_i)$ we need to fetch the element at index $i$
- To fetch $\frac{1}{A(x_i)}$ we need to fetch the element at index $i + 256$

> Gotcha: You may produce an off by one error, by not realising that the second optimization skips ahead 255 points for negative values, while the third optimization skips ahead 256. This is because the second optimization omits the value $\frac{1}{0}$.

## Evaluate polynomial in evaluation form on a point outside of the domain

Suppose $z$ is a point outside of the domain.

$$
f(z) = \sum_{i=0}^{d-1}f_i\mathcal{L_i}(z) = \sum_{i=0}^{d-1}{\frac{A(z)}{A'(x_i) (z - x_i)} f_i} = A(z)\sum_{i=0}^{d-1}\frac{f_i}{A'(x_i)(z-x_i)}
$$

**Optimising:**
- We already store precomputations for $\frac{1}{A'(x_i)}$
- We should compute $z-x_i$ separately, then batch invert using the montgomery trick, so that we only pay for one inversion.