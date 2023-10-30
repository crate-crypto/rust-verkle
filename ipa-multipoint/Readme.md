## IPA Multipoint

A polynomial commitment scheme for opening multiple polynomials at different points using the inner product argument.

This library uses the banderwagon prime group (https://hackmd.io/@6iQDuIePQjyYBqDChYw_jg/BJ2-L6Nzc) built on top of bandersnatch curve described in [https://eprint.iacr.org/2021/1152.pdf].


**Do not use in production.**

### Security 

- The CRS is not being generated in a secure manner. The relative DLOG is known. In actuality, we want to use a hash_to_group algorithm. Try and increment would be the easiest one to implement as we do not care about timing attacks.

- Even with this, the code has not been reviewed, so should not be used in production.

## Efficiency

- Parallelism is not being used
- We have not modified pippenger to take benefit of the GLV endomorphism

## API

- We should wrap the IPA proof in a poly commit struct, so that users cannot mix up the `a_vec` and `b_vec`, we will not commit to `b_vec` as a poly-commit

## Tentative benchmarks

Bandersnatch (old):

Machine : 2.4 GHz 8-Core Intel Core i9

- To verify the opening of a polynomial of degree 255 (256 points in lagrange basis): `11.92ms`

- To verify a multi-opening proof of 10,000 polynomials: `232.12ms`

- To verify a multi-opening proof of 20,000 polynomials: `405.87ms`

- To prove a multi-opening proof of 10,000 polynomials: `266.49ms`

- To prove a multi-opening proof of 20,000 polynomials: `422.94ms`



New benchmark on banderwagon subgroup: Apple M1 Pro 16GB RAM

- ipa - prove (256): `28.700 ms`

- ipa - verify (multi exp2 256): `2.1628 ms`

- ipa - verify (256): `20.818 ms`

- multipoint - verify (256)/1: `2.6983 ms`

- multipoint - verify (256)/1000: `8.5925 ms`

- multipoint - verify (256)/2000: `12.688 ms`

- multipoint - verify (256)/4000: `21.726 ms`

- multipoint - verify (256)/8000: `36.616 ms`

- multipoint - verify (256)/16000: `69.401 ms`

- multipoint - verify (256)/128000: `490.23 ms`

- multiproof - prove (256)/1: `33.231 ms`

- multiproof - prove (256)/1000: `47.764 ms`

- multiproof - prove (256)/2000: `56.670 ms`

- multiproof - prove (256)/4000: `74.597 ms`

- multiproof - prove (256)/8000: `114.39 ms`

- multiproof - prove (256)/16000: `189.94 ms`

- multiproof - prove (256)/128000: `1.2693 s`



*These benchmarks are tentative because on one hand, the machine being used may not be the what the average user uses, while on the other hand, we have not optimised the verifier algorithm to remove `bH` , the pippenger algorithm does not take into consideration GLV and we are not using rayon to parallelise.*
