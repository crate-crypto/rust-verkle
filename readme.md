We want to store the commitment for the stem/leaf etc
We can do this by storing 33 byte keys and using the 33rd byte to link to extra data. This will make it less efficient to query
a stem for all of their leaves however, because it will also get the extra data for each leaf too

Maybe this is fine, since if we want to get a leaf, we probably want the extra data to prove it's membership

MILESTONE 1:

- Get a database working without caching


Note, it might be possible to identify a branch node as (depth, position) where depth \in [0,32] and position \in [0,256]


MILESTONE N:

- Adding graphing software would be cool
- - Try implementing the materialised path schema (changes the way the trie works!)
- We can also store the projective form of the point instead of the affine form
- Use serialise_unchecked instead of serialise_uncompressed. Careful for when we are importing a database from somewhere else
# Assumptions

- There will not be more than 2^64 internal/branch nodes. They are indexed using 8 bytes. The theoretical limit is 256^31 = 2^248. This limit can be changed at a later date by padding all of the previous 8 byte branch IDs.

- Above assumption is wrong now, we don't hash because neighboring nodes will have differing keys. Hash([0,0]) is not close to Hash([0,0,1]). But do we lose anything by having variable sized keys?

IDEA: For database we have two traits, one for BatchInsert, but with store(key, value) and a flush method 
Then another with just a single store_all() method.

We can then create a struct which takes the store_all method and creates a higher db from it

Quesiton:

Should the cache be populated everytime the program starts? - Depends on useage. If it's going to be used in something like a node, then yep, but if its going to be used as a cli tool, this might be a very expensive startup that would happen multiple times. How expensive would this be for a large trie?