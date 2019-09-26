# pymerkletools
[![PyPI version](https://badge.fury.io/py/merkletools.svg)](https://badge.fury.io/py/merkletools) [![Build Status](https://travis-ci.org/Tierion/pymerkletools.svg?branch=master)](https://travis-ci.org/Tierion/pymerkletools)

This is a Python port of [merkle-tools](https://github.com/tierion/merkle-tools).

Tools for creating Merkle trees, generating merkle proofs, and verification of merkle proofs.

## Installation

```
pip install merkletools
```

## Validating

Use `validate_proff(proof, target_hash, merkle_root)` to validate a leaf node of a merkle tree.

```
def validate_proof(self, proof, target_hash, merkle_root):
    """
    Validate a leaf node proof
    
    :param proof:       A dictionary with sibling node hashes and their position
                        all the way to the Merkle root
    :param target_hash: Initial leaf node value
    :param merkle_root: Merkle root value
    :returns:           True if proof is valid, otherwise False
    """
```

Returns a boolean indicating whether or not the proof is valid and correctly connects the `target_hash` to the `merkle_root`. `proof` is a proof array as supplied by the `get_proof` method. The `target_hash` and `merkle_root` parameters must be a hex strings.

```python
proof = [
   { right: '09096dbc49b7909917e13b795ebf289ace50b870440f10424af8845fb7761ea5' },
   { right: 'ed2456914e48c1e17b7bd922177291ef8b7f553edf1b1f66b6fc1a076524b22f' },
   { left: 'eac53dde9661daf47a428efea28c81a021c06d64f98eeabbdcff442d992153a8' },
]
target_hash = '36e0fd847d927d68475f32a94efff30812ee3ce87c7752973f4dd7476aa2e97e'
merkle_root = 'b8b1f39aa2e3fc2dde37f3df04e829f514fb98369b522bfb35c663befa896766'

is_valid = mt.validate_proof(proof, targetHash, merkleRoot)
```

The proof process uses all the proof objects in the array to attempt to prove a relationship between the `target_hash` and the `merkle_root` values. The steps to validate a proof are:

1. Concatenate `target_hash` and the first hash in the proof array. The right or left designation specifies which side of the concatenation that the proof hash value should be on.
2. Hash the resulting value.
3. Concatenate the resulting hash with the next hash in the proof array, using the same left and right rules.
4. Hash that value and continue the process until you’ve gone through each item in the proof array.
5. The final hash value should equal the `merkle_root` value if the proof is valid, otherwise the proof is invalid.

## Common Usage

### Creating a tree and generating the proofs

```python
mt = MerkleTools()

mt.add_leaf("tierion", True)
mt.add_leaves(["bitcoin", "blockchain"], True)

mt.make_tree()

print("root:", mt.merkle_root)  # root: '765f15d171871b00034ee55e48ffdf76afbc44ed0bcff5c82f31351d333c2ed1'

print(mt.get_proof(1))  # [{left: '2da7240f6c88536be72abe9f04e454c6478ee29709fc3729ddfb942f804fbf08'},
                        #  {right: 'ef7797e13d3a75526946a3bcf00daec9fc9c9c4d51ddc7cc5df888f74dd434d1'}] 

print(mt.validate_proof(mt.get_proof(1), mt.leaves[1], mt.merkle_root)  # True
```

## Notes

### About tree generation

1. Internally, leaves are stored as a list of `bytes`. When the tree is built, it is generated by hashing together the `bytes` values. 
2. Lonely leaf nodes are promoted to the next level up, as depicted below.

                         ROOT=Hash(H+E)
                         /        \
                        /          \
                 H=Hash(F+G)        E
                 /       \           \
                /         \           \
         F=Hash(A+B)    G=Hash(C+D)    E
          /     \        /     \        \
         /       \      /       \        \
        A         B    C         D        E


### Development
This module uses Python's `hashlib` for hashing. Inside a `MerkleTools` object all
hashes are stored as Python `bytes`. This way hashes can be concatenated simply with `+` and the result
used as input for the hash function. But for
simplicity and easy to use `MerkleTools` methods expect that both input and outputs are hex
strings. We can convert from one type to the other using default Python string methods.
For example:
```python
hash = hashlib.sha256('a').digest()  # '\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc21\xb3\x9a#\xdcM\xa7\x86\xef\xf8\x14|Nr\xb9\x80w\x85\xaf\xeeH\xbb'
hex_string = hash.encode('hex')  # 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
back_to_hash = hex_string.decode('hex')  # '\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc21\xb3\x9a#\xdcM\xa7\x86\xef\xf8\x14|Nr\xb9\x80w\x85\xaf\xeeH\xbb'
```
