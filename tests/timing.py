import timeit
from itertools import count
import merkletools

LOOPS = 10

mt = merkletools.MerkleTools(hash_type="sha512")

timer = timeit.Timer("mt.make_tree()", globals=globals())

print("LEAVES,BUILD_TIME")
for i in count(1):
    mt.add_leaves([str(l) for l in range(i * 1000)], do_hash=True)
    t = timer.timeit(number=LOOPS)
    print(f"{len(mt.leaves)},{t / LOOPS}")
    mt.reset_tree()

