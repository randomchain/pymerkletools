import hashlib


class MerkleTools(object):
    def __init__(self, hash_type="sha256"):
        self._hash_type = hash_type.lower()
        if self._hash_type in hashlib.algorithms_available:
            self.hash_function = getattr(hashlib, self._hash_type)
        else:
            raise Exception('`hash_type` {} nor supported'.format(self._hash_type))

        self.reset_tree()

    def reset_tree(self):
        self.leaves = []
        self.levels = None
        self.is_ready = False

    def add_leaves(self, values, do_hash=False):
        """
        Add iterable of leaves
        """
        for v in values:
            self.add_leaf(v, do_hash=do_hash)

    def add_leaf(self, value, do_hash=False):
        """
        Add leaf to merkle tree

        :param value: Hash of data, or actual data
            can be bytes or string, but will always be converted to bytes
        :param do_hash: Flag specifying if the value should be hashed before adding leaf
        """
        self.is_ready = False
        if not isinstance(value, bytes):
            value = value.encode('utf-8')
        if do_hash:
            value = self.hash_function(value).digest()
        self.leaves.append(value)

    def _calculate_next_level(self):
        solo_leave = None
        N = len(self.levels[0])  # number of leaves on the level
        if N % 2 == 1:  # if odd number of leaves on the level
            solo_leave = self.levels[0][-1]
            N -= 1

        new_level = []
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(self.hash_function(l+r).digest())
        if solo_leave is not None:
            new_level.append(solo_leave)
        self.levels = [new_level, ] + self.levels  # prepend new level

    def make_tree(self):
        self.is_ready = False
        if self.leaves:
            self.levels = [self.leaves, ]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
        self.is_ready = True

    @property
    def merkle_root(self):
        if self.is_ready:
            if self.levels is not None:
                return self.levels[0][0]
            else:
                return None
        else:
            return None

    def get_proof(self, index):
        if self.levels is None:
            return None
        elif not self.is_ready or index > len(self.leaves)-1 or index < 0:
            return None
        else:
            proof = []
            for x in range(len(self.levels) - 1, 0, -1):
                level_len = len(self.levels[x])
                if (index == level_len - 1) and (level_len % 2 == 1):  # skip if this is an odd end node
                    index = int(index / 2.)
                    continue
                is_right_node = index % 2
                sibling_index = index - 1 if is_right_node else index + 1
                sibling_pos = "left" if is_right_node else "right"
                sibling_value = self.levels[x][sibling_index]
                proof.append({sibling_pos: sibling_value})
                index = int(index / 2.)
            return proof

    def validate_proof(self, proof, target_hash, merkle_root):
        if isinstance(merkle_root, str):
            merkle_root = bytes.fromhex(merkle_root)
        if isinstance(target_hash, str):
            target_hash = bytes.fromhex(target_hash)
        if len(proof) == 0:
            return target_hash == merkle_root
        else:
            proof_hash = target_hash
            for p in proof:
                try:
                    # the sibling is a left node
                    sibling = p['left']
                    proof_hash = self.hash_function(sibling + proof_hash).digest()
                except:
                    # the sibling is a right node
                    sibling = p['right']
                    proof_hash = self.hash_function(proof_hash + sibling).digest()
            return proof_hash == merkle_root
