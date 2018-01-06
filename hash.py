import hashlib

#class to handle the hashing
class Hash:
    def __init__(self, data, algo, iteration=1):
        self.data = data
        self.algo = algo
        self.iteration = iteration

    def hash(self):
        encoded_data = self.data.encode()
        if self.algo == "md5":
            while self.iteration > 0:
                hash_object = hashlib.md5()
                hash_object.update(encoded_data)
                encoded_data = hash_object.digest()
                self.iteration -= 1

        elif self.algo == "sha1":
            while self.iteration > 0:
                hash_object = hashlib.sha1()
                hash_object.update(encoded_data)
                encoded_data = hash_object.digest()
                self.iteration -= 1

        elif self.algo == "sha256":
            while self.iteration > 0:
                hash_object = hashlib.sha256()
                hash_object.update(encoded_data)
                encoded_data = hash_object.digest()
                self.iteration -= 1

        else:
            return 'Algo undefined'

        hash_string = hash_object.hexdigest()
        return hash_string

