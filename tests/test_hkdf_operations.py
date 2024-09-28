import unittest
import os
import sys
from hashlib import sha256, sha512, sha3_256, sha3_512

# Get the directory of the current file
current_dir = os.path.dirname(os.path.abspath(__file__))

# Get the parent directory of the current file's directory
parent_dir = os.path.dirname(current_dir)

# Add the parent directory to sys.path
sys.path.append(parent_dir)

from cryptographicprimitives.hkdf_operations import Hkdf

class TestHkdf(unittest.TestCase):

    def test_for_total_output_from_hkdf_being_equal_to_the_desired_length(self):
        for hash_func in [sha256, sha512, sha3_256, sha3_512]:
            hkdf_obj = Hkdf(hash_func)
            salt = os.urandom(32)
            skm = os.urandom(32)
            psuedo_random_key = hkdf_obj.hkdf_extract(salt, skm)
            if hash_func in [sha256, sha3_256]:
                DESIRED_OUTPUT_LENGTH = 32
            elif hash_func in [sha512, sha3_512]:
                DESIRED_OUTPUT_LENGTH = 64
            total_output_from_hkdf = hkdf_obj.hkdf_expand(psuedo_random_key,None,DESIRED_OUTPUT_LENGTH)
            self.assertEqual(DESIRED_OUTPUT_LENGTH, len(total_output_from_hkdf))
    
    def test_to_raise_error_with_the_total_output_length_for_hkdf_expand(self):
        for hash_func in [sha256, sha512, sha3_256, sha3_512]:
            hkdf_obj = Hkdf(hash_func)
            salt = os.urandom(32)
            skm = os.urandom(32)
            psuedo_random_key = hkdf_obj.hkdf_extract(skm,salt)            
            DESIRED_OUTPUT_LENGTH = 19999
            with self.assertRaises(ValueError):
                hkdf_obj.hkdf_expand(psuedo_random_key,None,DESIRED_OUTPUT_LENGTH)

if __name__ == "__main__":
    unittest.main()             