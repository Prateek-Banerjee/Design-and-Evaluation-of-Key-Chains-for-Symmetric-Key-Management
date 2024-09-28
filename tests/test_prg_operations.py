import unittest
import os
import sys

# Get the directory of the current file
current_dir = os.path.dirname(os.path.abspath(__file__))

# Get the parent directory of the current file's directory
parent_dir = os.path.dirname(current_dir)

# Add the parent directory to sys.path
sys.path.append(parent_dir)

from cryptographicprimitives.prg_operations import Prg
from keychains.utils import bits_to_bytes

class TestPrg(unittest.TestCase):

    def test_for_random_output_and_new_prg_state_being_equal_to_the_desired_length(self):
        for security_parameter_lambda in [16,24,32]:
            prg_state_of_all_zeroes = bits_to_bytes([0]*(security_parameter_lambda*8))
            prg_obj = Prg(security_parameter_lambda, prg_state_of_all_zeroes)

            random_output, new_prg_state = prg_obj.prg_next(prg_state_of_all_zeroes)
            self.assertEqual(security_parameter_lambda, len(random_output))
            self.assertEqual(security_parameter_lambda, len(new_prg_state))

    def test_for_refreshed_prg_state_being_equal_to_the_desired_length(self):
        for security_parameter_lambda in [16,24,32]:
            prg_state_of_all_zeroes = bits_to_bytes([0]*(security_parameter_lambda*8))
            prg_obj = Prg(security_parameter_lambda, prg_state_of_all_zeroes)
            seed_refresh = os.urandom(security_parameter_lambda)
            refreshed_prg_state = prg_obj.prg_refresh(prg_state_of_all_zeroes,seed_refresh)          
            self.assertEqual(security_parameter_lambda, len(refreshed_prg_state))            

if __name__ == "__main__":
    unittest.main()            