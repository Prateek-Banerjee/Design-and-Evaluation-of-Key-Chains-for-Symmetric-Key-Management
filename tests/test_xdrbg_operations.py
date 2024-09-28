import unittest
import os
import sys
import random
from hashlib import shake_128, shake_256
from ascon._ascon import ascon_hash

# Get the directory of the current file
current_dir = os.path.dirname(os.path.abspath(__file__))

# Get the parent directory of the current file's directory
parent_dir = os.path.dirname(current_dir)

# Add the parent directory to sys.path
sys.path.append(parent_dir)

from cryptographicprimitives.xdrbg_operations import ShakeBasedXdrbg, AsconBasedXdrbg

shake_128_xdrbg_obj = ShakeBasedXdrbg(shake_128())
shake_256_xdrbg_obj = ShakeBasedXdrbg(shake_256())
ascon_xdrbg_obj = AsconBasedXdrbg(ascon_hash, "Ascon-Xof")

class TestXdrbg(unittest.TestCase):

    def test_for_reseeded_xdrbg_state_being_equal_to_the_desired_length(self):
        for xdrbg_obj in [shake_128_xdrbg_obj, shake_256_xdrbg_obj, ascon_xdrbg_obj]:
            seed_instantiate = os.urandom(48)
            alpha_instantiate = os.urandom(random.randint(0, 84))
            xdrbg_state = xdrbg_obj.xdrbg_instantiate(seed_instantiate, alpha_instantiate)

            seed_reseed = os.urandom(32)
            alpha_reseed = os.urandom(random.randint(0, 84))

            reseeded_xdrbg_state = xdrbg_obj.xdrbg_reseed(xdrbg_state, seed_reseed, alpha_reseed)
            self.assertEqual(xdrbg_obj.XDRBG_STATE_SIZE, len(reseeded_xdrbg_state))

    def test_for_random_output_and_new_xdrbg_state_being_equal_to_their_desired_lengths(self):
        for xdrbg_obj in [shake_128_xdrbg_obj, shake_256_xdrbg_obj, ascon_xdrbg_obj]:
            seed_instantiate = os.urandom(48)
            alpha_instantiate = os.urandom(random.randint(0, 84))
            xdrbg_state = xdrbg_obj.xdrbg_instantiate(seed_instantiate, alpha_instantiate)

            alpha_generate = os.urandom(random.randint(0, 84))
            if xdrbg_obj in [shake_128_xdrbg_obj, ascon_xdrbg_obj]:
                DESIRED_OUTPUT_LENGTH = 16
            else:
                DESIRED_OUTPUT_LENGTH = 32
            new_xdrbg_state, random_output = xdrbg_obj.xdrbg_generate(xdrbg_state, DESIRED_OUTPUT_LENGTH, alpha_generate)
            self.assertEqual(DESIRED_OUTPUT_LENGTH, len(random_output))
            self.assertEqual(xdrbg_obj.XDRBG_STATE_SIZE, len(new_xdrbg_state))

    def test_for_initial_xdrbg_state_being_equal_to_the_desired_length(self):
        for xdrbg_obj in [shake_128_xdrbg_obj, shake_256_xdrbg_obj, ascon_xdrbg_obj]:
            seed_instantiate = os.urandom(48)
            alpha_instantiate = os.urandom(random.randint(0, 84))
            initial_state_of_xdrbg = xdrbg_obj.xdrbg_instantiate(seed_instantiate, alpha_instantiate)
            self.assertEqual(xdrbg_obj.XDRBG_STATE_SIZE, len(initial_state_of_xdrbg))

    def test_to_raise_error_with_the_seed_length_for_xdrbg_instantiate(self):
        for xdrbg_obj in [shake_128_xdrbg_obj, shake_256_xdrbg_obj, ascon_xdrbg_obj]:
            seed_instantiate = os.urandom(16)  # Intentionally incorrect length
            alpha_instantiate = os.urandom(random.randint(0, 84))
            with self.assertRaises(ValueError):
                xdrbg_obj.xdrbg_instantiate(seed_instantiate, alpha_instantiate)

    def test_to_raise_error_with_the_seed_length_for_xdrbg_reseed(self):
        for xdrbg_obj in [shake_128_xdrbg_obj, shake_256_xdrbg_obj, ascon_xdrbg_obj]:
            seed_instantiate = os.urandom(48)
            alpha_instantiate = os.urandom(random.randint(0, 84))
            xdrbg_state = xdrbg_obj.xdrbg_instantiate(seed_instantiate, alpha_instantiate)

            seed_reseed = os.urandom(12)  # Intentionally incorrect length
            alpha_reseed = os.urandom(random.randint(0, 84))

            with self.assertRaises(ValueError):
                xdrbg_obj.xdrbg_reseed(xdrbg_state, seed_reseed, alpha_reseed)

    def test_to_raise_error_with_total_output_length_for_xdrbg_generate(self):
        for xdrbg_obj in [shake_128_xdrbg_obj, shake_256_xdrbg_obj, ascon_xdrbg_obj]:
            seed_instantiate = os.urandom(48)
            alpha_instantiate = os.urandom(random.randint(0, 84))
            xdrbg_state = xdrbg_obj.xdrbg_instantiate(seed_instantiate, alpha_instantiate)

            alpha_generate = os.urandom(random.randint(0, 84))
            with self.assertRaises(ValueError):
                xdrbg_obj.xdrbg_generate(xdrbg_state, 345, alpha_generate)  # Intentionally incorrect length


if __name__ == "__main__":
    unittest.main()
