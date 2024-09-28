"""
A robust Pseudo Random Generator (PRG) takes as input a bit string of a certain length and produces an output which is
required (or at least expected) to be indistinguishable from completely random bits.

This is based on the academic work:

[1] Barak, Boaz, and Shai Halevi. "A model and architecture for pseudo-random generation with applications to/dev/random."
Proceedings of the 12th ACM conference on Computer and communications security. 2005.
https://eprint.iacr.org/2005/029.pdf
"""

from Crypto.Cipher import AES
from Crypto.Cipher.AES import MODE_CTR
from Crypto.Util import Counter

NONCE_FOR_PRG_REFRESH: bytes = b'\x96' + b'\r' * 11


class Prg:
    def __init__(self, security_parameter_lambda: int, initial_prg_state: bytes) -> None:
        """
        Creates an instance of the Prg with the initial Prg state
        of size equal to equal to the security parameter λ.

        Parameters
        ----------
        security_parameter_lambda : int
                                    The security parameter lambda in bytes.

        initial_prg_state : bytes
                            The initial Prg state will be of length equal
                            to λ bytes or λ*8 bits and will comprise of
                            all "0s" [1].

        Returns
        -------
        None
        """
        self.__security_parameter_lambda = security_parameter_lambda
        self.__initial_prg_state = initial_prg_state

    def prg_refresh(
        self, extracted_parameter: bytes
    ) -> bytes:
        """
        Creates a new Prg state.

        Parameters
        ----------

        extracted_parameter : bytes
                              This parameter is (expected to be) generated from a
                              randomness extractor which should be of length equal
                              to the security_parameter_lambda [1].

        Returns
        -------
        The Prg state after refreshing in bytes.
        """

        prg_state_after_refreshing: bytes = self.aes_counter_mode_as_prg_invoked_from_prg_refresh(
            extracted_parameter)
        return prg_state_after_refreshing

    # The method for using the AES in Counter mode as the PRG as mentioned in Page 12 of [1]
    def aes_counter_mode_as_prg_invoked_from_prg_refresh(
        self, input_key: bytes
    ) -> bytes:
        """
        According to [1], here an input of certain length (equal to the length
        of the security_parameter_lambda) is taken and an output twice the length of
        the input is generated.

        Parameter
        ---------

        input_key : bytes
                    This parameter is basically a value computed as current_prg_state ⊕ extracted_parameter,
                    where the extracted_parameter is extracted from a randomness extractor. This input_key
                    will always be of length either 16 or 24 or 32 bytes (128 or 192 or 256 bits).

        Returns
        -------
        The refreshed Prg state of size λ in bytes.
        """

        
        # As for uniqueness, in AES CTR mode, it is a combination of a nonce and a counter value which is of 16-bytes
        # (128 bits) altogether. Thus, we keep the nonce of length 12 bytes and a counter value of length 4 bytes (32 bits).
       

        nonce: bytes = NONCE_FOR_PRG_REFRESH

        
        # Generates a counter block function suitable for AES-CTR encryption modes.
       
        counter_block: dict[str, int | bytes | bool] = Counter.new(
            32, prefix=nonce, initial_value=0)

        
        # The plaintext (which is to be encrypted) is just a string of 0's of length equal to twice the
        # security parameter "λ" because the security of AES in Counter mode relies (with a vast majority)
        # on the uniqueness of the counter block.
       
        plaintext: bytes = b"\x00" * \
            (2 * self.__security_parameter_lambda)

        cipher_context = AES.new(input_key, MODE_CTR, counter=counter_block)

        pseudorandom_output: bytes = cipher_context.encrypt(plaintext)

        return pseudorandom_output[0: self.__security_parameter_lambda]
