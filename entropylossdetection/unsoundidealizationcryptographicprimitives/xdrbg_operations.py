"""
XDRBG is a Deterministic Random Bit Generator (DRBG) based on any sponge-based Extendable Output Function (XOF)
such as SHAKE_128 or SHAKE_256, which will produce an output which is required (or at least expected) to be
indistinguishable from completely random bits.

This is based on the academic work:

[1] Kelsey, John, Stefan Lucks, and Stephan Müller. "XDRBG: A Proposed Deterministic Random Bit Generator Based on Any XOF."
IACR Transactions on Symmetric Cryptology 2024.1 (2024): 5-34.
https://tosc.iacr.org/index.php/ToSC/article/view/11399
"""

from typing import Tuple, Optional
from .utils import encode_function, check_fulfillment_criteria_of_parameters

IS_PERFORMANCE_BENCHMARKING_DONE: bool = False

# Parent Class of Xdrbg


class Xdrbg:
    def __init__(
        self, xof, xdrbg_state_size: int
    ) -> None:
        self.xof = xof
        self.xdrbg_state_size = xdrbg_state_size

    def xdrbg_instantiate_main(
        self, xof_name: str, seed_instantiate: bytes, alpha_instantiate: Optional[bytes] = b""
    ) -> bytes:

        if not IS_PERFORMANCE_BENCHMARKING_DONE:
            check_fulfillment_criteria_of_parameters(
                xof_name=xof_name, seed=seed_instantiate, alpha=alpha_instantiate
            )
        encoded_bytes: bytes = encode_function(
            seed_instantiate, alpha_instantiate, 0)
        return self.generate_final_output(encoded_bytes, self.xdrbg_state_size)

    def xdrbg_reseed_main(
        self,
        xof_name: str,
        seed_reseeding: bytes,
        alpha_reseeding: Optional[bytes] = b"",
    ) -> bytes:

        if not IS_PERFORMANCE_BENCHMARKING_DONE:
            check_fulfillment_criteria_of_parameters(
                xof_name=xof_name, seed=seed_reseeding, alpha=alpha_reseeding
            )
        encoded_bytes: bytes = encode_function(seed_reseeding, alpha_reseeding, 1)
        return self.generate_final_output(encoded_bytes, self.xdrbg_state_size)

    def xdrbg_generate_main(
        self,
        xof_name: str,
        current_xdrbg_state: bytes,
        desired_output_length: int,
        alpha_generate: Optional[bytes] = b"",
    ) -> Tuple[bytes, bytes]:

        if not IS_PERFORMANCE_BENCHMARKING_DONE:
            check_fulfillment_criteria_of_parameters(
                xof_name=xof_name,
                length_of_the_random_output=desired_output_length,
                state_size=self.xdrbg_state_size,
                alpha=alpha_generate
            )
        encoded_bytes: bytes = encode_function(
            current_xdrbg_state, alpha_generate, 2)
        generated_output = self.generate_final_output(
            encoded_bytes, desired_output_length + self.xdrbg_state_size
        )
        new_xdrbg_state = generated_output[0:self.xdrbg_state_size]
        random_output = generated_output[self.xdrbg_state_size:]

        return (new_xdrbg_state, random_output)

    # This is an abstract method.
    def generate_final_output(
        self, encoded_bytes: bytes, length_of_output: int = 0
    ) -> bytes:
        """
        This is an abstract method which will be implemented by the
        respective sub classes to generate the final output of the
        Xdrbg of the desired length.

        Parameters
        ----------

        encoded_bytes : bytes

        length_of_output : int
                           The value of this length will depend from
                           where this method is invoked i.e. if it is
                           invoked from xdrbg_generate() then it will
                           be equal to the desired output length + the
                           Xdrbg state size, whereas, if it is invoked
                           form xdrbg_instantiate or xdrbg_reseed then
                           it will be equal to only the Xdrbg state size.

        Returns
        -------
        The final output of the Xdrbg in bytes of the desired length.
        """
        raise NotImplementedError(
            "This method is not yet implemented. It Must be implemented by a subclass."
        )


# Sub Class of Xdrbg for Shake-Xof based Xdrbg
class ShakeBasedXdrbg(Xdrbg):
    XDRBG_STATE_SIZE: int

    def __init__(self, xof) -> None:
        """
        Creates an instance of Xdrbg with a shake-based XOF and
        sets the Xdrbg state size depending on the XOF.

        Parameter
        ---------
        xof : _hashlib.HASHXOF

        Returns
        -------
        None
        """
        try:
            if xof.name == "shake_128":
                self.XDRBG_STATE_SIZE = 32  # 32 bytes = 256 bits
                super().__init__(xof, self.XDRBG_STATE_SIZE)
            elif xof.name == "shake_256":
                self.XDRBG_STATE_SIZE = 64  # 64 bytes = 512 bits
                super().__init__(xof, self.XDRBG_STATE_SIZE)
            else:
                raise NameError(
                    "Invalid XOF: Choose a valid XOF (like SHAKE_128 or SHAKE_256) from hashlib module."
                )
        except NameError as e:
            print(f"NameError: {e}")

    def xdrbg_instantiate(
        self, seed_instantiate: bytes, alpha_instantiate: Optional[bytes] = b""
    ) -> bytes:
        """
        Creates an Xdrbg state for the first time.

        Parameters
        ----------

        seed_instantiate : bytes
                           The initial seed material should be
                           preferably >=  24 bytes (192 bits) when
                           the Xof is SHAKE_128 or >= 48 bytes (384
                           bits) when the Xof is SHAKE_256 [1].

        alpha_instantiate : bytes
                            This is an optional parameter but it
                            can be of at most 84 bytes [1].

        Returns
        -------
        The Xdrbg state upon instantiation in bytes.
        """
        return super().xdrbg_instantiate_main(
            self.xof.name, seed_instantiate, alpha_instantiate
        )

    def xdrbg_reseed(
        self,
        seed_reseeding: bytes,
        alpha_reseeding: Optional[bytes] = b"",
    ) -> bytes:
        """
        Creates a new Xdrbg state.

        Parameters
        ----------

        seed_reseeding : bytes
                         The reseeding seed material should be
                         preferably >= 16 bytes (128 bits) when
                         the Xof is SHAKE_128 or >= 32 bytes
                         (256 bits) when the Xof is SHAKE_256 [1].

        alpha_reseeding : bytes
                          This is an optional parameter but it
                          can be of at most 84 bytes [1].

        Returns
        -------
        The Xdrbg state after reseeding in bytes.
        """
        return super().xdrbg_reseed_main(
            self.xof.name, seed_reseeding, alpha_reseeding
        )

    def xdrbg_generate(
        self,
        current_xdrbg_state: bytes,
        desired_output_length: int,
        alpha_generate: Optional[bytes] = b"",
    ) -> Tuple[bytes, bytes]:
        """
        Creates a new Xdrbg state and generates the (random) output.

        Parameters
        ----------

        current_xdrbg_state : bytes

        desired_output_length : int
                                The desired length of the random output bits must
                                be such that the length of total output of the Xof
                                i.e. desired_output_length + self.xdrbg_state_size
                                is <= 304 bytes (2432 bits) when the Xof is SHAKE_128
                                and is <= 344 bytes (2752 bits) when the Xof is
                                SHAKE_256. This means that when the Xof is SHAKE_128
                                (the state size is 32 bytes (256 bits) so) the
                                desired_output_length should be <= 272 bytes (2176
                                bits) and when the Xof is SHAKE_256 (the state size
                                is 64 bytes (512 bits)) the desired_output_length
                                should be <= 280 bytes (2240 bits).

        alpha_generate : bytes
                         This is an optional parameter but it
                         can be of at most 84 bytes [1].

        Returns
        -------
        A tuple of (new_xdrbg_state, random_output) both in bytes.
        """
        return super().xdrbg_generate_main(
            self.xof.name,
            current_xdrbg_state,
            desired_output_length,
            alpha_generate,
        )

    # Implementation of the abstract method for Shake based Xofs.
    def generate_final_output(
        self, encoded_bytes: bytes, length_of_output: int = 0
    ) -> bytes:

        # Feed the data into the Xof
        self.xof.update(encoded_bytes)

        
        # Return the (hash) digest of the data that has been
        # fed to the Xof of the desired length (as determined
        # by the parameter xdrbg_state_size).
       
        return self.xof.digest(length_of_output)


# Sub Class of Xdrbg for Ascon-Xof based Xdrbg
class AsconBasedXdrbg(Xdrbg):

    def __init__(self, xof, ascon_xof_name: str) -> None:
        """
        Creates an instance of Xdrbg with an ascon-based XOF and
        sets the Xdrbg state size.

        Parameter
        ---------

        xof :  ascon xof function

        ascon_xof_name : str
                         This must be a string "Ascon-Xof".

        Returns
        -------
        None
        """
        self.ascon_xof_name = ascon_xof_name
        try:
            if ascon_xof_name != "Ascon-Xof":
                raise NameError(
                    "Invalid name of ASCON XOF: Choose a valid name i.e. Ascon-Xof)."
                )
        except NameError as e:
            print(f"NameError: {e}")
        self.XDRBG_STATE_SIZE: int = 32  # 32 bytes = 256 bits
        super().__init__(xof, self.XDRBG_STATE_SIZE)

    def xdrbg_instantiate(
        self, seed_instantiate: bytes, alpha_instantiate: Optional[bytes] = b""
    ) -> bytes:
        """
        Creates an Xdrbg state for the first time.

        Parameters
        ----------

        seed_instantiate : bytes
                           The initial seed material should be
                           preferably >= 24 bytes (192 bits) [1].

        alpha_instantiate : bytes
                            This is an optional parameter but it
                            can be of at most 84 bytes [1].

        Returns
        -------
        The Xdrbg state upon instantiation in bytes.
        """
        return super().xdrbg_instantiate_main(
            self.ascon_xof_name, seed_instantiate, alpha_instantiate
        )

    def xdrbg_reseed(
        self,
        seed_reseeding: bytes,
        alpha_reseeding: Optional[bytes] = b"",
    ) -> bytes:
        """
        Creates a new Xdrbg state.

        Parameters
        ----------

        current_xdrbg_state : bytes

        seed_reseeding : bytes
                         The reseeding seed material should be
                         preferably >= 128 bits [1].

        alpha_reseeding : bytes
                          This is an optional parameter but it
                          can be of at most 84 bytes [1].

        Returns
        -------
        The Xdrbg state after reseeding in bytes.
        """
        return super().xdrbg_reseed_main(
            self.ascon_xof_name, seed_reseeding, alpha_reseeding
        )

    def xdrbg_generate(
        self,
        current_xdrbg_state: bytes,
        desired_output_length: int,
        alpha_generate: Optional[bytes] = b"",
    ) -> Tuple[bytes, bytes]:
        """
        Creates a new Xdrbg state and generates the (random) output.

        Parameters
        ----------

        current_xdrbg_state : bytes

        desired_output_length : int
                                The desired length of the random output bits must
                                be such that the length of total output of the Xof
                                i.e. desired_output_length + self.xdrbg_state_size
                                is <= 256 bytes (2048 bits). This means that, the
                                desired_output_length should be <= 224 bytes (1792
                                bits) because the state size is 32 bytes (256 bits).

        alpha_generate : bytes
                         This is an optional parameter but it
                         can be of at most 84 bytes [1].

        Returns
        -------
        A tuple of (new_xdrbg_state, random_output) both in bytes.
        """
        return super().xdrbg_generate_main(
            self.ascon_xof_name,
            current_xdrbg_state,
            desired_output_length,
            alpha_generate,
        )

    # Implementation of the abstract method for Ascon based Xofs.
    def generate_final_output(
        self, encoded_bytes: bytes, length_of_output: int = 0
    ) -> bytes:
        
        # Return the (hash) digest of the data that has been
        # fed to the Xof of the desired length (as determined
        # by the parameter length_of_output).
       
        return self.xof(encoded_bytes, self.ascon_xof_name, length_of_output)
