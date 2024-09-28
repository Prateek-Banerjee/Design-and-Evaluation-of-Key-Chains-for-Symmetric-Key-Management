"""
HKDF is a Hash (function) based Key Derivation Function which is based on the extract-then-expand approach and it takes a (source) keying material of a certain length
along with an optional salt and an info parameter as input and generates an output of a desired length. The motive of using the Hkdf is to ensure the security of the
generated output when the (source) keying material is not uniformly random or pseudorandom so as to be directly used as a seed for a Pseudorandom Generator. Instead,
it is expected that an extract-then-expand approach based Key Derivation Function (KDF) in general will extract a pseudorandom key from this imperfect source and
generate further outputs (cryptographic keys) by expanding this pseudorandom key.

[1] Krawczyk, Hugo. "Cryptographic extraction and key derivation: The HKDF scheme." Annual Cryptology Conference. Berlin, Heidelberg: Springer Berlin Heidelberg, 2010.
[2] https://github.com/casebeer/python-hkdf
"""
from math import ceil
from typing import Union
import hmac

IS_PERFORMANCE_BENCHMARKING_DONE: bool = True


class Hkdf:

    def __init__(self, hash_algorithm) -> None:
        """
        Creates an instance of Hkdf with a hash function
        like sha256, sha512 or any hash function from the
        SHA-3 family.

        Parameter
        ---------
        hash_algorithm

        Returns
        -------
        None
        """
        self.__hash_algorithm = hash_algorithm
        self.hash_algorithm_digest_size_in_bytes: int = self.__hash_algorithm().digest_size

    def hkdf_extract(
        self, extractor_salt: Union[bytes, None], source_key_material: bytes
    ) -> bytes:
        """
        This is the Hkdf extract step which takes the source keying material
        and an optional salt parameter and generates the pseudorandom key.

        Parameters
        ----------

        extractor_salt : bytes or None
                         This is an optional parameter which can also be a non-secret
                         value. But, if the salt is provided, then depending on the
                         chosen hash function, the upper bound on the salt size will
                         vary because it will depend on the digest size of the same.
                         For e.g. if the hash function is SHA256, then, the salt can
                         at most 32 bytes (256 bits) long [1].     

        source_key_material : bytes

        Returns
        -------
        The Pseudo Random Key (PRK) in bytes.
        """

        # If no salt value is provided, set it to 0's equal to the length of the
        # digest size of the chosen hash function, else check the salt length
        # accordingly.

        if extractor_salt is None:
            extractor_salt = bytes(
                [0] * self.hash_algorithm_digest_size_in_bytes)

        if not IS_PERFORMANCE_BENCHMARKING_DONE:
            try:
                if (len(extractor_salt) > self.hash_algorithm_digest_size_in_bytes):
                    raise ValueError(
                        f"The length of the provided salt is {len(extractor_salt)} bytes which is more than the limit of {
                            self.hash_algorithm_digest_size_in_bytes} bytes for the chosen hash function."
                    )
            except ValueError as e:
                print(f"ValueError: {e}")
                raise

        # This is the computation of the parameter PRK = HMAC(XTS, SKM) according to Page
        # 13 of the downloaded pdf (which is Page 11) of [1].

        pseudo_random_key: bytes = hmac.new(
            extractor_salt, memoryview(
                source_key_material), self.__hash_algorithm
        ).digest()
        return pseudo_random_key

    def hkdf_expand(
        self,
        pseudo_random_key: bytes,
        info_parameter: Union[bytes, None],
        total_desired_output_length_in_bytes: int
    ) -> bytes:
        """
        This is the Hkdf expand step which takes the pseudo_random_key (PRK) generated
        during the extraction step and an optional_info_parameter to generate an output
        (which is considered to be secure or cryptographically strong enough to be used
        as cryptographic keys) equal to the desired_master_key_length.

        Parameters
        ----------

        pseudo_random_key : bytes

        info_parameter : bytes or None

        total_desired_output_length_in_bytes : int
                                               This value will be considered as the total desired length
                                               of the output in bytes. One important thing to note here
                                               is that, there is a limit on the maximum length of the
                                               output from HKDF depending on the underlying hash function
                                               which is 255 * digest_size of the hash function. For e.g., 
                                               if the underlying hash function is SHA256 then the maximum
                                               output from that can be 255 * 256 = 65,280 bits (8160 bytes) [2].       

        Returns
        -------
        The output of the total desired length in bytes.
        """

        # Check whether total length of the output is within the acceptable bounds or not.
        if not IS_PERFORMANCE_BENCHMARKING_DONE:
            try:
                if total_desired_output_length_in_bytes > (255 * self.hash_algorithm_digest_size_in_bytes):
                    raise ValueError(
                        f"Cannot expand more than the limit i.e. {
                            255*self.hash_algorithm_digest_size_in_bytes} bytes for the chosen hash function."
                    )
            except ValueError as e:
                print(f"ValueError: {e}")
                raise

        # Compute the parameter t = ceil(L/k) according to Page 13 of the downloaded
        # pdf (which is Page 11) of [1].

        number_of_blocks_needed: int = ceil(
            total_desired_output_length_in_bytes/self.hash_algorithm_digest_size_in_bytes)

        generated_output: bytes = b""
        each_output_block: bytes = b""

        if info_parameter is None:
            info_parameter = b""

        # This is the computation of the parameter K(1) = HMAC(PRK, k(0) || CTXinfo ∥ 0)
        # ...K(i+1) = HMAC(PRK, K(i) ∥ CTXinfo ∥ i) ... and onwards, where ∥ denotes
        # concatenation according to Page 13 of the downloaded pdf (which is Page 11)
        # of [1]. For the first iteration where i = 1, K(0) is a null string, i.e., for
        # i = 1, in the buffer, the parameter each_output_block will be b"".

        for i in range(1, number_of_blocks_needed+1):
            each_output_block = hmac.new(
                pseudo_random_key,
                memoryview(
                    each_output_block
                    + info_parameter
                    + bytearray((i,))
                ),
                self.__hash_algorithm,
            ).digest()
            generated_output += each_output_block

        truncated_output_of_desired_length_from_hkdf_after_expansion: bytes = (
            generated_output[0:total_desired_output_length_in_bytes]
        )

        return truncated_output_of_desired_length_from_hkdf_after_expansion
