from typing import Tuple, Union
from cryptographicprimitives.hkdf_operations import Hkdf
from .utils import store_persistent_derivation_parameter


class HkdfKeyChain:
    __key_chain_state_state_size_using_hkdf: int

    def __init__(self, hash_algorithm, store_persistently: Union[bool, None] = None) -> None:

        self.__hash_algorithm = hash_algorithm
        try:
            if self.__hash_algorithm.__name__ == "openssl_sha3_256" or self.__hash_algorithm.__name__ == "openssl_sha256":
                self.__key_chain_state_state_size_using_hkdf = 32
                self.__desired_length_of_only_the_random_output_key = 32
            elif self.__hash_algorithm.__name__ == "openssl_sha3_512" or self.__hash_algorithm.__name__ == "openssl_sha512":
                self.__key_chain_state_state_size_using_hkdf = 64
                self.__desired_length_of_only_the_random_output_key = 64
            else:
                raise NameError(f"Incorrect choice of hash function {
                                self.__hash_algorithm.__name__} for the key chain.")
        except NameError as e:
            print(f"NameError: {e}")
        self.__store_persistently = store_persistently
        self.__hkdf_obj = Hkdf(self.__hash_algorithm)

    def key_chain_instantiate(self, initial_source_key_material: bytes) -> bytes:
        """ 
        Generates the initial state of the key chain.

        Parameters
        ----------

        initial_source_key_material : bytes
                                      This is the arbitrary input parameter from the randomness extractor Circulant
                                      which acts as I_init.                                            

        Returns
        -------

        The initial state S_init of the key chain.
        """

        # Generate the pseudorandom key from the HKDF extract function
        pseudo_random_key: bytes = self.__hkdf_obj.hkdf_extract(
            None, initial_source_key_material)

        total_desired_output_length: int = self.__key_chain_state_state_size_using_hkdf

        # Generate the initial HKDF state and the initial master key
        total_output_from_hkdf = self.__hkdf_obj.hkdf_expand(
            pseudo_random_key, None,
            total_desired_output_length
        )

        initial_state_of_key_chain_using_hkdf = total_output_from_hkdf

        return initial_state_of_key_chain_using_hkdf

    def key_chain_update(self, arbitrary_input_parameter: bytes, current_state_of_key_chain_using_hkdf: bytes) -> Tuple[bytes, bytes]:
        """ 
        Generates the random output and the new state of the key chain.

        Parameters
        ----------

        arbitrary_input_parameter : bytes
                                    This is the arbitrary input parameter from the randomness extractor Circulant.

        current_state_of_the_key_chain_using_hkdf : bytes
                                                    This parameter is basically the current state of the key chain
                                                    using HKDF.                                           

        Returns
        -------

        A tuple of (new_state_of_the_key_chain_using_hkdf, random_output) both in bytes.
        """

        return self.__hkdf_generate_keys(arbitrary_input_parameter, current_state_of_key_chain_using_hkdf, self.__store_persistently)

    def __hkdf_generate_keys(self, arbitrary_input_parameter: bytes, current_state_of_the_key_chain_using_hkdf: bytes,
                             store_persistently: Union[bool, None] = None) -> Tuple[bytes, bytes]:

        # Generate the pseudorandom key from the HKDF extract function
        pseudo_random_key: bytes = self.__hkdf_obj.hkdf_extract(
            None, arbitrary_input_parameter + current_state_of_the_key_chain_using_hkdf)

        total_desired_output_length: int = self.__key_chain_state_state_size_using_hkdf + \
            self.__desired_length_of_only_the_random_output_key

        total_output_from_hkdf: bytes = self.__hkdf_obj.hkdf_expand(
            pseudo_random_key, None, total_desired_output_length)

        # Generate the random output and the new state of the key chain
        # This state can be persistently stored and will be used as an input to the next call to the HKDF
        new_state_of_the_key_chain_using_hkdf, random_output = total_output_from_hkdf[
            :self.__key_chain_state_state_size_using_hkdf], total_output_from_hkdf[self.__key_chain_state_state_size_using_hkdf:]

        if store_persistently:
            store_persistent_derivation_parameter(
                new_state_of_the_key_chain_using_hkdf, self.__hash_algorithm.__name__)

        return (new_state_of_the_key_chain_using_hkdf, random_output)
