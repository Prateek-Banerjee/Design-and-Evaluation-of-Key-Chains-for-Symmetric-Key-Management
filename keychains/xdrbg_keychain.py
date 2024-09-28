from typing import Tuple, Union
from cryptographicprimitives.xdrbg_operations import (
    ShakeBasedXdrbg,
    AsconBasedXdrbg,
)
from .utils import store_persistent_derivation_parameter


def xdrbg_generate_keys(
    seed_for_xdrbg_reseeding: bytes,
    current_state_of_the_key_chain_using_xdrbg: bytes,
    xdrbg_obj: Union[ShakeBasedXdrbg, AsconBasedXdrbg],
    xof_name: str,
    desired_length_of_only_the_random_output_key: int,
    store_persistently: Union[bool, None]
) -> Tuple[bytes, bytes]:

    # Generate a reseeded XDRBG state which will be used as an input to the next GENERATE call
    reseeded_state_of_key_chain_using_xdrbg: bytes = xdrbg_obj.xdrbg_reseed(
        current_state_of_the_key_chain_using_xdrbg,
        seed_for_xdrbg_reseeding
    )

    # Generate the random output and the new XDRBG state.
    # This state can be persistently stored and will be used as an input to the next RESEED call to the XDRBG
    new_state_of_key_chain_using_xdrbg, random_output = xdrbg_obj.xdrbg_generate(
        reseeded_state_of_key_chain_using_xdrbg,
        desired_length_of_only_the_random_output_key
    )

    if store_persistently:
        store_persistent_derivation_parameter(
            new_state_of_key_chain_using_xdrbg, xof_name
        )

    return (new_state_of_key_chain_using_xdrbg, random_output)

LENGTH_OF_OUTPUT_KEY: dict[str, int] = {"shake_128": 16, "shake_256" : 32}

class ShakeXdrbgKeychain:

    def __init__(self, xof, store_persistently: Union[bool, None] = None) -> None:
        self.__xof = xof
        self.__store_persistently = store_persistently
        self.__shake_xdrbg_obj = ShakeBasedXdrbg(self.__xof)
        self.__desired_length_of_only_the_random_output_key = LENGTH_OF_OUTPUT_KEY.get(xof.name)

    def key_chain_instantiate(self, seed_for_xdrbg_instantiate: bytes) -> bytes:
        """ 
        Generates the initial state of the key chain.

        Parameters
        ----------

        seed_for_xdrbg_instantiate : bytes
                                     This is the arbitrary input parameter from the randomness extractor Circulant
                                     which acts as I_init.                                            

        Returns
        -------

        The initial state S_init of the key chain.
        """

        # Generate an initial state of the XDRBG at first which will be the initial state of the key chain
        initial_state_of_key_chain_using_shake_based_xdrbg: bytes = self.__shake_xdrbg_obj.xdrbg_instantiate(
            seed_for_xdrbg_instantiate
        )

        return initial_state_of_key_chain_using_shake_based_xdrbg

    def key_chain_update(
            self, arbitrary_input_parameter: bytes, current_state_of_key_chain_using_shake_based_xdrbg: bytes) -> Tuple[bytes, bytes]:
        """
        Generates the random output and the new XDRBG state which serves as the state of the key chain.

        Parameters
        ----------

        arbitrary_input_parameter : bytes
                                    This is the arbitrary input parameter from the randomness
                                    extractor Circulant.

        current_state_of_key_chain_using_shake_based_xdrbg : bytes

        Returns
        -------

        A tuple of (new_state_of_key_chain_using_xdrbg, random_output) both in bytes.
        """

        return xdrbg_generate_keys(arbitrary_input_parameter, current_state_of_key_chain_using_shake_based_xdrbg,
                                   self.__shake_xdrbg_obj, self.__xof.name, self.__desired_length_of_only_the_random_output_key,
                                   self.__store_persistently)


class AsconXdrbgKeychain:

    def __init__(self, xof, store_persistently: Union[bool, None] = None) -> None:
        self.__ascon_xof_name = "Ascon-Xof"
        self.__store_persistently = store_persistently
        self.__ascon_xdrbg_obj = AsconBasedXdrbg(xof, self.__ascon_xof_name)
        self.__desired_length_of_only_the_random_output_key = 16

    def key_chain_instantiate(self, seed_for_xdrbg_instantiate: bytes) -> bytes:
        """ 
        Generates the initial state of the key chain.

        Parameters
        ----------

        seed_for_xdrbg_instantiate : bytes
                                     This is the arbitrary input parameter from the randomness extractor Circulant
                                     which acts as I_init.                                            

        Returns
        -------

        The initial state S_init of the key chain.
        """

        # Generate an initial state of the XDRBG at first which will be the initial state of the key chain
        initial_state_of_key_chain_using_ascon_based_xdrbg: bytes = self.__ascon_xdrbg_obj.xdrbg_instantiate(
            seed_for_xdrbg_instantiate
        )

        return initial_state_of_key_chain_using_ascon_based_xdrbg

    def key_chain_update(
            self, arbitrary_input_parameter: bytes, current_state_of_key_chain_using_ascon_based_xdrbg: bytes) -> Tuple[bytes, bytes]:
        """
        Generates the random output and the new XDRBG state which serves as the state of the key chain.

        Parameters
        ----------

        arbitrary_input_parameter : bytes
                                    This is the arbitrary input parameter from the randomness
                                    extractor Circulant.

        current_state_of_key_chain_using_ascon_based_xdrbg : bytes

        Returns
        -------

        A tuple of (new_state_of_key_chain_using_xdrbg, random_output) both in bytes.
        """

        return xdrbg_generate_keys(arbitrary_input_parameter, current_state_of_key_chain_using_ascon_based_xdrbg,
                                   self.__ascon_xdrbg_obj, self.__ascon_xof_name, self.__desired_length_of_only_the_random_output_key,
                                   self.__store_persistently)
