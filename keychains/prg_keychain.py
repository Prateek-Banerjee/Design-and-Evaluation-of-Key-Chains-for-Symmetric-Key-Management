from typing import Tuple, Union
from cryptographicprimitives.prg_operations import Prg
from .utils import store_persistent_derivation_parameter, bits_to_bytes


class PrgKeyChain:
    def __init__(
        self, security_parameter_lambda: int, store_persistently: Union[bool, None] = None
    ) -> None:
        try:
            if security_parameter_lambda in [16, 24, 32]:
                self.__security_parameter_lambda = security_parameter_lambda
            else:
                raise ValueError(f"The security parameter lambda must be either 16 or 24 or 32 bytes, whereas {
                                 security_parameter_lambda} bytes are provided.")
        except ValueError as e:
            print(f"ValueError: {e}")
        self.__prg_state_of_all_zeroes = bits_to_bytes(
            [0] * self.__security_parameter_lambda * 8)
        self.__store_persistently = store_persistently
        self.__prg_obj = Prg(self.__security_parameter_lambda,
                             self.__prg_state_of_all_zeroes)

    def key_chain_instantiate(self, seed_for_prg_refreshing: bytes) -> bytes:
        """ 
        Generates the initial state of the key chain.

        Parameters
        ----------

        seed_for_prg_refreshing : bytes
                                  This is the arbitrary input parameter from the randomness extractor Circulant
                                  which acts as I_init.                                            

        Returns
        -------

        The initial state S_init of the key chain.
        """

        # Generate a refreshed state of the PRG at first which will be the initial state of the key chain
        initial_state_of_key_chain_using_prg: bytes = self.__prg_obj.prg_refresh(
            self.__prg_state_of_all_zeroes, seed_for_prg_refreshing
        )

        return initial_state_of_key_chain_using_prg

    def key_chain_update(self, arbitrary_input_parameter: bytes, current_state_of_key_chain_using_prg: bytes) -> Tuple[bytes, bytes]:
        """
        Generates the random output and the new PRG state which serves as the state of the key chain.

        Parameters
        ----------

        arbitrary_input_parameter : bytes
                                    This is the arbitrary input parameter from the randomness extractor Circulant.

        current_state_of_the_key_chain_using_prg : bytes

        Returns
        -------

        A tuple of (new_state_of_key_chain_using_prg, random_output) both in bytes.
        """

        return self.__prg_generate_keys(arbitrary_input_parameter, current_state_of_key_chain_using_prg, self.__store_persistently)

    def __prg_generate_keys(
        self,
        seed_for_prg_refreshing: bytes,
        current_state_of_the_key_chain_using_prg: bytes,
        store_persistently: Union[bool, None] = None
    ) -> Tuple[bytes, bytes]:

        # Generate a refreshed PRG state which will be used as an input to the next NEXT call
        refreshed_state_of_key_chain_using_prg: bytes = self.__prg_obj.prg_refresh(
            current_state_of_the_key_chain_using_prg, seed_for_prg_refreshing
        )

        # Generate the random output and the new PRG state
        # This state can be persistently stored and will be used as an input to the next REFRESH call to the PRG
        random_output, new_state_of_key_chain_using_prg = self.__prg_obj.prg_next(
            refreshed_state_of_key_chain_using_prg
        )

        if store_persistently:
            store_persistent_derivation_parameter(
                new_state_of_key_chain_using_prg, self.__security_parameter_lambda
            )

        return (new_state_of_key_chain_using_prg, random_output)
