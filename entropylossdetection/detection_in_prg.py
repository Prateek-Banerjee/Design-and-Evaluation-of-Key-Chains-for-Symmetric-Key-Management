from typing import Tuple
from keychains.utils import bits_to_bytes, generate_random_input_parameter_for_prg
from cryptographicprimitives.prg_operations import Prg
from .unsoundidealizationcryptographicprimitives.prg_operations import Prg as UnsoundPrg
from .utils import check_injectivity_for_idealizations


class PrgDetection:
    def __init__(self, security_parameter_lambda: int, number_of_random_parameters: int) -> None:
        self.__security_parameter_lambda = security_parameter_lambda
        self.__number_of_random_parameters = number_of_random_parameters
        self.__prg_state_of_all_zeroes = bits_to_bytes(
            [0] * self.__security_parameter_lambda * 8)
        self.prg_obj = Prg(self.__security_parameter_lambda,
                           self.__prg_state_of_all_zeroes)
        self.unsound_prg_obj = UnsoundPrg(
            self.__security_parameter_lambda, self.__prg_state_of_all_zeroes)

    def get_multiple_random_input_parameters_for_prg(self, number_of_parameters_to_be_generated: int) -> list[bytes]:
        """
        Generates a list of seeds to be used for refreshing the PRG state.
        Each seed is the parameter "X".
        """
        list_of_seeds: list[bytes] = [generate_random_input_parameter_for_prg(
            self.__security_parameter_lambda) for _ in range(number_of_parameters_to_be_generated)]
        return list_of_seeds

    def generate_random_outputs_from_prg_refresh_for_sound_idealization(self, list_of_seeds: list[bytes]) -> list[bytes]:
        """
        Generates a list of refreshed PRG states for sound idealization.

        Parameters
        ----------

        list_of_seeds : list[bytes]
                        This is the same list of seeds obtained from the method 
                        "get_multiple_random_input_parameters_for_prg()".

        Returns
        -------

        A list of refreshed PRG states as random outputs.       
        """
        list_of_refreshed_prg_state: list[bytes] = []
        for seed in list_of_seeds:
            refreshed_prg_state: bytes = self.prg_obj.prg_refresh(
                self.__prg_state_of_all_zeroes, seed)
            list_of_refreshed_prg_state.append(refreshed_prg_state)
        return list_of_refreshed_prg_state

    def generate_random_outputs_from_prg_refresh_for_unsound_idealization(self, list_of_seeds: list[bytes]) -> list[bytes]:
        """
        Generates a list of refreshed PRG states for unsound idealization.

        Parameters
        ----------

        list_of_seeds : list[bytes]
                        This is the same list of seeds obtained from the method 
                        "get_multiple_random_input_parameters_for_prg()".

        Returns
        -------

        A list of refreshed PRG states as random outputs.       
        """
        list_of_refreshed_prg_state: list[bytes] = []
        for seed in list_of_seeds:
            refreshed_prg_state: bytes = self.unsound_prg_obj.prg_refresh(seed)
            list_of_refreshed_prg_state.append(refreshed_prg_state)
        return list_of_refreshed_prg_state

    def generate_random_outputs_from_prg_next_for_sound_idealization(self) -> Tuple[list[bytes], list[bytes]]:
        """
        Generates a tuple of lists of new PRG states and corresponding
        random outputs for sound idealization from the PRG next call.  
        """
        list_of_random_outputs_from_prg: list[bytes] = []
        prg_state: bytes = self.__prg_state_of_all_zeroes
        list_of_the_corresponding_prg_states: list[bytes] = []
        for _ in range(self.__number_of_random_parameters):
            list_of_the_corresponding_prg_states.append(prg_state)
            random_output_from_prg, prg_state = self.prg_obj.prg_next(
                prg_state)
            list_of_random_outputs_from_prg.append(random_output_from_prg)
        return (list_of_random_outputs_from_prg, list_of_the_corresponding_prg_states)

    def check_for_entropy_loss(self, list_of_corresponding_inputs: list[bytes], list_of_random_outputs_from_prg: list[bytes]) -> None:
        check_injectivity_for_idealizations(
            list_of_corresponding_inputs, list_of_random_outputs_from_prg)
        print(f"\t\t The cryptographic primitive is injective because no collisions have been found after testing {
              self.__number_of_random_parameters} inputs parameters and their corresponding outputs.")
