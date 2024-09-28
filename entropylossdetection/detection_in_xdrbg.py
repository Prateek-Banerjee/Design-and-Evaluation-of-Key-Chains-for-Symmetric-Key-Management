from typing import Tuple, Union
from keychains.utils import generate_random_input_parameter_for_xdrbg
from cryptographicprimitives.xdrbg_operations import ShakeBasedXdrbg, AsconBasedXdrbg
from .utils import check_injectivity_for_idealizations
from .unsoundidealizationcryptographicprimitives.xdrbg_operations import (
    ShakeBasedXdrbg as UnsoundShakeBasedXdrbg, AsconBasedXdrbg as UnsoundAsconBasedXdrbg)

DESIRED_OUTPUT_LENGTH: int = 32 # 32 bytes


class XdrbgDetection:
    xdrbg_obj: Union[ShakeBasedXdrbg, AsconBasedXdrbg]
    unsound_xdrbg_obj: Union[UnsoundShakeBasedXdrbg, UnsoundAsconBasedXdrbg]

    def __init__(self, xof, number_of_random_parameters: int, ascon_xof_name: Union[str, None] = None) -> None:
        self.__xof = xof
        self.__number_of_random_parameters = number_of_random_parameters
        if ascon_xof_name is not None:
            self.xof_name = ascon_xof_name
            self.xdrbg_obj = AsconBasedXdrbg(self.__xof, self.xof_name)
            self.unsound_xdrbg_obj = UnsoundAsconBasedXdrbg(
                self.__xof, self.xof_name)
        else:
            self.xof_name = self.__xof.name
            self.xdrbg_obj = ShakeBasedXdrbg(self.__xof)
            self.unsound_xdrbg_obj = UnsoundShakeBasedXdrbg(self.__xof)

    def get_multiple_random_input_parameters_for_xdrbg(self, number_of_parameters_to_be_generated: int) -> list[bytes]:
        """
        Generates a list of seeds to be used for instantiating and
        reseeding the XDRBG state. During instantiation, each seed
        refers to the parameter "SD_init" and during reseeding, each
        sed refers to the parameter "SD_rsd".
        """
        list_of_seeds: list[bytes] = [generate_random_input_parameter_for_xdrbg(
            self.xof_name) for _ in range(number_of_parameters_to_be_generated)]
        return list_of_seeds

    def generate_random_outputs_from_xdrbg_instantiate_for_sound_idealization(self, list_of_seeds: list[bytes]) -> list[bytes]:
        """
        Generates a list of initial XDRBG states for sound idealization.

        Parameters
        ----------

        list_of_seeds : list[bytes]
                        This is the same list of seeds obtained from the method 
                        "get_multiple_random_input_parameters_for_xdrbg()".

        Returns
        -------

        A list of initial XDRBG states as random outputs.
        """
        list_of_initial_xdrbg_state: list[bytes] = []
        for seed in list_of_seeds:
            initial_xdrbg_state: bytes = self.xdrbg_obj.xdrbg_instantiate(seed)
            list_of_initial_xdrbg_state.append(initial_xdrbg_state)
        return list_of_initial_xdrbg_state

    def generate_random_outputs_from_xdrbg_reseed_for_sound_idealization(self, list_of_seeds: list[bytes]) -> list[bytes]:
        """
        Generates a list of reseeded XDRBG states for sound idealization.

        Parameters
        ----------

        list_of_seeds : list[bytes]
                        This is the same list of seeds obtained from the method 
                        "get_multiple_random_input_parameters_for_xdrbg()".

        Returns
        -------

        A list of reseeded XDRBG states as random outputs.
        """
        list_of_reseeded_xdrbg_state: list[bytes] = []
        initial_xdrbg_state: bytes = self.xdrbg_obj.xdrbg_instantiate(
            generate_random_input_parameter_for_xdrbg(self.xof_name))
        for seed in list_of_seeds:
            reseeded_xdrbg_state = self.xdrbg_obj.xdrbg_reseed(
                initial_xdrbg_state, seed)
            list_of_reseeded_xdrbg_state.append(reseeded_xdrbg_state)
        return list_of_reseeded_xdrbg_state

    def generate_random_outputs_from_xdrbg_reseed_for_unsound_idealization(self, list_of_seeds: list[bytes]) -> list[bytes]:
        """
        Generates a list of reseeded XDRBG states for unsound idealization.

        Parameters
        ----------

        list_of_seeds : list[bytes]
                        This is the same list of seeds obtained from the method 
                        "get_multiple_random_input_parameters_for_xdrbg()".

        Returns
        -------

        A list of reseeded XDRBG states as random outputs.
        """
        list_of_reseeded_xdrbg_state: list[bytes] = []
        for seed in list_of_seeds:
            reseeded_xdrbg_state = self.unsound_xdrbg_obj.xdrbg_reseed(seed)
            list_of_reseeded_xdrbg_state.append(reseeded_xdrbg_state)
        return list_of_reseeded_xdrbg_state

    def generate_random_outputs_from_xdrbg_generate_for_sound_idealization(self) -> Tuple[list[bytes], list[bytes]]:
        """
        Generates a tuple of lists of new XDRBG states and corresponding
        random outputs for sound idealization from the XDRBG generate call.  
        """
        list_of_random_outputs_from_xdrbg: list[bytes] = []
        xdrbg_state: bytes = self.xdrbg_obj.xdrbg_instantiate(
            generate_random_input_parameter_for_xdrbg(self.xof_name))
        list_of_the_corresponding_xdrbg_states: list[bytes] = []
        for _ in range(self.__number_of_random_parameters):
            list_of_the_corresponding_xdrbg_states.append(xdrbg_state)
            xdrbg_state, random_output_from_xdrbg = self.xdrbg_obj.xdrbg_generate(
                xdrbg_state, DESIRED_OUTPUT_LENGTH)
            list_of_random_outputs_from_xdrbg.append(random_output_from_xdrbg)
        return (list_of_random_outputs_from_xdrbg, list_of_the_corresponding_xdrbg_states)

    def check_for_entropy_loss(self, list_of_corresponding_inputs: list[bytes], list_of_random_outputs_from_xdrbg: list[bytes]) -> None:
        check_injectivity_for_idealizations(
            list_of_corresponding_inputs, list_of_random_outputs_from_xdrbg)
        print(f"\t\t The cryptographic primitive is injective because no collisions have been found after testing {
              self.__number_of_random_parameters} inputs parameters and their corresponding outputs.")
