from keychains.utils import generate_random_input_parameter_for_hkdf
from cryptographicprimitives.hkdf_operations import Hkdf
from .utils import check_injectivity_for_idealizations

DESIRED_OUTPUT_LENGTH: int = 32 # 32 bytes


class HkdfDetection:
    def __init__(self, hash_algorithm, number_of_random_parameters: int) -> None:
        self.__hash_algorithm = hash_algorithm
        self.__number_of_random_parameters = number_of_random_parameters
        self.hkdf_obj = Hkdf(self.__hash_algorithm)

    def get_multiple_random_input_parameters_for_hkdf(self, number_of_parameters_to_be_generated: int) -> list[bytes]:
        """
        Generates a list of seeds (SKMs).
        """
        list_of_seeds: list[bytes] = [generate_random_input_parameter_for_hkdf(
            self.__hash_algorithm.__name__) for _ in range(number_of_parameters_to_be_generated)]
        return list_of_seeds

    def generate_random_outputs_from_hkdf_extract_for_sound_idealization(self, list_of_seeds: list[bytes]) -> list[bytes]:
        """ 
        Generates multiple pseudo random keys from HKDF extract call.

        Parameters
        ----------

        list_of_seeds : list[bytes]
                        This is the same list of seeds (SKMs) obtained
                        from the method "get_multiple_random_input_parameters_for_hkdf()".

        Returns
        -------

        A list of pseudo random keys (PRKs) as output.
        """
        list_of_pseudo_random_keys: list[bytes] = []
        for seed in list_of_seeds:
            pseudo_random_key: bytes = self.hkdf_obj.hkdf_extract(None, seed)
            list_of_pseudo_random_keys.append(pseudo_random_key)
        return list_of_pseudo_random_keys

    def generate_random_outputs_from_hkdf_expand_for_sound_idealization(self, list_of_pseudo_random_keys: list[bytes]) -> list[bytes]:
        """
        Generates a list of random outputs from HKDF expand call.

        Parameters
        ----------

        list_of_pseudo_random_keys : list[bytes]
                                     This is the same list of pseudo random keys obtained from the method 
                                     "generate_random_outputs_from_hkdf_extract_for_sound_idealization()".
        Returns
        -------

        A list of random outputs.
        """
        list_of_random_outputs_from_hkdf: list[bytes] = []
        for pseudo_random_key in list_of_pseudo_random_keys:
            total_output_from_hkdf: bytes = self.hkdf_obj.hkdf_expand(
                pseudo_random_key, None, DESIRED_OUTPUT_LENGTH)
            list_of_random_outputs_from_hkdf.append(total_output_from_hkdf)
        return list_of_random_outputs_from_hkdf

    def check_for_entropy_loss(self, list_of_corresponding_inputs: list[bytes], list_of_random_outputs_from_hkdf: list[bytes]) -> None:
        check_injectivity_for_idealizations(
            list_of_corresponding_inputs, list_of_random_outputs_from_hkdf)
        print(f"\t\t The cryptographic primitive is injective because no collisions have been found after testing {
              self.__number_of_random_parameters} input parameters and their corresponding outputs.")
