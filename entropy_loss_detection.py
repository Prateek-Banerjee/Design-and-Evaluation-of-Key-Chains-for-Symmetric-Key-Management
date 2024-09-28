from hashlib import sha256, sha3_256, sha512, sha3_512, shake_128, shake_256
from typing import Union
from ascon._ascon import ascon_hash as ascon_xof
from entropylossdetection.detection_in_hkdf import HkdfDetection
from entropylossdetection.detection_in_xdrbg import XdrbgDetection
from entropylossdetection.detection_in_prg import PrgDetection

NUMBER_OF_RANDOM_PARAMETERS: int = 2**21


def entropy_loss_detection_for_hkdf(hash_algorithm):
    hkdf_detection_obj = HkdfDetection(
        hash_algorithm, NUMBER_OF_RANDOM_PARAMETERS)
    list_of_seeds: list[bytes] = hkdf_detection_obj.get_multiple_random_input_parameters_for_hkdf(NUMBER_OF_RANDOM_PARAMETERS)
    list_of_pseudo_random_keys: list[bytes] = hkdf_detection_obj.generate_random_outputs_from_hkdf_extract_for_sound_idealization(
        list_of_seeds)
    list_of_random_outputs_from_hkdf: list[bytes] = hkdf_detection_obj.generate_random_outputs_from_hkdf_expand_for_sound_idealization(
        list_of_pseudo_random_keys)
    print(f"\033[1;33m Sound Idealization for {
          hash_algorithm.__name__} as the cryptographic primitive:\033[0m")
    print(
        "\t\033[1;32m Checking injectivity between list of source key materials as inputs and list of pseudo random keys as outputs:\033[0m")
    hkdf_detection_obj.check_for_entropy_loss(
        list_of_seeds, list_of_pseudo_random_keys)
    print(
        "\t\033[1;32m Checking injectivity between list of pseudo random keys as inputs and list of random outputs:\033[0m")
    hkdf_detection_obj.check_for_entropy_loss(
        list_of_pseudo_random_keys, list_of_random_outputs_from_hkdf)


def entropy_loss_detection_for_xdrbg(xof, xof_name: Union[str, None] = None):
    if xof_name is not None:
        xdrbg_detection_obj = XdrbgDetection(
            xof, NUMBER_OF_RANDOM_PARAMETERS, xof_name)
    else:
        xdrbg_detection_obj = XdrbgDetection(
            xof, NUMBER_OF_RANDOM_PARAMETERS)
        xof_name = xof.name

    list_of_seeds: list[bytes] = xdrbg_detection_obj.get_multiple_random_input_parameters_for_xdrbg(NUMBER_OF_RANDOM_PARAMETERS)
    list_of_initial_xdrbg_state: list[bytes] = xdrbg_detection_obj.generate_random_outputs_from_xdrbg_instantiate_for_sound_idealization(
        list_of_seeds)
    list_of_reseeded_xdrbg_state_for_sound_idealization: list[bytes] = xdrbg_detection_obj.generate_random_outputs_from_xdrbg_reseed_for_sound_idealization(
        list_of_seeds)
    list_of_reseeded_xdrbg_state_for_unsound_idealization: list[bytes] = xdrbg_detection_obj.generate_random_outputs_from_xdrbg_reseed_for_unsound_idealization(
        list_of_seeds)
    list_of_random_outputs_from_xdrbg, list_of_the_corresponding_xdrbg_states = xdrbg_detection_obj.generate_random_outputs_from_xdrbg_generate_for_sound_idealization()
    print(f"\033[1;33m Sound Idealization for {
          xof_name} as the cryptographic primitive:\033[0m")
    print(
        "\t\033[1;32m Checking injectivity between list of seeds for xdrbg_instantiate as inputs and list of initial xdrbg states as outputs:\033[0m")
    xdrbg_detection_obj.check_for_entropy_loss(
        list_of_seeds, list_of_initial_xdrbg_state)
    print(
        "\t\033[1;32m Checking injectivity between list of seeds for xdrbg_reseed as inputs and list of reseeded xdrbg states as outputs:\033[0m")
    xdrbg_detection_obj.check_for_entropy_loss(
        list_of_seeds, list_of_reseeded_xdrbg_state_for_sound_idealization)
    print(
        "\t\033[1;32m Checking injectivity between list of xdrbg states for xdrbg_generate as inputs and list of random outputs:\033[0m")
    xdrbg_detection_obj.check_for_entropy_loss(
        list_of_the_corresponding_xdrbg_states, list_of_random_outputs_from_xdrbg)
    print(f"\033[1;33m Unsound Idealization for {
          xof_name} as the cryptographic primitive:\033[0m")
    print(
        "\t\033[1;32m Checking injectivity between list of seeds for xdrbg_reseed as inputs and list of reseeded xdrbg states as outputs:\033[0m")
    xdrbg_detection_obj.check_for_entropy_loss(
        list_of_seeds, list_of_reseeded_xdrbg_state_for_unsound_idealization)


def entropy_loss_detection_for_prg(security_parameter_lambda: int):
    prg_detection_obj = PrgDetection(
        security_parameter_lambda, NUMBER_OF_RANDOM_PARAMETERS)
    list_of_seeds: list[bytes] = prg_detection_obj.get_multiple_random_input_parameters_for_prg(NUMBER_OF_RANDOM_PARAMETERS)
    list_of_refreshed_prg_state_for_sound_idealization: list[bytes] = prg_detection_obj.generate_random_outputs_from_prg_refresh_for_sound_idealization(
        list_of_seeds)
    list_of_refreshed_prg_state_for_unsound_idealization: list[bytes] = prg_detection_obj.generate_random_outputs_from_prg_refresh_for_unsound_idealization(
        list_of_seeds)
    list_of_random_outputs_from_prg, list_of_the_corresponding_prg_states = prg_detection_obj.generate_random_outputs_from_prg_next_for_sound_idealization()
    print(f"\033[1;33m Sound Idealization for the security parameter λ = {
          security_parameter_lambda} as the cryptographic primitive:\033[0m")
    print(
        "\t\033[1;32m Checking injectivity between list of seeds for prg_refresh as inputs and list of refreshed prg states as outputs:\033[0m")
    prg_detection_obj.check_for_entropy_loss(
        list_of_seeds, list_of_refreshed_prg_state_for_sound_idealization)
    print(
        "\t\033[1;32m Checking injectivity between list of prg states for prg_next as inputs and list of random outputs:\033[0m")
    prg_detection_obj.check_for_entropy_loss(
        list_of_the_corresponding_prg_states, list_of_random_outputs_from_prg)
    print(f"\033[1;33m Unsound Idealization for the security parameter λ = {
          security_parameter_lambda} as the cryptographic primitive:\033[0m")
    print(
        "\t\033[1;32m Checking injectivity between list of seeds for prg_refresh as inputs and list of refreshed prg states as outputs:\033[0m")
    prg_detection_obj.check_for_entropy_loss(
        list_of_seeds, list_of_refreshed_prg_state_for_unsound_idealization)


def main():
    # Detection of Entropy Loss in HKDF
    entropy_loss_detection_for_hkdf(sha256)
    entropy_loss_detection_for_hkdf(sha3_256)
    entropy_loss_detection_for_hkdf(sha512)
    entropy_loss_detection_for_hkdf(sha3_512)

    # Detection of Entropy Loss in XDRBG
    entropy_loss_detection_for_xdrbg(shake_128())
    entropy_loss_detection_for_xdrbg(shake_256())
    entropy_loss_detection_for_xdrbg(ascon_xof, "Ascon-Xof")

    # Detection of Entropy Loss in PRG
    entropy_loss_detection_for_prg(16)
    entropy_loss_detection_for_prg(24)
    entropy_loss_detection_for_prg(32)


if __name__ == "__main__":
    main()
