from typing import Tuple, Union
from hashlib import sha256, sha512, sha3_256, sha3_512, shake_128, shake_256
import time
from ascon._ascon import ascon_hash as ascon_xof
from keychains.prg_keychain import PrgKeyChain
from keychains.xdrbg_keychain import ShakeXdrbgKeychain, AsconXdrbgKeychain
from keychains.hkdf_keychain import HkdfKeyChain
from keychains.utils import generate_random_input_parameter_for_prg, generate_random_input_parameter_for_hkdf, generate_random_input_parameter_for_xdrbg, \
    get_standard_deviation_of_execution_times, get_confidence_intervals_of_execution_times, total_time_taken_for_generating_random_input_parameter_for_hkdf, \
    total_time_taken_for_generating_random_input_parameter_for_prg, total_time_taken_for_generating_random_input_parameter_for_xdrbg

NUMBER_OF_KEY_CHAINS: int = 100
NUMBER_OF_KEYS_IN_A_KEY_CHAIN: int = 100
CONFIDENCE_LEVEL: float = 0.95


def calculate_execution_times_of_generating_key_chains(key_chain_obj: Union[PrgKeyChain, ShakeXdrbgKeychain, AsconXdrbgKeychain, HkdfKeyChain],
                                                       initial_state_to_start_the_key_chain: bytes, *args) -> list[float]:

    individual_execution_time_of_generating_each_key_chain: list[float] = []
    arbitrary_input_parameter: bytes
    current_state_of_the_key_chain: bytes = initial_state_to_start_the_key_chain

    for _ in range(0, NUMBER_OF_KEY_CHAINS):
        start_time = time.time()
        for _ in range(NUMBER_OF_KEYS_IN_A_KEY_CHAIN):
            if isinstance(key_chain_obj, PrgKeyChain):
                security_parameter_lambda: int = args[0]
                arbitrary_input_parameter = generate_random_input_parameter_for_prg(
                    security_parameter_lambda)
                current_state_of_the_key_chain, random_output = key_chain_obj.key_chain_update(
                    arbitrary_input_parameter, current_state_of_the_key_chain)
            elif isinstance(key_chain_obj, ShakeXdrbgKeychain) or isinstance(key_chain_obj, AsconXdrbgKeychain):
                xof_name: str = args[0]
                arbitrary_input_parameter = generate_random_input_parameter_for_xdrbg(
                    xof_name)
                current_state_of_the_key_chain, random_output = key_chain_obj.key_chain_update(
                    arbitrary_input_parameter, current_state_of_the_key_chain)
            elif isinstance(key_chain_obj, HkdfKeyChain):
                hash_func_name: str = args[0]
                arbitrary_input_parameter = generate_random_input_parameter_for_hkdf(
                    hash_func_name)
                current_state_of_the_key_chain, random_output = key_chain_obj.key_chain_update(
                    arbitrary_input_parameter, current_state_of_the_key_chain)

        end_time = time.time()
        time_taken_for_each_key_chain = end_time - start_time
        individual_execution_time_of_generating_each_key_chain.append(
            time_taken_for_each_key_chain)

    return individual_execution_time_of_generating_each_key_chain


def get_average_execution_time_and_standard_deviation_and_confidence_intervals(individual_execution_time_of_generating_each_key_chain:
                                                                               list[float]) -> Tuple[float, float, Tuple[float, float]]:

    average_execution_time: float = sum(
        individual_execution_time_of_generating_each_key_chain)/NUMBER_OF_KEY_CHAINS

    average_execution_time_rounded_off: float = round(
        average_execution_time, 4)

    standard_deviation_of_execution_times: float = get_standard_deviation_of_execution_times(
        individual_execution_time_of_generating_each_key_chain, average_execution_time)

    standard_deviation_of_execution_times_rounded_off: float = round(
        standard_deviation_of_execution_times, 4)

    confidence_intervals = get_confidence_intervals_of_execution_times(
        CONFIDENCE_LEVEL, average_execution_time, standard_deviation_of_execution_times, NUMBER_OF_KEY_CHAINS)

    confidence_intervals_rounded_off = (
        round(confidence_intervals[0], 4), round(confidence_intervals[1], 4))

    return (average_execution_time_rounded_off, standard_deviation_of_execution_times_rounded_off, confidence_intervals_rounded_off)


def benchmark_for_prg_keychain(store_persistently: bool, security_parameter_lambda: int) -> None:

    prg_key_chain = PrgKeyChain(security_parameter_lambda, store_persistently)
    initial_seed_for_prg_refreshing: bytes = generate_random_input_parameter_for_prg(
        security_parameter_lambda)
    initial_state_of_key_chain_using_prg: bytes = prg_key_chain.key_chain_instantiate(
        initial_seed_for_prg_refreshing)

    individual_execution_time_of_generating_each_prg_key_chain = calculate_execution_times_of_generating_key_chains(
        prg_key_chain, initial_state_of_key_chain_using_prg, security_parameter_lambda)

    total_output_data = get_average_execution_time_and_standard_deviation_and_confidence_intervals(
        individual_execution_time_of_generating_each_prg_key_chain)

    average_time_for_prg_keychain = total_output_data[0]
    standard_deviation_for_prg_keychain = total_output_data[1]
    confidence_intervals_of_execution_times_for_prg_keychain = total_output_data[2]

    average_time_taken_for_generation_of_input_parameters: float = round(
        (sum(total_time_taken_for_generating_random_input_parameter_for_prg[1:])/NUMBER_OF_KEY_CHAINS), 4)
    total_time_taken_for_generating_random_input_parameter_for_prg.clear()

    difference_of_the_average_timings = round(
        (average_time_for_prg_keychain - average_time_taken_for_generation_of_input_parameters), 4)

    print(f"\t\t\033[1;32m Average execution time for security parameter λ = {
          security_parameter_lambda}: {average_time_for_prg_keychain} seconds\033[0m")
    print(f"\t\t\033[1;33m Standard deviation for security parameter λ = {
          security_parameter_lambda}: {standard_deviation_for_prg_keychain}\033[0m")
    print(f"\t\t\033[1;34m Confidence intervals for security parameter λ = {
          security_parameter_lambda}: {confidence_intervals_of_execution_times_for_prg_keychain}\033[0m")
    print(f"\t\t\033[1;35m Average time taken to generate the arbitrary input parameters for security parameter λ = {
          security_parameter_lambda}: {average_time_taken_for_generation_of_input_parameters} seconds\033[0m")
    print(f"\t\t\033[1;36m Average execution time for only the cryptographic operations: {
          difference_of_the_average_timings} seconds\033[0m \n")


def benchmark_for_shake_xdrbg_keychain(xof, store_persistently: bool, xof_name: str) -> None:

    shake_xdrbg_key_chain = ShakeXdrbgKeychain(xof, store_persistently)
    seed_for_xdrbg_instantiate: bytes = generate_random_input_parameter_for_xdrbg(
        xof.name)
    initial_state_of_key_chain_using_shake_based_xdrbg: bytes = shake_xdrbg_key_chain.key_chain_instantiate(
        seed_for_xdrbg_instantiate)

    individual_execution_time_of_generating_each_shake_xdrbg_key_chain = calculate_execution_times_of_generating_key_chains(
        shake_xdrbg_key_chain, initial_state_of_key_chain_using_shake_based_xdrbg, xof.name)

    total_output_data = get_average_execution_time_and_standard_deviation_and_confidence_intervals(
        individual_execution_time_of_generating_each_shake_xdrbg_key_chain)

    average_time_for_shake_xdrbg_keychain = total_output_data[0]
    standard_deviation_for_shake_xdrbg_keychain = total_output_data[1]
    confidence_intervals_of_execution_times_for_shake_xdrbg_key_chain = total_output_data[2]

    average_time_taken_for_generation_of_input_parameters: float = round(
        (sum(total_time_taken_for_generating_random_input_parameter_for_xdrbg[1:])/NUMBER_OF_KEY_CHAINS), 4)
    total_time_taken_for_generating_random_input_parameter_for_xdrbg.clear()

    difference_of_the_average_timings = round(
        (average_time_for_shake_xdrbg_keychain - average_time_taken_for_generation_of_input_parameters), 4)

    print(f"\t\t\033[1;32m Average execution time when using {xof_name}: {
          average_time_for_shake_xdrbg_keychain} seconds\033[0m")
    print(f"\t\t\033[1;33m Standard deviation when using {xof_name}: {
          standard_deviation_for_shake_xdrbg_keychain}\033[0m")
    print(f"\t\t\033[1;34m Confidence intervals when using {xof_name}: {
          confidence_intervals_of_execution_times_for_shake_xdrbg_key_chain}\033[0m")
    print(f"\t\t\033[1;35m Average time taken to generate the arbitrary input parameters when using {
          xof_name}: {average_time_taken_for_generation_of_input_parameters} seconds\033[0m")
    print(f"\t\t\033[1;36m Average execution time for only the cryptographic operations: {
          difference_of_the_average_timings} seconds\033[0m \n")


def benchmark_for_hkdf_keychain(hash_func, store_persistently: bool, hash_function_digest_size: int, hash_function_name: str) -> None:

    hkdf_key_chain = HkdfKeyChain(hash_func, store_persistently)
    initial_source_key_material: bytes = generate_random_input_parameter_for_hkdf(
        hash_func.__name__)
    initial_state_of_key_chain_using_hkdf: bytes = hkdf_key_chain.key_chain_instantiate(
        initial_source_key_material)

    individual_execution_time_of_generating_each_hkdf_key_chain = calculate_execution_times_of_generating_key_chains(
        hkdf_key_chain, initial_state_of_key_chain_using_hkdf, hash_func.__name__, hash_function_digest_size)

    total_output_data = get_average_execution_time_and_standard_deviation_and_confidence_intervals(
        individual_execution_time_of_generating_each_hkdf_key_chain)

    average_time_for_hkdf_keychain = total_output_data[0]
    standard_deviation_for_hkdf_keychain = total_output_data[1]
    confidence_intervals_of_execution_times_for_hkdf_keychain = total_output_data[2]

    average_time_taken_for_generation_of_input_parameters: float = round(
        (sum(total_time_taken_for_generating_random_input_parameter_for_hkdf[1:])/NUMBER_OF_KEY_CHAINS), 4)
    total_time_taken_for_generating_random_input_parameter_for_hkdf.clear()

    difference_of_the_average_timings = round(
        (average_time_for_hkdf_keychain - average_time_taken_for_generation_of_input_parameters), 4)

    print(f"\t\t\033[1;32m Average execution time when using {
          hash_function_name}: {average_time_for_hkdf_keychain} seconds\033[0m")
    print(f"\t\t\033[1;33m Standard deviation when using {
          hash_function_name}: {standard_deviation_for_hkdf_keychain}\033[0m")
    print(f"\t\t\033[1;34m Confidence intervals when using {hash_function_name}: {
          confidence_intervals_of_execution_times_for_hkdf_keychain}\033[0m")
    print(f"\t\t\033[1;35m Average time taken to generate the arbitrary input parameters when using {
          hash_function_name}: {average_time_taken_for_generation_of_input_parameters} seconds\033[0m")
    print(f"\t\t\033[1;36m Average execution time for only the cryptographic operations: {
          difference_of_the_average_timings} seconds\033[0m \n")


def conduct_all_benchmarks(store_persistently: bool):

    if store_persistently:
        print(
            f"\033[1;31m Conducting benchmarks for generating {NUMBER_OF_KEY_CHAINS} key chains while persistently storing in the database:\033[0m")
    else:
        print(
            f"\033[1;31m Conducting benchmarks for generating {NUMBER_OF_KEY_CHAINS} key chains without persistently storing in the database:\033[0m")

    # Benchmark For HKDF Keychain
    print("\t Benchmark For HKDF KeyChain:")
    benchmark_for_hkdf_keychain(
        sha256, store_persistently, sha256().digest_size, "SHA256")
    benchmark_for_hkdf_keychain(
        sha3_256, store_persistently, sha3_256().digest_size, "SHA3-256")
    benchmark_for_hkdf_keychain(
        sha512, store_persistently, sha512().digest_size, "SHA512")
    benchmark_for_hkdf_keychain(
        sha3_512, store_persistently, sha3_512().digest_size, "SHA3-512")

    # Benchmark For Shake XDRBG Keychain
    print("\t Benchmark For Shake XDRBG KeyChain:")
    benchmark_for_shake_xdrbg_keychain(
        shake_128(), store_persistently, "SHAKE128")
    benchmark_for_shake_xdrbg_keychain(
        shake_256(), store_persistently, "SHAKE256")

    # Benchmark For Ascon XDRBG Keychain
    ascon_xdrbg_key_chain = AsconXdrbgKeychain(ascon_xof, store_persistently)
    seed_for_xdrbg_instantiate = generate_random_input_parameter_for_xdrbg(
        "Ascon-Xof")
    initial_state_of_key_chain_using_ascon_based_xdrbg = ascon_xdrbg_key_chain.key_chain_instantiate(
        seed_for_xdrbg_instantiate)

    print("\t Benchmark For ASCON XDRBG KeyChain:")

    individual_execution_time_of_generating_each_ascon_xdrbg_key_chain = calculate_execution_times_of_generating_key_chains(
        ascon_xdrbg_key_chain, initial_state_of_key_chain_using_ascon_based_xdrbg, "Ascon-Xof")

    total_output_data = get_average_execution_time_and_standard_deviation_and_confidence_intervals(
        individual_execution_time_of_generating_each_ascon_xdrbg_key_chain)

    average_time_for_ascon_xdrbg_keychain = total_output_data[0]
    standard_deviation_for_ascon_xdrbg_keychain = total_output_data[1]
    confidence_intervals_of_execution_times_for_ascon_xdrbg_key_chain = total_output_data[2]

    average_time_taken_for_generation_of_input_parameters: float = round(
        (sum(total_time_taken_for_generating_random_input_parameter_for_xdrbg[1:])/NUMBER_OF_KEY_CHAINS), 4)
    total_time_taken_for_generating_random_input_parameter_for_xdrbg.clear()

    difference_of_the_average_timings = round(
        (average_time_for_ascon_xdrbg_keychain - average_time_taken_for_generation_of_input_parameters), 4)

    print(f"\t\t\033[1;32m Average execution time: {
          average_time_for_ascon_xdrbg_keychain} seconds\033[0m")
    print(f"\t\t\033[1;33m Standard deviation: {
          standard_deviation_for_ascon_xdrbg_keychain}\033[0m")
    print(f"\t\t\033[1;34m Confidence intervals: {
          confidence_intervals_of_execution_times_for_ascon_xdrbg_key_chain}\033[0m")
    print(f"\t\t\033[1;35m Average time taken to generate the arbitrary input parameters: {
          average_time_taken_for_generation_of_input_parameters} seconds\033[0m")
    print(f"\t\t\033[1;36m Average execution time for only the cryptographic operations: {
          difference_of_the_average_timings} seconds\033[0m \n")

    # Benchmark For PRG Keychain
    print("\t Benchmark For PRG KeyChain:")
    benchmark_for_prg_keychain(store_persistently, 16)
    benchmark_for_prg_keychain(store_persistently, 24)
    benchmark_for_prg_keychain(store_persistently, 32)


def main() -> None:

    conduct_all_benchmarks(store_persistently=False)
    conduct_all_benchmarks(store_persistently=True)


if __name__ == "__main__":
    main()
