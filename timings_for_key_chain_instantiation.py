from hashlib import sha256, sha512, sha3_256, sha3_512, shake_128, shake_256
from typing import Union
from timeit import timeit
from ascon._ascon import ascon_hash as ascon_xof
from keychains.prg_keychain import PrgKeyChain
from keychains.xdrbg_keychain import ShakeXdrbgKeychain, AsconXdrbgKeychain
from keychains.hkdf_keychain import HkdfKeyChain
from keychains.utils import generate_random_input_parameter_for_prg, generate_random_input_parameter_for_hkdf, generate_random_input_parameter_for_xdrbg

NUMBER_OF_ITERATIONS: int = 100


def calculate_average_execution_times_for_key_chain_instantiation(key_chain_obj: Union[PrgKeyChain, ShakeXdrbgKeychain, AsconXdrbgKeychain, HkdfKeyChain],
                                                                  initial_input_parameter: bytes) -> float:

    def wrapped_instantiate_call():
        return key_chain_obj.key_chain_instantiate(initial_input_parameter)

    total_time_taken: float = timeit(
        wrapped_instantiate_call, number=NUMBER_OF_ITERATIONS)
    average_execution_time_for_instantiation = total_time_taken/NUMBER_OF_ITERATIONS
    return average_execution_time_for_instantiation


def get_average_execution_time_for_prg_key_chain(security_parameter_lambda: int):
    prg_key_chain = PrgKeyChain(security_parameter_lambda)
    seed_for_prg_refreshing: bytes = generate_random_input_parameter_for_prg(
        security_parameter_lambda)
    average_execution_time: float = calculate_average_execution_times_for_key_chain_instantiation(
        prg_key_chain, seed_for_prg_refreshing)
    print(f"\t \033[1;32m Average time for key chain instantiation for security parameter λ = {
          security_parameter_lambda}: {average_execution_time:.6f} seconds\033[0m")


def get_average_execution_time_for_xdrbg_key_chain(xof, xof_name: Union[str, None] = None):
    xdrbg_key_chain: Union[AsconXdrbgKeychain, ShakeXdrbgKeychain]
    if xof_name is not None:
        xdrbg_key_chain = AsconXdrbgKeychain(xof)
    else:
        xdrbg_key_chain = ShakeXdrbgKeychain(xof)
        xof_name = xof.name
    seed_for_xdrbg_instantiate: bytes = generate_random_input_parameter_for_xdrbg(
        xof_name)
    average_execution_time: float = calculate_average_execution_times_for_key_chain_instantiation(
        xdrbg_key_chain, seed_for_xdrbg_instantiate)
    print(f"\t \033[1;32m Average time for key chain instantiation using {
          xof_name}: {average_execution_time:.6f} seconds\033[0m")


def get_average_execution_time_for_hkdf_key_chain(hash_func):
    hkdf_key_chain = HkdfKeyChain(hash_func)
    initial_source_key_material: bytes = generate_random_input_parameter_for_hkdf(
        hash_func.__name__)
    average_execution_time: float = calculate_average_execution_times_for_key_chain_instantiation(
        hkdf_key_chain, initial_source_key_material)
    print(f"\t \033[1;32m Average time for key chain instantiation using {
          hash_func.__name__}: {average_execution_time:.6f} seconds\033[0m")


def main() -> None:

    # Benchmark for HKDF Key Chain Instantiation
    print("\033[1;33m For HKDF KeyChain:\033[0m")
    get_average_execution_time_for_hkdf_key_chain(sha256)
    get_average_execution_time_for_hkdf_key_chain(sha3_256)
    get_average_execution_time_for_hkdf_key_chain(sha512)
    get_average_execution_time_for_hkdf_key_chain(sha3_512)

    # Benchmark for XDRBG Key Chain Instantiation
    print("\033[1;33m For XDRBG KeyChain:\033[0m")
    get_average_execution_time_for_xdrbg_key_chain(shake_128())
    get_average_execution_time_for_xdrbg_key_chain(shake_256())
    get_average_execution_time_for_xdrbg_key_chain(ascon_xof, "Ascon-Xof")

    # Benchmark for PRG Key Chain Instantiation
    print("\033[1;33m For PRG KeyChain:\033[0m")
    get_average_execution_time_for_prg_key_chain(16)
    get_average_execution_time_for_prg_key_chain(24)
    get_average_execution_time_for_prg_key_chain(32)


if __name__ == "__main__":
    main()
