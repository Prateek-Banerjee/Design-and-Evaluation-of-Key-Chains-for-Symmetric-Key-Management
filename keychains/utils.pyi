from typing import Tuple, Union

total_time_taken_for_generating_random_input_parameter_for_hkdf: list[float] = [
]
total_time_taken_for_generating_random_input_parameter_for_xdrbg: list[float] = [
]
total_time_taken_for_generating_random_input_parameter_for_prg: list[float] = [
]


def bits_to_bytes(list_of_bits: list[int]) -> bytes: ...
def generate_random_input_parameter_for_hkdf(hash_func_name: str) -> bytes: ...
def generate_random_input_parameter_for_prg(
    security_parameter_lambda: int) -> bytes: ...


def generate_random_input_parameter_for_xdrbg(xof_name: str) -> bytes: ...


def store_persistent_derivation_parameter(
    state_of_key_chain_to_be_persistently_stored: bytes, extra_parameter: Union[str, int]) -> None: ...


def get_standard_deviation_of_execution_times(
    all_individual_execution_times: list[float], average_execution_time: float) -> float: ...


def get_confidence_intervals_of_execution_times(confidence_level: float, average_execution_time: float,
                                                standard_deviation_of_execution_times: float, length_of_dataset: int) -> Tuple[float, float]: ...


def fetch_persistent_derivation_parameter(
    fetch_state_of_the_key_chain_for_specification: Union[str, int]) -> bytes: ...
