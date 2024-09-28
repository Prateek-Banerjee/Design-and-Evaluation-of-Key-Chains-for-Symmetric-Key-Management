from math import sqrt
from statistics import stdev
from typing import Tuple, Union
import inspect
import random
import sqlite3
import time
from scipy.stats import norm
from cryptomite.circulant import Circulant


total_time_taken_for_generating_random_input_parameter_for_hkdf: list[float] = [
]
total_time_taken_for_generating_random_input_parameter_for_xdrbg: list[float] = [
]
total_time_taken_for_generating_random_input_parameter_for_prg: list[float] = [
]


def bits_to_bytes(list_of_bits: list[int]) -> bytes:
    """
    This methods takes a list of 0's and 1's and
    generates its corresponding byte value.

    Parameters
    ----------

    list_of_bits : list[int]

    Returns
    -------
    The byte value of the corresponding list of bits.
    """

    # Check if the provided list is a multiple of 8 or not
    if len(list_of_bits) % 8 != 0:
        raise ValueError(f"The provided list of bits is {
                         len(list_of_bits)}, which is not a multiple of 8.")

    all_integer_conversions: list[int] = []

    # The outer loop steps over 8 bits, i.e. 1 byte. In each iteration of
    # the outer loop the inner loop iterates over the 8 bits. In each
    # iteration of the inner loop, it shifts the current integer representation
    # 1 bit to the left and adds the next bit and it keeps on doing the same
    # until the whole integer representation of the 8 bits is generated.

    for i in range(0, len(list_of_bits), 8):
        integer_representation: int = 0
        for bit in list_of_bits[i:i+8]:
            integer_representation = (integer_representation << 1) | bit
        all_integer_conversions.append(integer_representation)

    return bytes(all_integer_conversions)


def generate_random_input_parameter_for_hkdf(hash_func_name: str) -> bytes:
    # global total_time_taken_for_generating_random_input_parameter_for_hkdf
    start_time = time.time()

    if hash_func_name == "openssl_sha3_256" or hash_func_name == "openssl_sha256":
        # Length of output parameter will 32 bytes (256 bits)
        circulant_obj = Circulant(256, 256)
    elif hash_func_name == "openssl_sha3_512" or hash_func_name == "openssl_sha512":
        # Length of output parameter will 64 bytes (512 bits)
        circulant_obj = Circulant(512, 512)

    extractor_input_parameter_1: list[int] = [
        random.randint(0, 1) for _ in range(circulant_obj.n)
    ]
    extractor_input_parameter_2: list[int] = [
        random.randint(0, 1) for _ in range(circulant_obj.n + 1)
    ]

    extracted_output_bits = circulant_obj.extract(
        extractor_input_parameter_1, extractor_input_parameter_2)

    extracted_output_bits_in_bytes: bytes = bits_to_bytes(
        extracted_output_bits)
    end_time = time.time()

    total_time_taken_for_generating_random_input_parameter_for_hkdf.append(
        end_time-start_time)
    return extracted_output_bits_in_bytes


def generate_random_input_parameter_for_prg(security_parameter_lambda: int) -> bytes:
    # global total_time_taken_for_generating_random_input_parameter_for_prg
    start_time = time.time()

    # If security parameter λ = 16, then length of output parameter will be 16 bytes (128 bits)
    # If security parameter λ = 24, then length of output parameter will be 24 bytes (192 bits)
    # If security parameter λ = 32, then length of output parameter will be 32 bytes (256 bits)
    circulant_obj = Circulant(
        security_parameter_lambda*8, security_parameter_lambda*8)

    extractor_input_parameter_1: list[int] = [
        random.randint(0, 1) for _ in range(circulant_obj.n)
    ]
    extractor_input_parameter_2: list[int] = [
        random.randint(0, 1) for _ in range(circulant_obj.n + 1)
    ]

    extracted_output_bits = circulant_obj.extract(
        extractor_input_parameter_1, extractor_input_parameter_2)

    extracted_output_bits_in_bytes: bytes = bits_to_bytes(
        extracted_output_bits)
    end_time = time.time()

    total_time_taken_for_generating_random_input_parameter_for_prg.append(
        end_time - start_time)
    return extracted_output_bits_in_bytes


def generate_random_input_parameter_for_xdrbg(xof_name: str) -> bytes:
    # global total_time_taken_for_generating_random_input_parameter_for_xdrbg
    start_time = time.time()

    if xof_name == "shake_128" or xof_name == "Ascon-Xof":
        # Length of output parameter will 24 bytes (192 bits)
        circulant_obj = Circulant(192, 192)

    elif xof_name == "shake_256":
        # Length of output parameter will 48 bytes (384 bits)
        circulant_obj = Circulant(384, 384)

    else:
        raise NameError(f"Unexpected Invocation from {xof_name}.")

    extractor_input_parameter_1: list[int] = [
        random.randint(0, 1) for _ in range(circulant_obj.n)
    ]
    extractor_input_parameter_2: list[int] = [
        random.randint(0, 1) for _ in range(circulant_obj.n + 1)
    ]

    extracted_output_bits = circulant_obj.extract(
        extractor_input_parameter_1, extractor_input_parameter_2)

    extracted_output_bits_in_bytes: bytes = bits_to_bytes(
        extracted_output_bits)
    end_time = time.time()

    total_time_taken_for_generating_random_input_parameter_for_xdrbg.append(
        end_time-start_time)

    return extracted_output_bits_in_bytes


def store_persistent_derivation_parameter(state_of_key_chain_to_be_persistently_stored: bytes, extra_parameter: Union[str, int]) -> None:
    """
    This function persistently stores the state of the key chain in a database table
    based on the method from which it is invoked, i.e., it can be either invoked
    from the xdrbg.generate() or prg.next() or hkdf.expand() calls. When invoked
    from xdrbg.generate() it stores the xdrbg state, prg.expand() it stores the prg
    state, and hkdf.expand() it stores the hkdf state.

    Parameters
    ----------
    state_of_key_chain_to_be_persistently_stored : bytes
                                                   The persistent derivation parameter to be stored in
                                                   the database.

    extra_parameter : str or int
                      This parameter depends on the cryptographic primitive for which
                      the persistent derivation is being stored. If it is being stored
                      for the XDRBG, then this extra parameter will denote the XOF name.
                      If it is being stored for the PRG, then this extra parameter will
                      denote the security parameter lambda. If it is being stored for
                      the HKDF, then this extra parameter will denote the name of the
                      hash function.

    Returns
    -------
    None
    """

    method_invoker_name: str = inspect.stack()[1].function
    if isinstance(extra_parameter, str):
        if method_invoker_name == "xdrbg_generate_keys":
            store_persistent_derivation_parameter_for_xdrbg_based_key_chain(
                state_of_key_chain_to_be_persistently_stored, extra_parameter)
        elif method_invoker_name == "__hkdf_generate_keys":
            store_persistent_derivation_parameter_for_hkdf_based_key_chain(
                state_of_key_chain_to_be_persistently_stored, extra_parameter)
    elif isinstance(extra_parameter, int) and method_invoker_name == "__prg_generate_keys":
        store_persistent_derivation_parameter_for_prg_based_key_chain(
            state_of_key_chain_to_be_persistently_stored, extra_parameter)
    else:
        raise Exception(f"Invalid invocation from {method_invoker_name}.")


def store_persistent_derivation_parameter_for_hkdf_based_key_chain(state_of_key_chain_to_be_persistently_stored: bytes, extra_parameter: str) -> None:

    try:
        database_connection_object = sqlite3.connect(
            "persistent_derivation_storage.db")
    except sqlite3.Error as e:
        raise Exception(f"Failed to connect to the database: {e}")

    try:
        query_cursor = database_connection_object.cursor()

        if extra_parameter == "openssl_sha256":
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_hkdf_sha256 = (:persistent_derivation_for_hkdf_sha256)",
                {"persistent_derivation_for_hkdf_sha256": state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_hkdf_sha256) values (:persistent_derivation_for_hkdf_sha256)",
            #     {"persistent_derivation_for_hkdf_sha256": persistent_derivation},
            # )
            database_connection_object.commit()
        elif extra_parameter == "openssl_sha3_256":
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_hkdf_sha3_256 = (:persistent_derivation_for_hkdf_sha3_256)",
                {"persistent_derivation_for_hkdf_sha3_256": state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_hkdf_sha3_256) values (:persistent_derivation_for_hkdf_sha3_256)",
            #     {"persistent_derivation_for_hkdf_sha3_256": persistent_derivation},
            # )
            database_connection_object.commit()
        elif extra_parameter == "openssl_sha512":
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_hkdf_sha512 = (:persistent_derivation_for_hkdf_sha512)",
                {"persistent_derivation_for_hkdf_sha512": state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_hkdf_sha512) values (:persistent_derivation_for_hkdf_sha512)",
            #     {"persistent_derivation_for_hkdf_sha512": persistent_derivation},
            # )
            database_connection_object.commit()
        elif extra_parameter == "openssl_sha3_512":
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_hkdf_sha3_512 = (:persistent_derivation_for_hkdf_sha3_512)",
                {"persistent_derivation_for_hkdf_sha3_512": state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_hkdf_sha3_512) values (:persistent_derivation_for_hkdf_sha3_512)",
            #     {"persistent_derivation_for_hkdf_sha3_512": persistent_derivation},
            # )
            database_connection_object.commit()
        else:
            raise Exception(f"Invalid hash function {extra_parameter}.")
    finally:
        database_connection_object.close()


def store_persistent_derivation_parameter_for_prg_based_key_chain(state_of_key_chain_to_be_persistently_stored: bytes, extra_parameter: int) -> None:
    try:
        database_connection_object = sqlite3.connect(
            "persistent_derivation_storage.db")
    except sqlite3.Error as e:
        raise Exception(f"Failed to connect to the database: {e}")

    try:
        query_cursor = database_connection_object.cursor()
        if extra_parameter == 16:
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_prg_sec_param_16 = (:persistent_derivation_for_prg_sec_param_16)",
                {"persistent_derivation_for_prg_sec_param_16":
                    state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_prg_sec_param_16) values (:persistent_derivation_for_prg_sec_param_16)",
            #     {"persistent_derivation_for_prg_sec_param_16": persistent_derivation},
            # )
            database_connection_object.commit()
        elif extra_parameter == 24:
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_prg_sec_param_24 = (:persistent_derivation_for_prg_sec_param_24)",
                {"persistent_derivation_for_prg_sec_param_24":
                    state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_prg_sec_param_24) values (:persistent_derivation_for_prg_sec_param_24)",
            #     {"persistent_derivation_for_prg_sec_param_24": persistent_derivation},
            # )
            database_connection_object.commit()
        elif extra_parameter == 32:
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_prg_sec_param_32 = (:persistent_derivation_for_prg_sec_param_32)",
                {"persistent_derivation_for_prg_sec_param_32":
                    state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_prg_sec_param_32) values (:persistent_derivation_for_prg_sec_param_32)",
            #     {"persistent_derivation_for_prg_sec_param_32": persistent_derivation},
            # )
            database_connection_object.commit()
        else:
            raise ValueError(f"Invalid security parameter lambda {
                             extra_parameter}.")
    finally:
        database_connection_object.close()


def store_persistent_derivation_parameter_for_xdrbg_based_key_chain(state_of_key_chain_to_be_persistently_stored: bytes, extra_parameter: str) -> None:
    try:
        database_connection_object = sqlite3.connect(
            "persistent_derivation_storage.db")
    except sqlite3.Error as e:
        raise Exception(f"Failed to connect to the database: {e}")

    try:
        query_cursor = database_connection_object.cursor()
        if extra_parameter == "shake_128":
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_shake128_xdrbg = (:persistent_derivation_for_shake128_xdrbg)",
                {"persistent_derivation_for_shake128_xdrbg": state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_shake128_xdrbg) values (:persistent_derivation_for_shake128_xdrbg)",
            #     {"persistent_derivation_for_shake128_xdrbg": persistent_derivation},
            # )
            database_connection_object.commit()
        elif extra_parameter == "shake_256":
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_shake256_xdrbg = (:persistent_derivation_for_shake256_xdrbg)",
                {"persistent_derivation_for_shake256_xdrbg": state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_shake256_xdrbg) values (:persistent_derivation_for_shake256_xdrbg)",
            #     {"persistent_derivation_for_shake256_xdrbg": persistent_derivation},
            # )
            database_connection_object.commit()
        elif extra_parameter == "Ascon-Xof":
            query_cursor.execute(
                "Update persistent_derivation set persistent_derivation_for_ascon_xdrbg = (:persistent_derivation_for_ascon_xdrbg)",
                {"persistent_derivation_for_ascon_xdrbg": state_of_key_chain_to_be_persistently_stored},
            )

            # query_cursor.execute(
            #     "Insert into persistent_derivation(persistent_derivation_for_ascon_xdrbg) values (:persistent_derivation_for_ascon_xdrbg)",
            #     {"persistent_derivation_for_ascon_xdrbg": persistent_derivation},
            # )
            database_connection_object.commit()
        else:
            raise Exception(f"Invalid XOF name {extra_parameter}.")
    finally:
        database_connection_object.close()

# TODO If it is decided that we do not use the update query for storing the persistent_derivation_parameter above and
# instead use the insert query, then, the select query in the below method must also be changed accordingly so that it
# fetches the last known state of the key chain. Currently, as there is only one record for each of the columns in the
# table, that's why this simple select query works.


def fetch_persistent_derivation_parameter(fetch_state_of_the_key_chain_for_specification: Union[str, int]) -> bytes:
    """
    This method fetches the last known state of the key chain, so that it can
    be used for generating further cryptographic keys in the key chain.

    Parameters
    ----------

    fetch_state_of_the_key_chain_for_specification : str or int
                                                     This parameter denotes that for which specification of the
                                                     cryptographic primitive the state of the key chain must be
                                                     fetched for. This parameter can only accept shake_128,
                                                     shake_256, Ascon-Xof, openssl_sha256, openssl_sha3_256, 
                                                     openssl_sha512, and openssl_sha3_512 as string values and 
                                                     16, 24 and 32 as integer values.

    Returns
    -------

    The last known (secure) state of the key chain in bytes.
    """

    try:
        database_connection_object = sqlite3.connect(
            "persistent_derivation_storage.db")
    except sqlite3.Error as e:
        raise Exception(f"Failed to connect to the database: {e}")

    try:
        query_cursor = database_connection_object.cursor()

        match fetch_state_of_the_key_chain_for_specification:
            case "shake_128":
                output = query_cursor.execute(
                    "Select persistent_derivation_for_shake128_xdrbg from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case "shake_256":
                output = query_cursor.execute(
                    "Select persistent_derivation_for_shake256_xdrbg from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case "Ascon-Xof":
                output = query_cursor.execute(
                    "Select persistent_derivation_for_ascon_xdrbg from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case 16:
                output = query_cursor.execute(
                    "Select persistent_derivation_for_prg_sec_param_16 from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case 24:
                output = query_cursor.execute(
                    "Select persistent_derivation_for_prg_sec_param_24 from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case 32:
                output = query_cursor.execute(
                    "Select persistent_derivation_for_prg_sec_param_32 from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case "openssl_sha256":
                output = query_cursor.execute(
                    "Select persistent_derivation_for_hkdf_sha256 from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case "openssl_sha3_256":
                output = query_cursor.execute(
                    "Select persistent_derivation_for_hkdf_sha3_256 from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case "openssl_sha512":
                output = query_cursor.execute(
                    "Select persistent_derivation_for_hkdf_sha512 from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case "openssl_sha3_512":
                output = query_cursor.execute(
                    "Select persistent_derivation_for_hkdf_sha3_512 from persistent_derivation").fetchone()[0]
                database_connection_object.commit()
            case _:
                raise Exception(f"Invalid specification {
                                fetch_state_of_the_key_chain_for_specification} provided for the cryptographic primitive.")
    finally:
        database_connection_object.close()

    return output


def get_standard_deviation_of_execution_times(all_individual_execution_times: list[float], average_execution_time: float) -> float:
    standard_deviation_in_execution_times = stdev(
        all_individual_execution_times, average_execution_time)
    return standard_deviation_in_execution_times


def get_confidence_intervals_of_execution_times(confidence_level: float, average_execution_time: float, standard_deviation_of_execution_times: float, length_of_dataset: int) -> Tuple[float, float]:
    alpha = 1 - confidence_level
    z_critical = norm.ppf(1 - (alpha/2))
    margin_of_error = z_critical * \
        (standard_deviation_of_execution_times / (sqrt(length_of_dataset)))
    confidence_intervals = (average_execution_time - margin_of_error,
                            average_execution_time + margin_of_error)

    return confidence_intervals
