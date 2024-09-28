"""
[1] Kelsey, John, Stefan Lucks, and Stephan Müller. "XDRBG: A Proposed Deterministic Random Bit Generator Based on Any XOF."
IACR Transactions on Symmetric Cryptology 2024.1 (2024): 5-34.

[2] Barak, Boaz, and Shai Halevi. "A model and architecture for pseudo-random generation with applications to/dev/random."
Proceedings of the 12th ACM conference on Computer and communications security. 2005.
"""

import inspect


def check_fulfillment_criteria_of_parameters(
    xof_name: str = "",
    seed: bytes = b"",
    length_of_the_random_output: int = 0,
    state_size: int = 0,
    alpha: bytes = b""
) -> None:
    """
    This method checks whether the parameters to be used when accessing the Xdrbg
    fulfils certain criteria or not. The parameters with which this method will be
    invoked will depend on where it is invoked from i.e. xdrbg_instantiate or
    xdrbg_reseed or xdrbg_generate.

    Parameters
    ----------

    xof_name : str
               This name of the Xof with which the Xdrbg was instantiated.

    seed : bytes
           The seed which is used for either xdrbg_instantiate or
           xdrbg_reseed.

    length_of_the_random_output : int
                                  The length (in bytes) of the desired random output.

    state_size : int
                 The length (in bytes) of the state size of Xdrbg which
                 was set when the Xdrbg instance was created.

    alpha : bytes
            This parameter will depend whether on whether it was provided
            during invocation of xdrbg_instantiate or xdrbg_reseed or
            xdrbg_generate or not.

    Returns
    -------
    This method does not return any value.
    """

    method_invoker_name: str = inspect.stack()[1].function
    try:
        match method_invoker_name:
            case "xdrbg_instantiate_main":
                length_of_provided_seed_for_xdrbg_instantiate_in_bytes: int = len(
                    seed)

                
                # This dictionary maps the minimum seed length required for
                # instantiation of the Xdrbg based on the respective Xof.

                # The {key : value} pair is respectively {xof_name : minimum_seed_length_required_in_bytes}.
               
                REQUIRED_SEED_LENGTH_FOR_XDRBG_INSTANTIATE: dict[str, int] = {
                    "shake_128": 24,
                    "Ascon-Xof": 24,
                    "shake_256": 48,
                }

                # Validate the seed length for instantiation if the xof_name is valid.
                try:
                    if xof_name in REQUIRED_SEED_LENGTH_FOR_XDRBG_INSTANTIATE:
                        try:
                            validate_seed_length_for_xdrbg(
                                length_of_provided_seed_for_xdrbg_instantiate_in_bytes,
                                REQUIRED_SEED_LENGTH_FOR_XDRBG_INSTANTIATE[xof_name],
                                "instantiation",
                                xof_name
                            )
                        except ValueError as e:
                            print(f"VlaueError: {e}")
                            raise
                    else:
                        raise NameError(f"Invalid XOF (name): {xof_name}.")
                except NameError as e:
                    print(f"NameError: {e}")

            case "xdrbg_reseed_main":

                length_of_provided_seed_for_xdrbg_reseed_in_bytes: int = len(
                    seed)

                
                # This dictionary maps the minimum seed length required for
                # reseeding the Xdrbg based on the respective Xof.

                # The {key : value} pair is respectively {xof_name : minimum_seed_length_required_in_bytes}.
               
                REQUIRED_SEED_LENGTH_FOR_XDRBG_RESEED: dict[str, int] = {
                    "shake_128": 16,
                    "Ascon-Xof": 16,
                    "shake_256": 32,
                }

                # Validate the seed length for reseeding if the xof_name is valid.
                try:
                    if xof_name in REQUIRED_SEED_LENGTH_FOR_XDRBG_RESEED:
                        try:
                            validate_seed_length_for_xdrbg(
                                length_of_provided_seed_for_xdrbg_reseed_in_bytes,
                                REQUIRED_SEED_LENGTH_FOR_XDRBG_RESEED[xof_name],
                                "reseeding",
                                xof_name
                            )
                        except ValueError as e:
                            print(f"ValueError: {e}")
                            raise
                    else:
                        raise NameError(f"Invalid XOF (name): {xof_name}.")
                except NameError as e:
                    print(f"NameError: {e}")

            case "xdrbg_generate_main":

                
                # This dictionary maps the maximum (total) output length in bytes i.e. sum
                # of length_of_the_random_output + xdrbg_state_size (in bytes) from a single
                # xdrbg_generate-call based on the respective Xof.

                # The {key : value} pair is respectively {xof_name : max_output_bytes_allowed_during_xdrbg_generate_in_bytes}.
               
                MAX_OUTPUT_BYTES_ALLOWED_DURING_XDRBG_GENERATE: dict[str, int] = {
                    "shake_128": 304,
                    "Ascon-Xof": 256,
                    "shake_256": 344,
                } 

                # Validate the maximum output length for generate-calls if the xof_name is valid.
                try:
                    if xof_name in MAX_OUTPUT_BYTES_ALLOWED_DURING_XDRBG_GENERATE:
                        try:
                            validate_desired_output_length_for_xdrbg(
                                (length_of_the_random_output + state_size),
                                MAX_OUTPUT_BYTES_ALLOWED_DURING_XDRBG_GENERATE[xof_name],
                                xof_name
                            )
                        except ValueError as e:
                            print(f"ValueError: {e}")
                            raise
                    else:
                        raise NameError(f"Invalid XOF (name): {xof_name}.")
                except NameError as e:
                    print(f"NameError: {e}")
            case _:
                raise NameError(f"Invalid invocation from {
                                method_invoker_name}.")
    except NameError as e:
        print(f"NameError: {e}")

    try:
        if (alpha != b"") and (len(alpha) > 84):
            raise ValueError(f"The length of the (optional) alpha parameter is {len(
                alpha)} bytes which is more than the limit of 84 bytes. Choose an alpha which is of length between 0 and 84 bytes (both inclusive).")
    except ValueError as e:
        print(f"ValueError: {e}")
        raise


def validate_seed_length_for_xdrbg(
    length_of_provided_seed_in_bytes: int,
    minimum_seed_length_required_in_bytes: int,
    operation_name: str,
    xof_name: str,
) -> None:
    """
    This method is required to check whether the seed length meets a
    certain threshold or not.

    Parameters
    ----------

    length_of_provided_seed_in_bytes : int
                                       The length of the provided seed in bytes.

    minimum_seed_length_required_in_bytes : int
                                            The minimum seed length will depend
                                            on the xof with which the Xdrbg is
                                            instantiated and for what purpose
                                            the length checking is required i.e
                                            for xdrbg_instantiate or xdrbg_reseed.

    operation_name : str
                     This parameter denotes the purpose as to why this
                     method was invoked. This parameter will either be
                     the string "instantiation " or "reseeding".

    xof_name : str
               The name of the Xof with which the Xdrbg was instantiated.

    Returns
    -------
    This method does not return any value.
    """
    if length_of_provided_seed_in_bytes < minimum_seed_length_required_in_bytes:
        raise ValueError(f"The length of the provided seed material for {operation_name} with {xof_name} is {length_of_provided_seed_in_bytes} bytes, which is less than {
                         minimum_seed_length_required_in_bytes} bytes. Choose a seed of length >= {minimum_seed_length_required_in_bytes} bytes.")


def validate_desired_output_length_for_xdrbg(
    requested_output_length_in_bytes: int,
    max_output_bytes_allowed_during_xdrbg_generate_in_bytes: int,
    xof_name: str,
) -> None:
    """
    This method is required to check whether the maximum output length
    meets is below a certain threshold or not.

    Parameters
    ----------

    requested_output_length_in_bytes : int
                                       The length of the total output
                                       generated by the Xdrbg in bytes.

    max_output_bytes_allowed_during_xdrbg_generate_in_bytes : int
                                     The maximum output length will depend on
                                     the xof with which the Xdrbg is instantiated.

    xof_name : str
               This name of the Xof with which the Xdrbg was instantiated.

    Returns
    -------
    This method does not return any value.
    """

    if requested_output_length_in_bytes > max_output_bytes_allowed_during_xdrbg_generate_in_bytes:
        raise ValueError(f"The length of the desired output + the xdrbg state size is {
                         requested_output_length_in_bytes} bytes, which is more than the limit of {xof_name} which is {max_output_bytes_allowed_during_xdrbg_generate_in_bytes} bytes.")


# The method ENCODE(S,α,N) according to Page 29 of the downloaded pdf (which is the Page 33) of [1]
def encode_function(seed: bytes, alpha: bytes, value_N: int) -> bytes:
    """
    Computes ENCODE(S,α,n) = ( S ∥ α ∥ (n*85+|α|/8)_8 )
    recommended in [1] while ensuring that it does not
    introduce any trivial collisions.

    Parameters
    ----------
    seed : bytes
           The value for seed will depend i.e. from which call
           (xdrbg_instantiate or xdrbg_reseed or xdrbg_generate)
           this ENCODE(S,α,n) method has been invoked.
    alpha : bytes

    Returns
    -------
    The encoded value in bytes.
    """

    # Computation of just (n*85+|α|/8)_8 from [1]
    computed_param: int = value_N * 85 + (len(alpha) * 8) // 8

    
    # Computation of the part ( S ∥ α ∥ (n*85+|α|/8)_8 ) where
    # ∥ denotes concatenation.
    # The (computed_param.bit_length() + 7) // 8 is needed to
    # correctly determine the length required to represent the
    # parameter (computed_param) in bytes.
   
    encoded_value: bytes = (
        seed
        + alpha
        + (computed_param.to_bytes((computed_param.bit_length() + 7) // 8, "big"))
    )
    return encoded_value
