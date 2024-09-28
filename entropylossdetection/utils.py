def check_injectivity_for_idealizations(list_of_corresponding_inputs: list[bytes], list_of_random_outputs: list[bytes]) -> None:
    mapping_of_seeds_to_random_output: dict[bytes, bytes] = {}

    for corresponding_input, random_output in zip(list_of_corresponding_inputs, list_of_random_outputs):
        if random_output in mapping_of_seeds_to_random_output:
            raise Exception(f"Seed \033[1;33m{corresponding_input!r}\033[0m and \033[1;33m{
                            mapping_of_seeds_to_random_output[random_output]!r}\033[0m generated the same random output: \033[1;33m{random_output!r}\033[0m")
        mapping_of_seeds_to_random_output[random_output] = corresponding_input
