from entropylossdetection.utils import check_injectivity_for_idealizations
import unittest


class TesInjectivity(unittest.TestCase):

    def test_to_raise_error_for_injectivity_check(self) -> None:
        list_of_dummy_inputs: list[bytes] = [
            b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j']
        list_of_dummy_outputs: list[bytes] = [
            b'1', b'2', b'3', b'4', b'5', b'4', b'7', b'8', b'9', b'10']
        with self.assertRaises(Exception):
            check_injectivity_for_idealizations(
                list_of_dummy_inputs, list_of_dummy_outputs)
