## Disclaimer
This was meant to be used for prototyping and as a research tool only. It has not been sufficiently vetted for use in security-critical production environments. All implementations are to be considered experimental.

## Overview of the Contents of the Different Folders
1) [Cryptographic Primitives](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/tree/master/cryptographicprimitives): This folder comprises of the interface for the different operations of each cryptographic primitives namely [`hkdf_operations.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/cryptographicprimitives/hkdf_operations.py), [`xdrbg_operations.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/cryptographicprimitives/xdrbg_operations.py), and [`prg_operations.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/cryptographicprimitives/prg_operations.py)  according to **Algorithm 1**, **Algorithm 2**, and **Algorithm 3** respectively from the ***chapters 2 and 3*** of the [report](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/Research%20Project%20Report.pdf).

2) [Entropy Loss Detection](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/tree/master/entropylossdetection): This folder comprises the code for the sound and unsound idealizations required for the detection of entropy loss based on the ***chapter 5*** of the [report](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/Research%20Project%20Report.pdf).

2) [Key Chains](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/tree/master/keychains): This folder comprises the code for the key chain generation using each of the [cryptographic primitives](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/tree/master/cryptographicprimitives) according to the **Fig. 4.1**, **Fig. 4.2**, and **Fig. 4.3** of the ***chapter 4*** of the [report](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/Research%20Project%20Report.pdf).

3) [Tests](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/tree/master/tests): This folder comprises of some basic tests for the individual cryptographic primitives from [Cryptographic Primitives](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/tree/master/cryptographicprimitives).


## Other Important Files
1) The file [`benchmark_key_generation.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/benchmark_key_chain_generation.py) comprises of the code for conducting the performance evaluation.

2) The file [`entropy_loss_detection.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/entropy_loss_detection.py) comprises the code executing the idealizations required for the detection of entropy loss.

3) The file [`timings_for_key_chain_instantiation.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/timings_for_key_chain_instantiation.py) comprises the code for checking the execution times for the key chain instantiation using different cryptographic primitives.

## Installing the External Python Modules
Open any command line interface (like CMD on Windows) and traverse to the directory where you have downloaded the [`requirements.txt`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/requirements.txt) file and then execute the below command.
```bash 
pip install -r requirements.txt
```
## Database Setup
Download the [DB Browser for SQLite](https://sqlitebrowser.org/dl/). We have used the *64-bit* Windows installer. We encourage a user to use the [`Table Creation Script.sql`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/Database%20Table%20Create%20Script.sql) at first, and then proceed with (let's say) executing the [`benchmark_key_generation.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/benchmark_key_chain_generation.py) on their own system.

## For Test Execution in the [tests](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/tree/master/tests) Directory
Paste the below section in your (VS Code) settings.json file.
```
"python.testing.unittestArgs": [
  "-v",
  "-s",
  "./tests",
  "-p",
  "test_*.py"
],
"python.testing.pytestEnabled": false,
"python.testing.unittestEnabled": true
```

### Additional Information
There is a boolean flag in [`hkdf_operations.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/cryptographicprimitives/hkdf_operations.py) and [`xdrbg_operations.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/cryptographicprimitives/xdrbg_operations.py) mentioned as:

```
IS_PERFORMANCE_BENCHMARKING_DONE: bool = True
```

This is set to **True** by default, which skips the checks of the fulfillment criteria of the parameters during benchmarking for the HKDF and the XDRBG based on what is mentioned in *Table 4.2* and *Table 4.4* respectively in the ***chapter 4*** of the [report](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/Research%20Project%20Report.pdf) as we are only executing those scripts when we are conducting the benchmark using the [`benchmark_key_generation.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/benchmark_key_chain_generation.py). But, if the keychain is to be used for some other purposes later on or if the tests are to be executed from the [tests](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/tree/master/tests) directory, **we request you to set this flag to *False*** to ensure that the proper parameter checks are also being conducted to uphold the security of the cryptographic primitives and to ensure that the tests are also being executed successfully.


### Some Key References Used for This Work
(1) [Krawczyk, Hugo. "Cryptographic extraction and key derivation: The HKDF scheme." Annual Cryptology Conference. Berlin, Heidelberg: Springer Berlin Heidelberg, 2010.](https://eprint.iacr.org/2010/264.pdf)
(2) [Kelsey, John, Stefan Lucks, and Stephan Müller. "XDRBG: A Proposed Deterministic Random Bit Generator Based on Any XOF."
IACR Transactions on Symmetric Cryptology 2024.1 (2024): 5-34.](https://tosc.iacr.org/index.php/ToSC/article/view/11399)
(3) [Barak, Boaz, and Shai Halevi. "A model and architecture for pseudo-random generation with applications to/dev/random."
Proceedings of the 12th ACM conference on Computer and communications security. 2005.](https://eprint.iacr.org/2005/029.pdf)
(4) [HKDF - HMAC Key Derivation Function](https://github.com/casebeer/python-hkdf) *Note: There are some subtle modifications in our [`hkdf_operations.py`](https://github.com/Prateek-Banerjee/Design-and-Evaluation-of-Key-Chains-for-Symmetric-Key-Management/blob/master/cryptographicprimitives/hkdf_operations.py), but the fundamental idea logic has been referred from this resource.*
(5) [Python implementation of Ascon](https://github.com/meichlseder/pyascon)
(6) [Circulant](https://github.com/CQCL/cryptomite)