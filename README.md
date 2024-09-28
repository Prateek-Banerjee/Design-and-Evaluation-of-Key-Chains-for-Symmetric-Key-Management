# Research_Project Prateek_Banerjee Design_and_Evaluation_of_Key_Chains_for_Symmetric_Key Management

This repository comprises of all the documents generated during the research project done by Prateek Banerjee under the supervision of Professor David Schatz.

# Cryptographic Key Chain Evaluation
This directory contains the complete code base which includes:
1) [Cryptographic Primitives](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/tree/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/cryptographicprimitives): This folder comprises of the interface for the different operations of each cryptographic primitives namely [`hkdf_operations.py`](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/cryptographicprimitives/hkdf_operations.py), [`xdrbg_operations.py`](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/cryptographicprimitives/xdrbg_operations.py), [`prg_operations.py`](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/cryptographicprimitives/prg_operations.py) according to **Algorithm 1**, **Algorithm 2**, and **Algorithm 3** respectively from the ***chapters 2 and 3*** of the [report](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Report/first%20draft%20of%20project%20report.pdf).

2) [Key Chains](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/tree/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/keychains): This folder comprises the code for the key chain generation using each of the [cryptographic primitives](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/tree/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/cryptographicprimitives) according to the **Fig. 4.1** of the ***chapter 4*** of the [report](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Report/first%20draft%20of%20project%20report.pdf).

3) The file [`benchmark_key_generation.py`](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/benchmark_key_chain_generation.py) comprises of the code for conducting the performance evaluation.

4) [Console Screenshots](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/tree/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/Console%20Screeenshots): This folder comprises of the screenshots for verifying the execution times mentioned in the ***chapter 5*** of the [report](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Report/first%20draft%20of%20project%20report.pdf).

## Installing the External Python Modules
Open any command line interface (like CMD on Windows) and traverse to the directory where you have downloaded the [`requirements.txt`](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/requirements.txt) file and then execute the below command.
```bash 
pip install -r requirements.txt
```
## Database Setup
Download the [DB Browser for SQLite](https://sqlitebrowser.org/dl/). We have used the *64-bit* Windows installer. We encourage a user to use the [`Table Creation Script.sql`](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/Database%20Table%20Create%20Script.sql) at first, and then proceed with (let's say) executing the [`benchmark_key_generation.py`](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/blob/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/benchmark_key_chain_generation.py) on their own system.

## Test Execution in the [tests](https://github.com/Prateek-Banerjee/Master-s-Curriculum-Individual-Studies/tree/main/5th%20Sem/Research%20Project/Cryptographic%20Key%20Chain%20Evaluation/tests) Directory

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