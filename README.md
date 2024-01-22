# Binary Security Checker

This Python script leverages the lief library to perform security checks on binaries. As of the current implementation, the script focuses on checking security protections for PE (Portable Executable) files. However, future updates are planned to extend support for ELF (Executable and Linkable Format) and iOS binaries.

## PE Features

- **AppContainer Check:** Verify if the binary is designed to run in an AppContainer.
- **ASLR Check:** Determine if Address Space Layout Randomization (ASLR) is enabled.
- **Force Integrity Check:** Check compatibility with Data Execution Prevention (DEP).
- **Isolation Check:** Confirm if the binary is intended for isolated environments (AppContainer).
- **Control Flow Guard (CFG) Check:** Check for CFG security mitigation.
- **Return Flow Guard (RFG) Check:** Validate Return Flow Guard presence.
- **High Entropy Virtual Address Check:** Check for high entropy virtual address.
- **Dynamic Linking Check:** Assess if the binary has limitations on dynamic linking. If the `NO_BIND` flag is set, it indicates that the binary is not using base relocations, implying restrictions on dynamic linking.
- **DEP (NX Compatibility) Check:** Verify Data Execution Prevention compatibility.
- **SEH (Structured Exception Handling) Check:** Examine the presence of SEH records.
- **SafeSEH Check:** Validate the presence of SafeSEH mitigations.
- **Security Cookie Check:** Validate the presence of a stack canary (Binary compiled with /GS flag).
- **Authenticode Check:** Detect the presence of binary signatures.
- **/DYNAMICBASE with Stripped Relocations:** Check if `/DYNAMICBASE` is enabled, but relocations are stripped.
- **Binary Signature Issuer:** Print the issuer of the binary signature, if present.

## Installation

1. Create a virtual environment:

    ```bash
    python3 -m venv bin_checker_env
    ```

2. Activate the virtual environment:

    ```bash
    source bin_checker_env/bin/activate
    ```

3. Install required dependencies using `pip`:

    ```bash
    pip install lief colorama argparse prettytable
    ```

## Usage

```bash
python binary_security_checker.py <binary_path>
```
