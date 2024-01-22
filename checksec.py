import lief
from colorama import Fore, Style
import argparse
import struct
import sys
from prettytable import PrettyTable, ALL


def check(bin):
    try:
        binary = lief.parse(bin)
        return binary
    except lief.parser_error:
        print("Couldn't load this file")
        return None

class PE:
    def __init__(self, pe):
        self.pe = pe
        self.optional_header = pe.optional_header
        self.characteristics = self.optional_header.dll_characteristics_lists

    def _color_print(self, name, result):
        color = Fore.GREEN if result else Fore.RED
        return color + f"{name}: {result}" + Style.RESET_ALL

    def appcontainer(self):
        return lief.PE.DLL_CHARACTERISTICS.APPCONTAINER in self.characteristics

    def aslr(self):
        return lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE in self.characteristics

    def force_integrity(self):
        # FORCE_INTEGRITY flag is used to indicate that the image is compatible with Data Execution Prevention (DEP).
        return lief.PE.DLL_CHARACTERISTICS.FORCE_INTEGRITY in self.characteristics

    def isolation(self):
        # NO_ISOLATION flag indicates that the binary is not intended to run in an isolated environment (AppContainer).
        return not (lief.PE.DLL_CHARACTERISTICS.NO_ISOLATION in self.characteristics)

    def cfg(self):
        return lief.PE.DLL_CHARACTERISTICS.GUARD_CF in self.characteristics

    def rfg(self):
        # Check if the binary uses Return Flow Guard (RFG).
        load_config_entry = self.pe.data_directories[lief.PE.DATA_DIRECTORY.LOAD_CONFIG_TABLE]
        if load_config_entry and load_config_entry.rva:
            # Find the section containing the load configuration data.
            section = next((s for s in self.pe.sections if s.virtual_address <= load_config_entry.rva < s.virtual_address + s.virtual_size), None)
            if section:
                # Calculate the offset within the section for the load configuration data.
                load_config_offset = load_config_entry.rva - section.virtual_address
                # Extract the load configuration data.
                load_config = section.content[load_config_offset:load_config_offset + load_config_entry.size]
                # Retrieve the values related to the Import Address Table (IAT) from the load configuration.
                iat_rva = struct.unpack("<I", load_config[0x28:0x2C])[0]
                iat_size = struct.unpack("<I", load_config[0x2C:0x30])[0]
                # Check if IAT RVA and size are non-zero.
                return iat_rva != 0 and iat_size != 0
        return False

    def high_entropy_va(self):
        # Check if the binary supports high-entropy virtual addresses.
        return lief.PE.DLL_CHARACTERISTICS.HIGH_ENTROPY_VA in self.characteristics

    def no_bind(self):
        # NO_BIND flag limits dynamic linking, potentially undermining ASLR effectiveness by reducing address space variability.
        return not (lief.PE.DLL_CHARACTERISTICS.NO_BIND in self.characteristics)

    def dep(self):
        # DEP flag indicates support for Data Execution Prevention.
        return lief.PE.DLL_CHARACTERISTICS.NX_COMPAT in self.characteristics

    def seh(self):
        if not self.pe.header.machine == lief.PE.MACHINE_TYPES.I386:
            return False
        # Check if the binary uses Structured Exception Handling (SEH).
        return lief.PE.DLL_CHARACTERISTICS.NO_SEH not in self.characteristics

    def safe_seh(self):
        if not self.pe.header.machine == lief.PE.MACHINE_TYPES.I386:
            return False
        try:
            # Check if the binary has SafeSEH mitigations.
            return (
                self.seh()
                and self.pe.load_configuration.se_handler_table != 0
                and self.pe.load_configuration.se_handler_count != 0
            )
        except AttributeError:
            return False

    def security_cookie(self):
        try:
            # Check if binary has stack canary (/GS)
            return True if self.pe.load_configuration.security_cookie != 0 else False
        except AttributeError:
            return False

    def aslr_relocations_check(self):
        # Check if ASLR is enabled and relocations are stripped
        return self.aslr and not self.pe.has_relocations

    def binary_signature_issuer(self):
        # Get the issuer of the binary signature
        if self.pe.has_signatures:
            for signature in self.pe.signatures:
                certificates = signature.certificates
                for certificate in certificates:
                    issuer = certificate.issuer
                    return issuer
        return "Not Signed"


    def has_signatures(self):
        # Check if the binary has authenticode signatures.
        return self.pe.has_signatures

    def display_results(self):
        features = [
            ("AppContainer", self.appcontainer),
            ("ASLR", self.aslr),
            ("ForceIntegrity", self.force_integrity),
            ("Isolation", self.isolation),
            ("ControlFlowGuard", self.cfg),
            ("ReturnFlowGuard", self.rfg),
            ("HighEntropyVA", self.high_entropy_va),
            ("Dynamic Linking (Base Relocations)", self.no_bind),
            ("DEP", self.dep),
            ("SEH", self.seh),
            ("SafeSEH", self.safe_seh),
            ("Security Cookie", self.security_cookie),
            ("Authenticode", self.has_signatures),
            ("/DYNAMICBASE with Stripped Relocations", self.aslr_relocations_check),
            ("Binary Signature Issuer", self.binary_signature_issuer)
        ]

        out = PrettyTable(hrules=ALL)
        out.field_names = [f"{Fore.BLUE}Feature{Style.RESET_ALL}", f"{Fore.BLUE}Enabled{Style.RESET_ALL}"]

        for feature, func in features:
            result = func()
            color = Fore.GREEN if result else Fore.RED
            # Check if the result is a string
            if isinstance(result, str):
                out.add_row([feature, f"{color}{result}{Style.RESET_ALL}"])
            else:
                # Handle boolean results
                out.add_row([feature, f"{color}Yes{Style.RESET_ALL}" if result else f"{color}No{Style.RESET_ALL}"])

        # Pretty Printed Table
        print(out)

class Checker:
    def __init__(self, filename):
        # Check if lief can parse binary
        binary = check(filename)
        if binary is None:
            sys.exit(1)
        
        self.binary = binary
        if lief.is_pe(filename):
            PE(self.binary).display_results()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Check security features of a binary.")
    parser.add_argument("binary", help="Path to the binary file.")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    binary = Checker(args.binary)
