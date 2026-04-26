#!/usr/bin/env python3

"""
pydys - Python PYC Deep Disassembler

A recursive Python bytecode disassembler that penetrates nested code objects,
reconstructs function signatures, and generates human-readable annotated output.

Author: bl4d3rvnner7
License: MIT
"""

import marshal
import dis
import colorama
import sys
import re
import struct
import argparse
import json
from pathlib import Path

colorama.init(autoreset=True)

PYTHON_MAGIC_NUMBERS = {
    20121: "1.5", 50428: "1.6", 50823: "2.0", 60202: "2.1", 60717: "2.2",
    62011: "2.3", 62021: "2.3", 62041: "2.4", 62051: "2.4", 62061: "2.4",
    62071: "2.5", 62081: "2.5", 62091: "2.5", 62092: "2.5", 62101: "2.5",
    62111: "2.5", 62121: "2.5", 62131: "2.5", 62151: "2.6", 62161: "2.6",
    62171: "2.7", 62181: "2.7", 62191: "2.7", 62201: "2.7", 62211: "2.7",
    3000: "3.0", 3400: "3.8", 3410: "3.8", 3420: "3.9", 3430: "3.10",
    3450: "3.11", 3500: "3.12", 3531: "3.13 (Pre-release)", 3550: "3.13",
    3600: "3.14", 3610: "3.14", 3620: "3.14", 3627: "3.14 beta", 3630: "3.14", 3640: "3.14",
    3650: "3.14"
}

MAX_ERROR_COUNT = 10

class Pydis:
    """
    Main disassembler class for recursive PYC file analysis.

    This class handles reading PYC files, recursively disassembling nested code objects,
    cleaning opcode output, and exporting results in various formats.

    Attributes:
        no_color (bool): Disable colored terminal output
        json_output (bool): Enable JSON export format
        modern_mode (bool): Enable Python 3.11+ adaptive features
        assembly_string (str): Accumulated disassembly output
        imports (set): Collection of all imported modules found
        code_objects (list): List of nested code objects discovered
        magic_number (int): PYC file magic number
        version (str): Detected Python version string
        current_indent (int): Current indentation level for nested output
        filename (str): Path to the PYC file being analyzed
    """
    def __init__(self, no_color=False, json_output=False, modern_mode=False):
        """
        Initialize the Pydis disassembler with specified options.

        Args:
            no_color (bool, optional): Disable ANSI color codes in output. Defaults to False.
            json_output (bool, optional): Enable JSON output format. Defaults to False.
            modern_mode (bool, optional): Enable Python 3.11+ adaptive opcode handling. Defaults to False.
        """
        self.no_color = no_color
        self.json_output = json_output
        self.modern_mode = modern_mode
        self.assembly_string = ""
        self.imports = set()
        self.code_objects = []
        self.magic_number = None
        self.version = None
        self.current_indent = 0
        self.COLOR_RED = '\x1b[91m'
        self.COLOR_GREEN = '\x1b[92m'
        self.COLOR_YELLOW = '\x1b[93m'
        self.COLOR_BLUE = '\x1b[94m'
        self.COLOR_MAGENTA = '\x1b[95m'
        self.COLOR_CYAN = '\x1b[96m'
        self.COLOR_WHITE = '\x1b[97m'
        self.COLOR_RESET = '\x1b[0m'

    def colorize(self, text, color_code):
        """
        Apply ANSI color codes to text if color output is enabled.

        Args:
            text (str): The text to colorize
            color_code (str): ANSI color code (e.g., '\x1b[91m' for red)

        Returns:
            str: Colorized text if enabled, otherwise original text
        """
        if self.no_color:
            return text
        return f"{color_code}{text}{self.COLOR_RESET}"

    def get_version_by_num(self, magic_number):
        """
        Convert Python magic number to human-readable version string.

        Args:
            magic_number (int): Python PYC magic number from file header

        Returns:
            str: Human-readable Python version string
        """
        if magic_number in PYTHON_MAGIC_NUMBERS:
            return PYTHON_MAGIC_NUMBERS[magic_number]

        if magic_number >= 3600:
            return f"3.14+ (magic {magic_number})"
        elif magic_number >= 3550:
            return "3.13+"
        elif magic_number >= 3500:
            return "3.12+"
        elif magic_number >= 3400:
            return "3.8–3.11"

        if magic_number < 3000:
            return "< 3.0"
        minor = (magic_number - 2900) // 50
        return f"3.{minor} (approx)"

    def read_pyc_file(self, filename):
        """
        Read and parse a PYC file, extracting the code object.

        Args:
            filename (str): Path to the PYC file

        Returns:
            tuple: (code_object, version_string)

        Raises:
            SystemExit: If marshal loading fails (usually wrong Python version)
        """
        with open(filename, 'rb') as f:
            self.magic_number = struct.unpack("<H", f.read(2))[0]
            self.version = self.get_version_by_num(self.magic_number)
            f.seek(16)  # Skip header for Python 3.8+
            try:
                code = marshal.load(f)
            except Exception as e:
                print(self.colorize(f"[I] Marshal Error: {e}", self.COLOR_RED))
                print(self.colorize(f"[V] Your Python: {sys.version_info.major}.{sys.version_info.minor}", self.COLOR_RED))
                print(self.colorize(f"[V] Detected: {self.version}", self.COLOR_RED))
                sys.exit(1)
        return code, self.version

    def detect_version_only(self, filename):
        """
        Detect and display Python version without full disassembly.

        Args:
            filename (str): Path to the PYC file

        Returns:
            dict: Version information including magic number and recommended interpreter
        """
        with open(filename, 'rb') as f:
            magic_number = struct.unpack("<H", f.read(2))[0]
            version = self.get_version_by_num(magic_number)

            result = {
                "file": filename,
                "magic_number": magic_number,
                "python_version": version,
                "recommended_interpreter": self.get_recommended_interpreter(version)
            }

            if self.json_output:
                print(json.dumps(result, indent=2))
            else:
                print(f"File: {filename}")
                print(f"Magic Number: {magic_number}")
                print(f"Python Version: {version}")
                print(f"Recommended Interpreter: {result['recommended_interpreter']}")
            return result

    def get_recommended_interpreter(self, version):
        """
        Generate pyenv command for installing required Python version.

        Args:
            version (str): Python version string (e.g., "3.13+")

        Returns:
            str: Command string for pyenv installation
        """
        match = re.search(r'(\d+\.\d+)', version)
        if match:
            ver = match.group(1)
            return f"pyenv install {ver} && pyenv local {ver}"
        return "Check Python.org for appropriate version"

    def disassemble_code(self, code, indent=0, force_class=False, force_dataclass=False):
        """
        Recursively disassemble a code object and its nested children.

        This is the core disassembly method that walks through bytecode instructions,
        cleans opcode output, and recursively processes nested code objects.

        Args:
            code (code object): Python code object to disassemble
            indent (int, optional): Current indentation level for nested output. Defaults to 0.
        """
        is_class = force_class
        is_dataclass = force_dataclass
        errors = 0

        print(f"\n{' ' * indent}{self.colorize('═' * 90, self.COLOR_WHITE)}")
        print(f"{' ' * indent}{self.colorize(f'Code Object: {code.co_name} at {hex(id(code))}', self.COLOR_YELLOW)}")
        print(f"{' ' * indent}{self.colorize(f'Name: {code.co_name}', self.COLOR_BLUE)}")
        print(f"{' ' * indent}{self.colorize(f'Arguments: {code.co_argcount}', self.COLOR_MAGENTA)}")
        print(f"{' ' * indent}{self.colorize(f'Var Names: {code.co_varnames}', self.COLOR_CYAN)}")
        print(f"{' ' * indent}{self.colorize('═' * 90, self.COLOR_WHITE)}")

        self.assembly_string += f"\n{' ' * indent}{'═' * 90}\n"
        self.assembly_string += f"{' ' * indent}Code Object: {code.co_name} at {hex(id(code))}\n"
        self.assembly_string += f"{' ' * indent}Name: {code.co_name}\n"
        self.assembly_string += f"{' ' * indent}Arguments: {code.co_argcount}\n"
        self.assembly_string += f"{' ' * indent}Var Names: {code.co_varnames}\n"
        self.assembly_string += f"{' ' * indent}{'═' * 90}\n"

        # Reconstruct signature
        args_list = list(code.co_varnames)[:code.co_argcount]
        args_string = ', '.join(args_list)

        if code.co_name == "<module>":
            print(f"{' ' * indent}{self.colorize('# Module level code', self.COLOR_GREEN)}")
            self.assembly_string += f"{' ' * indent}# Module level code\n"
        else:
            if is_dataclass:
                signature = f"@dataclass\n{' ' * indent}class {code.co_name}:"
            elif is_class:
                signature = f"class {code.co_name}:"
            else:
                signature = f"def {code.co_name}({args_string}):"

            print(f"{' ' * indent}{self.colorize('Possible Code : ', self.COLOR_GREEN)}{self.colorize(signature, self.COLOR_RED)}")
            self.assembly_string += f"{' ' * indent}Possible Code : {signature}\n"

        next_code_is_class = False
        next_code_is_dataclass = False

        for instruction in dis.Bytecode(code, show_caches=True):
            try:
                # Skip noisy modern opcodes
                if instruction.opname in ("CACHE", "RESUME", "PRECALL", "RETURN_GENERATOR", "KW_NAMES"):
                    continue

                offset = instruction.offset
                opname = instruction.opname
                argrepr = instruction.argrepr or ""

                # Special coloring
                if opname in {'GET_ITER', 'FOR_ITER', 'JUMP_BACKWARD', 'END_FOR'}:
                    color = self.COLOR_RED
                elif opname in {'SETUP_EXCEPT', 'SETUP_FINALLY', 'CHECK_EXCEPT'}:
                    color = self.COLOR_BLUE
                elif opname in {'IMPORT_NAME', 'IMPORT_FROM'}:
                    color = self.COLOR_BLUE
                    if opname == 'IMPORT_NAME':
                        mod = argrepr.split()[-1] if ' ' in argrepr else argrepr
                        self.imports.add(mod)
                elif opname in {'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE'}:
                    color = self.COLOR_YELLOW
                else:
                    color = self.COLOR_WHITE

                line = f"{' ' * indent}{offset:4d} {self.colorize(opname.ljust(20), color)} {argrepr}"
                print(line)
                self.assembly_string += f"\n{' ' * indent}{offset:4d} {opname.ljust(20)} {argrepr}"

                # Deep recursion for every nested code object
                if instruction.opname == 'LOAD_CONST' and isinstance(instruction.argval, type(code)):
                    nested = instruction.argval
                    print(f"\n{' ' * (indent + 4)}{self.colorize(f'→ Entering nested Code Object: {nested.co_name}', self.COLOR_YELLOW)}")
                    self.assembly_string += f"\n\n{' ' * (indent + 4)}→ Entering nested Code Object: {nested.co_name}\n"
                    self.disassemble_code(nested, indent + 8, force_class=next_code_is_class, force_dataclass=next_code_is_dataclass)
                    next_code_is_class = False

                # LOAD_ATTR cleaning
                elif instruction.opname == 'LOAD_ATTR':
                    cleaned = re.sub(r'\.?NULL(.*?)\+ ', '.', argrepr)
                    cleaned = re.sub(r'\.+', '.', cleaned)
                    print(f"{' ' * indent}{offset:4d} {self.colorize(opname.ljust(20), self.COLOR_GREEN)} {cleaned}")
                    self.assembly_string += f"\n{' ' * indent}{offset:4d} {opname.ljust(20)} {cleaned}"

                # LOAD_GLOBAL cleaning
                elif instruction.opname == 'LOAD_GLOBAL':
                    attr = re.sub(r'\.?NULL(.*?)\+ ', '', argrepr)
                    if attr.startswith('.'):
                        attr = attr[1:]
                    print(f"{' ' * indent}{self.colorize(f'{offset:4d} {opname.ljust(20)} {attr}', self.COLOR_MAGENTA)}")
                    self.assembly_string += f"\n{' ' * indent}{offset:4d} {opname.ljust(20)} {attr}"

                # Class detection
                elif instruction.opname == "LOAD_NAME" and instruction.argval == "dataclass":
                    next_code_is_dataclass = True
                elif instruction.opname == "LOAD_BUILD_CLASS":
                    next_code_is_class = True
                    is_class = True
                    continue

            except Exception as e:
                errors += 1
                print(self.colorize(f"[E] Error {errors}: {e} at instruction {instruction}", self.COLOR_RED))
                if errors >= MAX_ERROR_COUNT:
                    print(self.colorize("Too many errors, stopping this code object.", self.COLOR_RED))
                    break

        self.assembly_string += f"\n{' ' * indent}{'-' * 80}\n"

    def save_assembly(self, filename, output_file=None):
        """
        Save the disassembly output to a file.

        Args:
            filename (str): Original PYC filename (used for default output name)
            output_file (str, optional): Custom output file path. Defaults to None.

        Returns:
            str: Path to the saved output file
        """
        if output_file:
            out_filename = output_file
        elif filename.endswith('.pyc'):
            out_filename = filename.replace('.pyc', '.pyasm.full.txt')
        else:
            out_filename = filename + '.pyasm.full.txt'

        with open(out_filename, 'w', encoding='utf-8') as f:
            f.write(self.assembly_string)
        return out_filename

    def to_json(self):
        """
        Convert disassembly results to JSON-serializable dictionary.

        Returns:
            dict: Complete analysis results including magic number, version, imports, and code objects
        """
        return {
            "magic_number": self.magic_number,
            "python_version": self.version,
            "imports": list(self.imports),
            "code_objects": self.code_objects
        }

    def extract_requirements(self):
        """
        Generate requirements.txt content from detected imports.

        Separates Python built-in modules from third-party packages and
        maps common package names to pip-installable requirements.

        Returns:
            str: requirements.txt formatted content with comments
        """
        builtins = {
            'sys', 'os', 'json', 'time', 'datetime', 'hashlib', 're', 'struct',
            'argparse', 'pathlib', 'signal', 'platform', 'threading', 'subprocess',
            'socket', 'ssl', 'logging', 'collections', 'itertools', 'functools',
            'random', 'math', 'string', 'io', 'tempfile', 'pickle', 'copy', 'abc',
            'typing', 'enum', 'dataclasses', 'contextlib', 'unittest', 'pdb',
            'traceback', 'inspect', 'ast', 'dis', 'marshal', 'imp', 'importlib',
            'zipfile', 'tarfile', 'shutil', 'glob', 'fnmatch', 'pprint', 'textwrap',
            'base64', 'binascii', 'urllib', 'http', 'email', 'xml', 'html', 'csv',
            'configparser', 'argparse', 'getopt', 'optparse', 'atexit', 'sysconfig'
        }

        third_party_map = {
            'requests': 'requests>=2.28.0',
            'colorama': 'colorama>=0.4.6',
            'bip32utils': 'bip32utils>=0.3.0',
            'eth_account': 'eth-account>=0.9.0',
            'mnemonic': 'mnemonic>=0.20',
            'keyauth': 'keyauth',
            'bip32utils': 'bip32utils',
            'web3': 'web3>=6.0.0',
            'beautifulsoup4': 'beautifulsoup4>=4.12.0',
            'selenium': 'selenium>=4.15.0',
            'numpy': 'numpy>=1.24.0',
            'pandas': 'pandas>=2.0.0',
            'flask': 'Flask>=2.3.0',
            'django': 'Django>=4.2.0',
            'cryptography': 'cryptography>=41.0.0',
            'paramiko': 'paramiko>=3.3.0',
            'pymongo': 'pymongo>=4.5.0',
            'psycopg2': 'psycopg2-binary>=2.9.0',
            'mysql': 'mysql-connector-python>=8.1.0',
            'redis': 'redis>=5.0.0',
            'celery': 'celery>=5.3.0',
            'pytest': 'pytest>=7.4.0',
            'scrapy': 'Scrapy>=2.11.0',
            'tensorflow': 'tensorflow>=2.13.0',
            'torch': 'torch>=2.0.0',
            'transformers': 'transformers>=4.35.0',
            'PIL': 'Pillow>=10.0.0',
            'cv2': 'opencv-python>=4.8.0',
            'tkinter': 'tk',
        }

        requirements = []
        unknown = []

        for imp in sorted(self.imports):
            base_import = imp.split('.')[0]
            base_import = base_import.lower()

            if base_import in builtins:
                continue
            elif base_import in third_party_map:
                requirements.append(third_party_map[base_import])
            else:
                unknown.append(base_import)

        output = []
        output.append("# Auto-generated by pydys")
        output.append(f"# From: {self.filename}")
        output.append(f"# Python version: {self.version}")
        output.append("")

        if requirements:
            output.append("# Known third-party packages:")
            output.extend(sorted(set(requirements)))
            output.append("")

        if unknown:
            output.append("# Unknown packages (manual review needed):")
            for pkg in sorted(set(unknown)):
                output.append(f"# {pkg}")

        return '\n'.join(output)

    def save_requirements(self, filename):
        """
        Save requirements.txt file from detected imports.

        Args:
            filename (str): Original PYC filename (used for default output name)

        Returns:
            str: Path to the saved requirements.txt file
        """
        req_content = self.extract_requirements()
        req_filename = filename.replace('.pyc', '_requirements.txt')
        if not req_filename.endswith('_requirements.txt'):
            req_filename = filename + '_requirements.txt'

        with open(req_filename, 'w', encoding='utf-8') as f:
            f.write(req_content)
        return req_filename

    def disassemble_pyc(self, filename, output_file=None, extract_requirements=False):
        """
        Main entry point for full PYC file disassembly.

        Orchestrates the complete disassembly process: reading the file,
        detecting version, optionally extracting requirements, and
        performing recursive disassembly.

        Args:
            filename (str): Path to the PYC file
            output_file (str, optional): Custom output file path. Defaults to None.
            extract_requirements (bool, optional): Generate requirements.txt. Defaults to False.
        """
        self.filename = filename
        print(self.colorize(f"[+] Loading: {filename}", self.COLOR_BLUE))
        code, self.version = self.read_pyc_file(filename)

        print(self.colorize(f"[V] Detected Version: {self.version}", self.COLOR_BLUE))

        print(self.colorize(f"[I] Imports: {', '.join(sorted(self.imports))}", self.COLOR_BLUE))

        if extract_requirements:
            req_file = self.save_requirements(filename)
            print(self.colorize(f"[R] Requirements saved to: {req_file}", self.COLOR_GREEN))

        print(self.colorize("[0] Starting full recursive disassembly...\n", self.COLOR_GREEN))
        self.disassemble_code(code)

        dumpname = self.save_assembly(filename, output_file)
        print(self.colorize(f"\n[D] Full dump saved to: {dumpname}", self.COLOR_BLUE))
        print(self.colorize("[+] Done! Check the output file for complete structure.\n", self.COLOR_GREEN))

        if self.json_output:
            print(json.dumps(self.to_json(), indent=2))

def main():
    """
    Command-line interface for pydys.

    Parses arguments and orchestrates either version detection or full disassembly.
    """
    parser = argparse.ArgumentParser(
        description="Python PYC Deep Disassembler - Recursive Analysis",
        epilog="""
Examples:
  pydys -f script.pyc                    # Basic analysis
  pydys -f script.pyc --detect-version   # Just detect Python version
  pydys -f script.pyc --json             # JSON output for parsing
  pydys -f script.pyc --no-color         # Plain text for logs
  pydys -f script.pyc -o output.txt      # Custom output file
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--file", "-f", dest="filename", help="PYC file to disassemble", required=True)
    parser.add_argument("--output", "-o", dest="output_file", help="Custom output file path (default: input_name.pyasm.full.txt)")
    parser.add_argument("--no-color", dest="no_color", action="store_true", help="Disable colored output (for CI/CD, logging)")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output in JSON format for programmatic parsing")
    parser.add_argument("--modern", dest="modern_mode", action="store_true", help="Enable Python 3.11+ adaptive features (handles new opcodes)")
    parser.add_argument("--detect-version", dest="detect_only", action="store_true", help="Only detect Python version and exit (dry run)")
    parser.add_argument("--requirements", "-r", dest="extract_requirements", action="store_true", help="Extract requirements.txt from imports")

    args = parser.parse_args()

    if not Path(args.filename).exists():
        print(f"\x1b[91mError: File '{args.filename}' not found\x1b[0m")
        sys.exit(1)

    pydis = Pydis(
        no_color=args.no_color,
        json_output=args.json_output,
        modern_mode=args.modern_mode
    )

    if args.detect_only:
        pydis.detect_version_only(args.filename)
        return

    # Full disassembly )
    pydis.disassemble_pyc(args.filename, args.output_file, args.extract_requirements)


if __name__ == "__main__":
    main()
