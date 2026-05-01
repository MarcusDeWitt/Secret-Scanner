"""
This Module will contain the main CLI tool used to scan incoming files to 
check for patterns that may be malicious. This will be used 
to find hardcoded secrets such as API keys, Passwords, 
tokens and private keys by using regex patterns to match 
against the contents of the file. 
"""

import argparse
import logging
import os
from patterns import PATTERNS
from utils import get_file


def scan_file(file_path):
    findings = []

    try:
        content = get_file(file_path)
        lines = content.split('\n')

        for line_num, line in enumerate(lines, start=1):
            for name, pattern in PATTERNS.items():
                match = pattern.search(line)
                if match:
                    finding = {
                        "file": file_path,
                        "line": line_num,
                        "type": name,
                        "match": match.group(0)
                    }
                    findings.append(finding)

                    logging.info(
                        f"{name} found in {file_path} at line {line_num}: {match.group(0)}"
                    )

    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")

    return findings


def scan_path(path):
    all_findings = []

    if os.path.isfile(path):
        return scan_file(path)

    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                all_findings.extend(scan_file(full_path))
    else:
        raise ValueError("Invalid file or directory path")

    return all_findings


def print_report(findings):
    if not findings:
        print("No secrets found.")
        return

    print("\nSecrets found:\n")

    for f in findings:
        print(f"[{f['type']}] {f['file']}:{f['line']}")
        print(f"  → {f['match']}\n")


def save_report(findings, output_file):
    with open(output_file, 'w') as f:
        if not findings:
            f.write("No secrets found.\n")
            return

        for finding in findings:
            f.write(
                f"[{finding['type']}] {finding['file']}:{finding['line']} -> {finding['match']}\n"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Scan files or directories for hardcoded secrets."
    )

    parser.add_argument(
        "path",
        nargs="?",
        help="File or directory to scan"
    )

    parser.add_argument(
        "-o", "--output",
        help="Save results to a file"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        filename='scanner.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    # Handle user input if no path provided
    path = args.path if args.path else input("Enter file or directory path: ")

    try:
        findings = scan_path(path)

        print_report(findings)

        if args.output:
            save_report(findings, args.output)
            print(f"\nReport saved to {args.output}")

    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Fatal error: {e}")


if __name__ == "__main__":
    main()