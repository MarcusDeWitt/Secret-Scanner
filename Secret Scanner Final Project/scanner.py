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

# Main scanning functions
def scan_file(file_path):
    findings = [] # List to store findings for this file
    # Read file content and scan for patterns
    try:
        content = get_file(file_path)
        lines = content.split('\n') # Split content into lines for easier scanning and reporting
        # Scan each line for matches against our patterns
        for line_num, line in enumerate(lines, start=1):
            for name, pattern in PATTERNS.items():
                match = pattern.search(line)
                if match: # If a match is found, create a finding entry and log it
                    finding = {
                        "file": file_path,
                        "line": line_num,
                        "type": name,
                        "match": match.group(0)
                    }
                    findings.append(finding)
                    # Log the finding with details
                    logging.info(
                        f"{name} found in {file_path} at line {line_num}: {match.group(0)}"
                    )
    # Handle any exceptions that occur during file reading or scanning and log them
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")

    return findings # Return the list of findings for this file

# Function to scan a directory recursively
def scan_path(path):
    all_findings = [] # List to store all findings from the path
    # Check if the path is a file or directory and scan accordingly
    if os.path.isfile(path):
        return scan_file(path)

    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                all_findings.extend(scan_file(full_path))
    else: 
        raise ValueError("Invalid file or directory path") # Raise an error if the path is not valid

    return all_findings # Return the list of all findings from the directory scan

# Reporting functions
def print_report(findings):
    if not findings:
        print("No secrets found.")
        return
    
    print("\nSecrets found:\n")
    # Print each finding in a readable format
    for f in findings:
        print(f"[{f['type']}] {f['file']}:{f['line']}")
        print(f"  → {f['match']}\n")

# Function to save findings to a report file
def save_report(findings, output_file):
    with open(output_file, 'w') as f:
        if not findings:
            f.write("No secrets found.\n")
            return
        # Write each finding to the file in a structured format
        for finding in findings:
            f.write(
                f"[{finding['type']}] {finding['file']}:{finding['line']} -> {finding['match']}\n"
            )

# Main function to handle CLI arguments and orchestrate the scanning process
def main():
    parser = argparse.ArgumentParser(
        description="Scan files or directories for hardcoded secrets."
    )
    # Add argument for file or directory path, making it optional to allow for user input if not provided
    parser.add_argument(
        "path",
        nargs="?",
        help="File or directory to scan"
    )
    # Add argument for output file to save results, making it optional
    parser.add_argument(
        "-o", "--output",
        help="Save results to a file"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        filename='scanner.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s' # Log format to include timestamp, log level, and message
    )

    # Handle user input if no path provided
    path = args.path if args.path else input("Enter file or directory path: ")

    try:
        findings = scan_path(path)

        print_report(findings)
        # Save report to file if output argument is provided
        if args.output:
            save_report(findings, args.output)
            print(f"\nReport saved to {args.output}")
    # Handle any exceptions that occur during the scanning process and log them
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Fatal error: {e}")


if __name__ == "__main__":
    main()
