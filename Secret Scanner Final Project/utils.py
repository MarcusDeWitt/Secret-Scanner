import os

# Utility functions for the secret scanner
def get_file(file_path):
    if not file_path:
        file_path = input("Please enter the file path to scan: ")
    if os.path.isfile(file_path):
        with open(file_path, 'r') as file:
            return file.read()
    else:
        raise FileNotFoundError("File not found")
