"""
This file aims to do some clean-up for the files specified by the given file (ill_files.txt by default).
The user could specify 
"""

import os
import sys
import argparse

def delete_files(file_path, verbose=False, clear_content=False):
    try:
        # Open the list file for reading
        with open(file_path, 'r') as f:
            filenames = f.readlines()
        # Process each filename
        for filename in filenames:
            filename = filename.strip()  # Remove leading/trailing whitespace and newline characters
            if os.path.isfile(filename):
                try:
                    os.remove(filename)
                    if verbose:
                        print(f"Deleted file: {filename}")
                except Exception as e:
                    print(f"Error deleting file {filename}: {e}")
            else:
                print(f"File does not exist: {filename}")

        if clear_content:
            # Clear the content of the list file
            with open(file_path, 'w') as f:
                f.truncate(0)  # Clear file content
            print(f"Cleared the content of {file_path}")
    
    except Exception as e:
        print(f"An error occurred: {e}")

def ask_proceed():
    while True:
        user_input = input("Proceed? [Y/N]").strip().lower()
        if not user_input:  # Default action
            user_input = 'y'  # Assume 'yes' as the default
        if user_input in {'y', 'yes'}:
            return True
        elif user_input in {'n', 'no'}:
            print(f"Operation cancelled...")
            return False
        else:
            print("Invalid input. Please enter 'Y' or 'N'.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--list', type=str, help="The file list to delete")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument('--clear-content', action='store_true', help="If specified, the content of the specified file will be cleared")
    args = parser.parse_args()

    try:
        # Open the list file for reading
        with open(args.list, 'r') as f:
            filenames = f.readlines()
        # Process each filename
        print("The following files will be removed:")
        for filename in filenames:
            filename = filename.strip()  # Remove leading/trailing whitespace and newline characters
            print(f'\t{filename}')
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

    if not ask_proceed():
        sys.exit(0)

    delete_files(file_path=args.list, verbose=args.verbose, clear_content=args.clear_content)