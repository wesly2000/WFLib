"""
This file is used to test batch_capture. Also, it could be used as a simple script to for capture.
"""

from WFlib.tools.capture import batch_capture, read_host_list
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument('-l', '--list', type=str, help="The hostname list file to read")
    parser.add_argument('-d', '--dir', type=str, help="The base dir to which the capture will output")
    parser.add_argument('-i', '--iface', type=str, help="The interface to perform capturing")
    parser.add_argument('-r', '--repeat', type=int, default=20, help="How many times the request will repeat")
    parser.add_argument('-t', '--timeout', type=int, default=200, help="The living time for a browsing session")
    args = parser.parse_args()

    host_list = read_host_list(args.list)

    batch_capture(base_dir=args.dir, host_list=host_list, iface=args.iface, repeat=args.repeat, timeout=args.timeout)