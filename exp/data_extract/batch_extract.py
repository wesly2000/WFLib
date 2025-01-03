"""
This file is used to test batch_extract. Also, it could be used as a simple script to for extract features from a 
list of files.

NOTE: Currently, only .pcap files are supported. More file format (.json, .csv, .etc.) would be supported in the future.

NOTE: The extractors are now hard-coded into the script. Passing extractors as flags might be supported in the future.
"""

from WFlib.tools.formatter import PcapFormatter, DirectionExtractor
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', type=str, help="The base dir of the .pcap files")
    parser.add_argument('-l', '--length', type=int, default=0, help="The length of the expect feature vectors")
    # parser.add_argument('-f', '--filter', type=str, default=None, help="The DISPLAY filter")
    parser.add_argument('-s', '--src', type=str, default="192.168.5.5", help="The source IP address")
    parser.add_argument('-o', '--output_file', type=str, help="The path to the files to hold the output file")
    args = parser.parse_args()

    formatter = PcapFormatter(length=args.length)

    extractor = DirectionExtractor(src=args.src)

    formatter.batch_extract(args.dir, args.output_file, extractor)