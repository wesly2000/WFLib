"""
This file is used to test batch_extract. Also, it could be used as a simple script to for extract features from a 
list of files.

NOTE: Currently, only .pcap files are supported. More file format (.json, .csv, .etc.) would be supported in the future.

NOTE: The extractors are now hard-coded into the script. Passing extractors as flags might be supported in the future.
"""

from WFlib.tools.formatter import DistriPcapFormatter, DirectionExtractor
from WFlib.tools.capture import read_host_list
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dir', type=str, help="The base dir of the .pcap files")
    parser.add_argument('-l', '--length', type=int, default=5000, help="The length of the expect feature vectors")
    # parser.add_argument('-f', '--filter', type=str, default=None, help="The DISPLAY filter")
    parser.add_argument('-s', '--src', type=str, default="192.168.5.5", help="The source IP address")
    parser.add_argument('-o', '--output_file', type=str, help="The path to the files to hold the output file")
    parser.add_argument('-n', '--num_worker', type=int, default=6, help="Number of processes to extract features")
    args = parser.parse_args()

    formatter = DistriPcapFormatter(length=args.length, num_worker=args.num_worker)

    extractor = DirectionExtractor(src=args.src)

    filter_file = "exp/data_extract/filter.txt"
    SNIs = read_host_list(filter_file)

    formatter.batch_extract(args.dir, args.output_file, SNIs, extractor)