'''
This file is a test on using Selenium for automated website request
'''
from WFlib.tools.capture import capture
import argparse
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument('-u', '--url', type=str, help="The website url that Selenium will request")
    parser.add_argument('-d', '--dir', type=str, help="The base dir to which the capture will output")
    parser.add_argument('-i', '--iface', type=str, help="The interface to perform capturing.")
    parser.add_argument('-r', '--repeat', type=int, default=1, help="How many times the request will repeat, if set with <=0, 1 will be used.")
    parser.add_argument('-t', '--timeout', type=int, default=10, help="The living time for a browsing session.")
    args = parser.parse_args()

    repeat = 1 if args.repeat < 1 else args.repeat
    timeout = 10 if args.timeout < 1 else args.timeout

    host = str.split(args.url, "//")[1] # Only fetch the hostname

    for i in range(repeat):
        output_file = os.path.join(args.dir, "{}_{:02d}.pcapng".format(host, i))
        # Create and start the threads
        capture(url=args.url, timeout=timeout, iface=args.iface, output_file=output_file)