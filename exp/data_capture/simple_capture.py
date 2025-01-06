'''
This file is a test on using Selenium for automated website request
'''
from WFlib.tools.capture import capture
import argparse
import os
from pathlib import Path

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument('-u', '--url', type=str, help="The website url that Selenium will request")
    parser.add_argument('-d', '--dir', type=str, help="The base dir to which the capture will output")
    parser.add_argument('-i', '--iface', type=str, help="The interface to perform capturing.")
    parser.add_argument('-r', '--repeat', type=int, default=1, help="How many times the request will repeat, if set with <=0, 1 will be used.")
    parser.add_argument('-t', '--timeout', type=int, default=200, help="The living time for a browsing session.")
    parser.add_argument('--dry-run', action='store_true', help="To output the file names will be created without actual creation.")
    args = parser.parse_args()

    repeat = 1 if args.repeat < 1 else args.repeat
    timeout = 10 if args.timeout < 1 else args.timeout

    ssl_keylog_file = os.path.join(args.dir, "keylog.txt")
    host = str.split(args.url, "//")[1] # Only fetch the hostname

    if args.dry_run:
        print("Dry run mode, the file names are listed below:")
        for i in range(repeat):
            output_file = os.path.join(args.dir, "{}_{:02d}.pcapng".format(host, i))
            print(f"{output_file}")
        print(f"{ssl_keylog_file}")
    else:
        os.environ["SSLKEYLOGFILE"] = ssl_keylog_file
        for i in range(repeat):
            # Set SSLKEYLOGFILE variable
            Path("{}/{}".format(args.dir, host)).mkdir(parents=True, exist_ok=True)
            output_file = os.path.join(args.dir, "{}_{:02d}.pcapng".format(host, i))
            # Create and start the threads
            capture(url=args.url, timeout=timeout, iface=args.iface, output_file=output_file)