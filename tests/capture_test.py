'''
This file is a test on using Selenium for automated website request
'''
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
import argparse
import time
import threading
import pyshark
import os

gecko_path = r'/usr/local/bin/geckodriver'
stop_event = threading.Event()

def browse(url, interval, log_output=None):
    time.sleep(5)
    service = Service(executable_path=gecko_path, log_output=log_output)

    options = Options()
    options.add_argument("--headless") 
    options.set_preference("browser.cache.disk.enable", False)
    options.set_preference("browser.cache.memory.enable", False)
    options.set_preference("browser.cache.offline.enable", False)
    options.set_preference("network.http.use-cache", False)

    driver = webdriver.Firefox(options=options, service=service)
    print("Browsing Starts.......................")
    driver.get(url)
    time.sleep(interval)
    # Notify the capture thread that the capturing process is over.
    stop_event.set()
    driver.quit()
    print("Browsing Ends.......................")

def capture(iface, output_file):
    # TODO: Add some capture filter
    capture = pyshark.LiveCapture(interface=iface, output_file=output_file)
    # Comment out the following line for TShark debugging
    # capture.set_debug(set_to=True) 
    # Keep capturing until the stop event is set
    capture.sniff(timeout=60)
    # print("Capturing Starts.......................")
    # while not stop_event.is_set():
    #     # Capture the next packet, but do nothing with it
    #     next(capture.sniff_continuously())

    # # Once the event is set, stop capturing
    # capture.close()
    print("Capturing Ends.......................")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Flag argument
    parser.add_argument('-u', '--url', type=str, help="The website url that Selenium will request")
    parser.add_argument('-d', '--dir', type=str, help="The base dir to which the capture will output")
    parser.add_argument("--iface", type=str, help="The interface to perform capturing.")
    parser.add_argument('-r', '--repeat', type=int, default=1, help="How many times the request will repeat, if set with <=0, 1 will be used.")
    parser.add_argument('-i', '--interval', type=int, default=10, help="The interval between 2 consecutive requests.")
    args = parser.parse_args()

    repeat = 1 if args.repeat < 1 else args.repeat
    interval = 10 if args.interval < 1 else args.interval

    host = str.split(args.url, "//")[1] # Only fetch the hostname

    for i in range(repeat):
        output_file = os.path.join(args.dir, "{}_{:02d}.pcapng".format(host, i))
        # Create and start the threads
        browse_thread = threading.Thread(target=browse, kwargs={"url": args.url, "interval": args.interval})
        capture_thread = threading.Thread(target=capture, kwargs={"iface": args.iface, "output_file": output_file})

        capture_thread.start()
        # time.sleep(5) # Maybe we should wait for TShark to launch for some time?
        browse_thread.start()
        

        # Wait for both threads to finish
        browse_thread.join()
        capture_thread.join()

        # stop_event.clear()

