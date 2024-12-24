"""
A module for website browsing and traffic capture. Ideally, they should work coorperatively
in an asynchronized style. The general workflow is as follows.

main        ----------------------------------------------------------------------------------------------------->
                         |      |                                                           ^       ^
browsing                 |      v-----------------------------------------------------------|       |
                         |                                                                          |
sniff                    v---------------------------------------------------------------------------
                         |                                                                          |
capture                  |--------------------------------------------------------------------------|
"""

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

from scapy.all import sniff, wrpcap

import time
import threading

gecko_path = r'/usr/local/bin/geckodriver'

def capture(url, timeout, iface, output_file, log_output=None):
    # TODO: Add some capture filter
    stop_event = threading.Event()

    def _sniff(iface, output_file):
        print("Capturing Starts.......................")
        capture = sniff(iface=iface, stop_filter=lambda _: stop_event.is_set())
        wrpcap(output_file, capture)
        print("Capturing Ends.......................")

    def browse(url, timeout, log_output=None):
        time.sleep(1) # maybe waiting for interface to be ready?
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
        time.sleep(timeout)
        # Notify the capture thread that the capturing process is over.
        stop_event.set()
        driver.quit()
        print("Browsing Ends.......................")

    browse_thread = threading.Thread(target=browse, kwargs={"url": url, "timeout": timeout})
    capture_thread = threading.Thread(target=_sniff, kwargs={"iface": iface, "output_file": output_file})

    capture_thread.start()
    browse_thread.start()

    browse_thread.join()
    capture_thread.join()