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

from selenium.common.exceptions import WebDriverException
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

import pyshark
from pyshark.capture.capture import Capture

import time
import threading
import multiprocessing
import subprocess
from typing import Union
from pathlib import Path
from urllib.parse import urlparse
import os
import time
import warnings
import logging

logger = logging.getLogger('selenium')
logger.setLevel(logging.WARN)

gecko_path = r'/usr/local/bin/geckodriver'

"""
This filter is a Capture Filter to filter the annoying traffic which, with high probability, is NOT related with the
traffic directly generated by requesting the website. Although some protocols DO relate to surfing the Web, e.h., SOAP and DNS,
they do NOT belong to the communication process between the client and server. Therefore, they are NOT included in
the capture.

The semantics of the filter is that we ONLY want TCP or UDP packets, but the following protocols are NOT considered:

LLMNR (5355), MDNS (5353), SOAP (3702), NTP (123), SSDP (1900), SSH (22), RDP (3389), DOT (853), HTTP (80)

NOTE: This filter is not exhausted, and further updates are possible in the future.
NOTE: Plain HTTP (port 80) is excluded after some consideration, since most of the request are based on HTTPS 
"""
common_filter = 'not (port 53 or port 22 or port 3389 or port 5355 or port 5353 or port 3702 or port 123 or port 1900 or port 853 or port 80) and (tcp or udp)'

def capture(url, iface, output_file, timeout=200, capture_filter=common_filter, ill_files=None, log_output=None):
    stop_event = multiprocessing.Event()

    def _sniff():
        tshark_process = subprocess.Popen(
            ['tshark', '-i', iface, '-f', capture_filter, '-w', output_file,],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL 
        )
        try:
            # Monitor the event
            while not stop_event.is_set():
                time.sleep(.1)  # Poll every second
            tshark_process.terminate()
            tshark_process.wait()
        except Exception as e:
            print(f"Error in subprocess: {e}")
        finally:
            if tshark_process.poll() is None:
                tshark_process.terminate()

    def browse():
        time.sleep(2) # maybe waiting for interface to be ready?
        
        service = Service(executable_path=gecko_path, log_output=log_output)

        options = Options()
        options.add_argument("--headless") 
        options.set_preference("browser.cache.disk.enable", False)
        options.set_preference("browser.cache.memory.enable", False)
        options.set_preference("browser.cache.offline.enable", False)
        options.set_preference("network.http.use-cache", False)

        try:
            driver = webdriver.Firefox(options=options, service=service)
        except WebDriverException as e:
            warnings.warn(f"The file {output_file} raises the exception: {e}")
            if ill_files is not None:
                with open(ill_files, 'a+') as f:
                    f.write(f"{output_file}\n")
            time.sleep(2)
            stop_event.set()
            return
            
        # print("Browsing Starts.......................")
        try:
            driver.get(url)
            time.sleep(timeout)
        except Exception as e:
            warnings.warn(f"The file {output_file} raises the exception: {e}")
            if ill_files is not None:
                with open(ill_files, 'a+') as f:
                    f.write(f"{output_file}\n")
        driver.quit()
        
        time.sleep(2)
        # Notify the capture thread that the capturing process is over.
        stop_event.set()

    browse_thread = threading.Thread(target=browse)
    monitor_process = multiprocessing.Process(target=_sniff)
    
    monitor_process.start()
    browse_thread.start()

    browse_thread.join()
    monitor_process.join()

def read_host_list(file) -> list:
    """
    Read the hostname list file, remove the possible duplicates, and store the results into a list.
    """
    def strip_url(url : str) -> str:
        """
        To strip possible protocol descriptors in the URL, e.g., https://.
        """
        if '://' in url: # TODO: Awkward check, make it more robust
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            return hostname
        else:
            return url
    host_list = []
    with open(file, 'r') as f:
        for line in f:
            # print(line)
            if line not in host_list: # Avoid possible dups
                host_list.append(strip_url(line.strip()))

    return host_list

def decide_output_file_idx(directory : Path) -> int:
    """
    Utility function to enable continuous capture, i.e., capture on the same base_dir for multiple times.
    The idea here is to check if the host has been captured previously. If so, fetch the .pcap(ng) file name
    with the largest index, and plus 1 on it for appending. Otherwise, simply return base for directory creation.

    For example, if the original directory is as follows.
    ```
    base_dir
       |---www.baidu.com
       |         |---www.baidu.com_00.pcapng
       |         |---www.baidu.com_02.pcapng (Note that 01 was missing due to some reason)
       |
       |---www.google.com
       |         |---www.google.com_00.pcapng
    ```

    And the capture list is ['www.baidu.com', 'www.google.com', 'www.zhihu.com'], repeat is set to 1. Then, after performing
    capture, the directory should be as follows.
    ```
    base_dir
       |---www.baidu.com
       |         |---www.baidu.com_00.pcapng
       |         |---www.baidu.com_02.pcapng 
       |         |---www.baidu.com_03.pcapng
       |
       |---www.google.com
       |         |---www.google.com_00.pcapng
       |         |---www.google.com_01.pcapng
       |
       |---www.zhihu.com
       |         |---www.zhihu.com_00.pcapng
    ```
    """
    
    if not os.path.exists(directory):
        return 0 
    max_idx = 0
    for file in directory.iterdir():
        if file.is_file() and file.suffix in ['.pcapng', '.pcap']:  # Ensure it's a .pcap(ng) file
            cur_idx = int(file.name.split('_')[-1].split('.')[0])
            max_idx = max(cur_idx, max_idx)

    return 1 + max_idx

def batch_capture(base_dir, host_list, iface, 
                  capture_fileter=common_filter, 
                  repeat=20, 
                  timeout=200, 
                  ill_files=None,
                  log_output=None):
    """
    Capture the traffic of a list of hosts. The capturing and storing process is illustrated as follows.
    Suppose the host_list = [www.baidu.com, www.zhihu.com, www.google.com], and the base_dir is set to
    $home. Moreover, repeat is set to 2. Then, the resulting capture directory should be

    ```
    $home
      |------www.baidu.com
      |            |---------www.baidu.com_00.pcap
      |            |---------www.baidu.com_01.pcap
      |
      |------www.zhihu.com
      |            |---------www.zhihu.com_00.pcap
      |            |---------www.zhihu.com_01.pcap
      |
      |------www.google.com
      |             |---------www.google.com_00.pcap
      |             |---------www.google.com_01.pcap
    ```

    NOTE: Currently, batch_capture by default using HTTPS for requesting. So the caller needs not
    to add 'https://' before the hostname.

    Params
    ------
    base_dir : str
        The base directory to hold all captures for each hostname.

    host_list : list
        The list of hostnames to perform capture.

    iface : str
        The inferface to perform capture.

    capture_filter : str
        The capture filter using the BPF syntax to pass to tshark, common_filter is used by default.

    repeat : int
        The number of repetitive capture towards the same hostname, note that repeat should be large
        enough (>=20) to obtain a stable website fingerprint.

    timeout : int
        The amount of seconds after which the headless browser would stop. Timeout should be large
        enough for the website to load entirely.

    log_output : str
        The path for Selenium to record the debug log files.
    """
    proto_header = "https://"
    # Handle directory, create if necessary. 
    # Ref: https://stackoverflow.com/questions/273192/how-do-i-create-a-directory-and-any-missing-parent-directories
    for i in range(repeat):
        for host in host_list:
            # Create a proper subdirectory for each host. Set parents=True to create base_dir if needed.
            # set exist_ok=True to avoid FileExistsError.
            host = host.strip()
            output_dir = Path("{}/{}".format(base_dir, host))

            output_file_idx = decide_output_file_idx(directory=output_dir)
            output_file = os.path.join(base_dir, host, "{}_{}.pcapng".format(host, output_file_idx))
            
            output_dir.mkdir(parents=True, exist_ok=True)
            url = proto_header + host
            # start_time = time.time()
            
            capture(url=url, 
                    timeout=timeout, 
                    iface=iface, 
                    output_file=output_file,
                    capture_filter=capture_fileter,
                    ill_files=ill_files,
                    log_output=log_output)
            
            time.sleep(5)  # Avoid previous session traffic to affect succeeding capture.
            
            # end_time = time.time()
            # print(f"Captured {host}_{i:02d}.pcapng, time duration {end_time-start_time:.2f} seconds.")

def SNI_extract(capture : Capture) -> set:
    """
    Extract all SNIs from a capture, and return a set that contains these SNIs.
    """
    SNIs = set()

    def process_packet(packet):
        try:
            if 'TLS' in packet:
                tls_layer = packet['TLS']
                if hasattr(tls_layer, 'handshake_extensions_server_name'):
                    SNI = tls_layer.handshake_extensions_server_name
                    SNIs.add(SNI)
        except AttributeError as e:
            # Handle packets that don't have the expected structure
            print(f"Error processing packet: {e}")

    for pkt in capture:
        process_packet(pkt)
    return SNIs

def stream_number_extract(capture : Capture, check) -> set:
    """
    Extract all TCP stream numbers for the streams where at least one packet within satisfies
    the condition required by the check.

    For example, if the check checks whether a TLS session is for SNI=www.baidu.com, it iterates
    over all the packets (all Client Hello's actually), if some packet contains the SNI, the tcp.stream
    numbers will be recorded.

    TODO: Currently, the extractor only works for TCP-based protocols. Integrating the support for UDP will
    be finished in the future. :)

    Parameter
    ---------
    check : function(pkt) -> bool
        The check on packet. Return TRUE if the packet satisfies the condition.

    Return
    ------
    set : The set contains the stream numbers each of which contains at least 1 packet satisfying check.
    """
    stream_numbers = set(pkt['TCP'].stream for pkt in capture if 'TCP' in pkt and check(pkt))
    return stream_numbers

def stream_extract_filter(stream_numbers : Union[list, set]):
    """
    Extract the streams with the given stream_numbers from input_file, and write the results to output_file.
    """
    extended_stream_numbers = ["tcp.stream == " + stream_number for stream_number in stream_numbers]
    display_filter = " or ".join(extended_stream_numbers)

    return display_filter

def stream_exclude_filter(stream_numbers : Union[list, set]):
    """
    Remove the streams with the given stream_numbers from input_file, and write the other streams to output_file.
    """
    extended_stream_numbers = ["tcp.stream != " + stream_number for stream_number in stream_numbers]
    display_filter = " and ".join(extended_stream_numbers)

    return display_filter

def contains_SNI(SNIs, pkt):
    if SNIs is None or len(SNIs) == 0:
        return False
    result = False

    if 'TLS' in pkt:
        tls_layer = pkt['TLS']
        if hasattr(tls_layer, 'handshake_extensions_server_name'):
            SNI = tls_layer.handshake_extensions_server_name
            if SNI in SNIs:
                return True
            
    return result

def SNI_exclude_filter(file, SNIs):
    """
    Create a display filter for the given .pcap file which exclude all the TCP streams that contains the SNI in SNIs.

    Params
    ------
    file : str
        The file path to the .pcap(ng) file.

    SNIs : list
        The SNIs for each of which to exclude the corresponding TCP stream.

    Returns
    -------
    filter : str
        The display filter created from the .pcap file and SNIs.
    """
    if SNIs is None or len(SNIs) == 0:
        return None
    client_hello_capture = pyshark.FileCapture(input_file=file, display_filter="tls.handshake.type == 1")
    stream_numbers = stream_number_extract(capture=client_hello_capture, check=lambda pkt: contains_SNI(SNIs, pkt))
    client_hello_capture.close()
    display_filter = stream_exclude_filter(stream_numbers)
    return display_filter