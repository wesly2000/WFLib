"""
This file covers tests for WFlib/tools/analyzer.py
"""
from WFlib.tools.analyzer import *
from pathlib import Path
import pyshark
import os

baidu_proxied_file = "exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng"
google_file = "exp/test_dataset/realworld_dataset/www.google.com.pcapng"
apple_file = "exp/test_dataset/realworld_dataset/decryption/www.apple.com.pcapng"
tiktok_file = "exp/test_dataset/realworld_dataset/decryption/www.tiktok.com.pcapng"

def test_packet_count_01():
    target = 8627
    cap = pyshark.FileCapture(input_file=baidu_proxied_file, only_summaries=True, keep_packets=False)
    cnt = packet_count(cap)

    cap.close()

    assert target == cnt

def test_packet_count_02():
    target = 8564
    cap = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter="tcp", only_summaries=True, keep_packets=False)
    cnt = packet_count(cap)

    cap.close()

    assert target == cnt

def test_file_count():
    base_dir = Path("exp/test_dataset")
    target = {"realworld_dataset": 2, "simple_dataset": 3}

    result = file_count(base_dir)

    assert len(target) == len(result)

    for k in result:
        assert result[k] == target[k]

def test_http2_bytes_count():
    counter = HTTP2ByteCounter()

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2 and http2",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
    byte_count, pkt_count = 0, 0
    for pkt in capture:
        byte_count += counter.count(pkt)
        pkt_count += 1

    byte_target, packet_target = 3242, 9

    capture.close()
    
    assert byte_target == byte_count and packet_target == pkt_count

def test_tcp_bytes_count():
    counter = TCPByteCounter()

    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2")
    
    byte_count, pkt_count = 0, 0
    for pkt in capture:
        byte_count += counter.count(pkt)
        pkt_count += 1

    byte_target, packet_target = 11408, 32

    capture.close()
    
    assert byte_target == byte_count and packet_target == pkt_count

def test_tls_bytes_count():
    counter = TLSByteCounter()

    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2 and tls")
    
    byte_count, pkt_count = 0, 0
    for pkt in capture:
        byte_count += counter.count(pkt)
        pkt_count += 1

    byte_target, packet_target = 10347, 16

    capture.close()
    
    assert byte_target == byte_count and packet_target == pkt_count

def test_udp_bytes_count():
    counter = UDPByteCounter()

    capture = pyshark.FileCapture(input_file=tiktok_file, display_filter="udp.stream == 0")

    byte_count, pkt_count = 0, 0

    for pkt in capture:
        byte_count += counter.count(pkt)
        pkt_count += 1

    byte_target, packet_target = 56518, 80

    capture.close() 

    assert byte_target == byte_count and packet_target == pkt_count

def test_quic_bytes_count():
    counter = QUICByteCounter()

    capture = pyshark.FileCapture(input_file=tiktok_file, display_filter="udp.stream == 0 and quic")

    byte_count, pkt_count = 0, 0
    
    for pkt in capture:
        byte_count += counter.count(pkt)
        pkt_count += 1

    byte_target, packet_target = 55878, 80

    capture.close()

    assert byte_target == byte_count and packet_target == pkt_count

def test_http3_bytes_count():
    counter = HTTP3ByteCounter()

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    capture = pyshark.FileCapture(input_file=tiktok_file, display_filter="udp.stream == 0 and http3",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})

    byte_count, pkt_count = 0, 0
    for pkt in capture:
        byte_count += counter.count(pkt)
        pkt_count += 1

    byte_target, packet_target = 42925, 22

    assert byte_target == byte_count and packet_target == pkt_count


def test_capture_counter_1():
    """
    This test covers TCP/TLS/HTTP2 layered counter to the given capture.
    """
    counter = CaptureCounter(TCPByteCounter(), TLSByteCounter(), HTTP2ByteCounter())

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
    result = counter.count(capture)

    capture.close()

    assert  result['tcp'][0] == 32 and result['tcp'][1] == 11408 and \
            result['tls'][0] == 16 and result['tls'][1] == 10347 and \
            result['http2'][0] == 9 and result['http2'][1] == 3242
    
def test_capture_counter_2():
    """
    This test covers UDP/QUIC/HTTP3 layered counter to the given capture."
    """
    counter = CaptureCounter(UDPByteCounter(), QUICByteCounter(), HTTP3ByteCounter())

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"

    capture = pyshark.FileCapture(input_file=tiktok_file, display_filter="udp.stream == 0",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})

    result = counter.count(capture)

    capture.close()

    assert result['udp'][0] == 80 and result['udp'][1] == 56518 and \
           result['quic'][0] == 80 and result['quic'][1] == 55878 and \
           result['http3'][0] == 22 and result['http3'][1] == 42925