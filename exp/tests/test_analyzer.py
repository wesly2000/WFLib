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
    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
    byte_count, pkt_count = 0, 0
    for pkt in capture:
        cnt = counter.count(pkt)
        if cnt > 0:
            pkt_count += 1
            byte_count += cnt

    byte_target, packet_target = 3242, 9

    capture.close()
    
    assert byte_target == byte_count and packet_target == pkt_count

def test_tcp_bytes_count():
    counter = TCPByteCounter()

    keylog_file = "exp/test_dataset/realworld_dataset/decryption/keylog.txt"
    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    
    byte_count, pkt_count = 0, 0
    for pkt in capture:
        cnt = counter.count(pkt)
        if cnt > 0:
            pkt_count += 1
            byte_count += cnt
    byte_target, packet_target = 11408, 32

    capture.close()
    
    assert byte_target == byte_count and packet_target == pkt_count