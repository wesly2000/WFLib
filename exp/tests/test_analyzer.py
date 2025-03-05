"""
This file covers tests for WFlib/tools/analyzer.py
"""
from WFlib.tools.analyzer import packet_count, file_count, http2_bytes_count
from pathlib import Path
import pyshark
import os

baidu_proxied_file = "exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng"
google_file = "exp/test_dataset/realworld_dataset/www.google.com.pcapng"
apple_file = "exp/test_dataset/realworld_dataset/www.apple.com.pcapng"

def test_packet_count_01():
    target = 8627
    cnt = packet_count(baidu_proxied_file)

    assert target == cnt

def test_packet_count_02():
    target = 8564
    cnt = packet_count(file=baidu_proxied_file, display_filter="tcp")

    assert target == cnt

def test_file_count():
    base_dir = Path("exp/test_dataset")
    target = {"realworld_dataset": 2, "simple_dataset": 3}

    result = file_count(base_dir)

    assert len(target) == len(result)

    for k in result:
        assert result[k] == target[k]

def test_http2():
    keylog_file = "exp/test_dataset/realworld_dataset/keylog.txt"
    capture = pyshark.FileCapture(input_file=apple_file, display_filter="tcp.stream == 2",
                                  override_prefs={'tls.keylog_file': os.path.abspath(keylog_file)})
    target = 3242
    result = http2_bytes_count(capture)
    
    assert target == result