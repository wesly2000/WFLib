"""
This file covers tests for WFlib/tools/analyzer.py
"""
from WFlib.tools.analyzer import packet_count

def test_packet_count_01():
    target = 8627
    cnt = packet_count("exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng")

    assert target == cnt

def test_packet_count_02():
    target = 8564
    cnt = packet_count(file="exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng",
                       display_filter="tcp")

    assert target == cnt