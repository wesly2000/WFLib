from WFlib.tools.capture import *
from WFlib.tools.formatter import *

import io
import json
import tempfile

def test_PcapFormatter_1():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the direction feature.
    This test makes feature vector length smaller than the number of packets to test truncation.
    """
    extractor = DirectionExtractor(src="192.168.5.5")

    formatter = PcapFormatter(length=5)
    formatter.load("exp/test_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.baidu.com"]), "labels": np.array([0]), "direction": np.array([[1, 1, 1, 1, 1]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_2():
    """
    This test covers reading the first 10 packets from a .pcap file, and extract the direction feature.
    This test makes feature vector length larger than the number of packets to test padding.
    """
    extractor = DirectionExtractor(src="192.168.5.5")

    formatter = PcapFormatter(length=12)
    formatter.load("exp/test_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.baidu.com"]), "labels": np.array([0]), "direction": np.array([[1, 1, 1, 1, 1, 1, -1, 1, 1, -1, 0, 0]])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_3():
    """
    This test covers reading the first 10 packets from multiple .pcap files, and extract the direction feature.
    """
    formatter = PcapFormatter(length=10)

    extractor = DirectionExtractor(src="192.168.5.5")

    formatter.load("exp/test_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_pcap_02.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_pcap_03.pcapng")
    formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.baidu.com", "www.zhihu.com"]), 
              "labels": np.array([0, 0, 1]), 
              "direction": np.array([
                  [1, 1, 1, 1, 1, 1, -1, 1, 1, -1],
                  [1, 1, -1, 1, 1, 0, 0, 0, 0, 0],
                  [-1, -1, 1, -1, 1, -1, 1, 1, -1, -1]
                  ])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_4():
    """
    This test covers reading the first 10 packets from multiple .pcap files, and extract the direction feature.
    This test involves the use of display filter.
    """
    formatter = PcapFormatter(length=10, display_filter='tls')

    extractor = DirectionExtractor(src="192.168.5.5")
    
    formatter.load("exp/test_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_pcap_02.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_pcap_03.pcapng")
    formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    buffer = io.BytesIO()

    formatter.dump(buffer)

    buffer.seek(0)  # Move to the start of the buffer
    loaded_data = np.load(buffer)

    target = {"hosts" : np.array(["www.baidu.com", "www.zhihu.com"]), 
              "labels": np.array([0, 0, 1]), 
              "direction": np.array([
                  [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                  [1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                  [-1, -1, -1, 1, -1, -1, 0, 0, 0, 0]
                  ])}
    for k, v in loaded_data.items():
        assert np.all(target[k] == v)

    loaded_data.close()

def test_PcapFormatter_5():
    """
    This test covers reading the first 10 packets from multiple .pcap files, and extract the direction feature.
    This test involves the use of display filter.
    """
    formatter = PcapFormatter(display_filter='tls')

    extractor = DirectionExtractor(src="192.168.5.5")
    
    formatter.load("exp/test_dataset/simple_pcap_01.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_pcap_02.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    formatter.load("exp/test_dataset/simple_pcap_03.pcapng")
    formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    with tempfile.NamedTemporaryFile(mode="r+", delete=True) as temp_file:
        formatter.dump(temp_file.name)
        loaded_data = json.load(temp_file)

        target = {"hosts" : ["www.baidu.com", "www.zhihu.com"], 
                "labels": [0, 0, 1], 
                "direction": [
                    [1],
                    [1, 1],
                    [-1, -1, -1, 1, -1, -1]
                    ]}
        for k, v in loaded_data.items():
            for i in range(len(v)):
                assert target[k][i] == v[i]

def test_JsonFormatter_1():
    """
    This test covers reading a .json file, and extract the direction feature, truncate/pad it to given length,
    and dump it into a .npz file.
    """
    pcap_formatter = PcapFormatter(display_filter='tls')

    extractor = DirectionExtractor(src="192.168.5.5")
    
    pcap_formatter.load("exp/test_dataset/simple_pcap_01.pcapng")
    pcap_formatter.transform("www.baidu.com", 0, extractor)

    pcap_formatter.load("exp/test_dataset/simple_pcap_02.pcapng")
    pcap_formatter.transform("www.baidu.com", 0, extractor)

    pcap_formatter.load("exp/test_dataset/simple_pcap_03.pcapng")
    pcap_formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    with tempfile.NamedTemporaryFile(mode="r+", delete=True) as temp_file:
        pcap_formatter.dump(temp_file.name)
        json_formatter = JsonFormatter()
        json_formatter.load(temp_file)
        json_formatter.transform(direction=10)

        # Create an in-memory bytes buffer
        buffer = io.BytesIO()
        json_formatter.dump(buffer)
        buffer.seek(0)  # Move to the start of the buffer
        loaded_data = np.load(buffer)

        target = {"hosts" : np.array(["www.baidu.com", "www.zhihu.com"]), 
                "labels": np.array([0, 0, 1]), 
                "direction": np.array([
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
                    [-1, -1, -1, 1, -1, -1, 0, 0, 0, 0]
                    ])}
        
        for k, v in loaded_data.items():
            assert np.all(target[k] == v)

        loaded_data.close()

def test_JsonFormatter_2():
    """
    This test covers the statistics with JsonFormatter.
    """
    pcap_formatter = PcapFormatter(display_filter='tls')

    extractor = DirectionExtractor(src="192.168.5.5")
    
    pcap_formatter.load("exp/test_dataset/simple_pcap_01.pcapng")
    pcap_formatter.transform("www.baidu.com", 0, extractor)

    pcap_formatter.load("exp/test_dataset/simple_pcap_02.pcapng")
    pcap_formatter.transform("www.baidu.com", 0, extractor)

    pcap_formatter.load("exp/test_dataset/simple_pcap_03.pcapng")
    pcap_formatter.transform("www.zhihu.com", 1, extractor)

    # Create an in-memory bytes buffer
    with tempfile.NamedTemporaryFile(mode="r+", delete=True) as temp_file:
        pcap_formatter.dump(temp_file.name)
        json_formatter = JsonFormatter()
        json_formatter.load(temp_file)

        hosts = json_formatter.get_feature_buf('hosts')
        target = ["www.baidu.com", "www.zhihu.com"]
        for i in range(len(target)):
            assert hosts[i] == target[i]

        target = [[1], [1, 1], [-1, -1, -1, 1, -1, -1]]
        directions = json_formatter.get_feature_buf('direction')
        for i in range(len(target)):
            for j in range(len(target[i])):
                assert target[i][j] == directions[i][j]