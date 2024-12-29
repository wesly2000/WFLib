from WFlib.tools.capture import *
from WFlib.tools.formatter import *
import pyshark
import io

def test_SNI_extract():
    capture = pyshark.FileCapture(input_file="exp/test_dataset/www.baidu.com_proxied.pcapng", display_filter="tls.handshake.type == 1")
    SNIs = SNI_extract(capture)

    target = {
        "dns.alidns.com",
        "doh.pub",
        "dns.cloudflare.com",
        "firefox.settings.services.mozilla.com",
        "content-signature-2.cdn.mozilla.net",
        "firefox-settings-attachments.cdn.mozilla.net",
        "dns.twnic.tw"
    }

    assert SNIs == target

    capture.close()

def test_stream_number_extract():
    capture = pyshark.FileCapture(input_file="exp/test_dataset/www.baidu.com_proxied.pcapng", display_filter="tls.handshake.type == 1")
    SNIs = SNI_extract(capture)

    def contains_SNI(pkt):
        result = False

        if 'TLS' in pkt:
            tls_layer = pkt['TLS']
            if hasattr(tls_layer, 'handshake_extensions_server_name'):
                SNI = tls_layer.handshake_extensions_server_name
                if SNI in SNIs:
                    return True
                
        return result
    
    stream_number = stream_number_extract(capture=capture, check=contains_SNI)

    target = {'1', '4', '3', '10', '11', '13', '14', '65', '68', '67', '66', '69', '97', '101', '105', '123'}

    assert stream_number == target

    capture.close()

def test_stream_extract_filter():
    stream_numbers = []
    display_filter = stream_extract_filter(stream_numbers)
    target = ""
    assert display_filter == target

    stream_numbers = ['1', '4', '3']
    display_filter = stream_extract_filter(stream_numbers)
    target = "tcp.stream == 1 or tcp.stream == 4 or tcp.stream == 3"

    assert display_filter == target

def test_stream_exclude_filter():
    stream_numbers = []
    display_filter = stream_exclude_filter(stream_numbers)
    target = ""
    assert display_filter == target

    stream_numbers = ['1', '4', '3']
    display_filter = stream_exclude_filter(stream_numbers)
    target = "tcp.stream != 1 and tcp.stream != 4 and tcp.stream != 3"

    assert display_filter == target

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

    extractor = DirectionExtractor(src="192.168.5.5")
    formatter.load("exp/test_dataset/simple_pcap_02.pcapng")
    formatter.transform("www.baidu.com", 0, extractor)

    extractor = DirectionExtractor(src="192.168.5.5")
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