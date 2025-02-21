from WFlib.tools.capture import *
from WFlib.tools.analyzer import packet_count
import pyshark


baidu_proxied_file = "exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng"
google_file = "exp/test_dataset/realworld_dataset/www.google.com.pcapng"

def test_SNI_extract_1():
    capture = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter="tls.handshake.type == 1")
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

def test_SNI_extract_2():
    capture = pyshark.FileCapture(input_file=google_file, display_filter="tls.handshake.type == 1")
    SNIs = SNI_extract(capture)

    target = {
        "mobile.events.data.microsoft.com",
        "firefox-settings-attachments.cdn.mozilla.net",
        "www.google.com",
        "csp.withgoogle.com",
        "www.gstatic.com",
        "ogads-pa.googleapis.com"
    }

    assert SNIs == target

    capture.close()

def test_stream_number_extract():
    capture = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter="tls.handshake.type == 1")
    SNIs = SNI_extract(capture)
    
    tcp_stream_numbers, _ = stream_number_extract(capture=capture, check=lambda pkt: contains_SNI(SNIs, pkt))

    target = {'1', '4', '3', '10', '11', '13', '14', '65', '68', '67', '66', '69', '97', '101', '105', '123'}

    assert tcp_stream_numbers == target

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

def test_stream_exclude_filter_1():
    tcp_stream_numbers, udp_stream_numbers = [], []
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "(tcp or udp) and not icmp"
    assert display_filter == target

def test_stream_exclude_filter_2():
    tcp_stream_numbers, udp_stream_numbers = ['1', '4', '3'], []
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "((tcp and tcp.stream != 1 and tcp.stream != 4 and tcp.stream != 3) or udp) and not icmp"

    assert display_filter == target

def test_stream_exclude_filter_3():
    tcp_stream_numbers, udp_stream_numbers = [], ['1', '4', '3']
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "(tcp or (udp and udp.stream != 1 and udp.stream != 4 and udp.stream != 3)) and not icmp"

    assert display_filter == target

def test_stream_exclude_filter_4():
    tcp_stream_numbers, udp_stream_numbers = ['2', '5'], ['1', '4', '3']
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "((tcp and tcp.stream != 2 and tcp.stream != 5) or (udp and udp.stream != 1 and udp.stream != 4 and udp.stream != 3)) and not icmp"

    assert display_filter == target

def test_SNI_exclude_filter_1():
    SNIs = read_host_list("exp/data_extract/filter.txt")

    client_hello_capture = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter="tls.handshake.type == 1")
    tcp_stream_numbers, _ = stream_number_extract(capture=client_hello_capture, check=lambda pkt: contains_SNI(SNIs, pkt))
    client_hello_capture.close()

    display_filter = SNI_exclude_filter(baidu_proxied_file, SNIs)

    capture = pyshark.FileCapture(input_file=baidu_proxied_file, display_filter=display_filter)
    for pkt in capture:
        if 'TCP' in pkt:
            assert pkt['TCP'].stream not in tcp_stream_numbers 

    capture.close()

def test_SNI_exclude_filter_2():
    """
    This test covers filtering out TCP streams and UDP streams once their SNI lies in the given
    SNIs set.
    """
    target = 16
    SNIs = ['www.google.com', 'mobile.events.data.microsoft.com']
    display_filter = SNI_exclude_filter(google_file, SNIs)

    cnt = packet_count(file=google_file,
                       display_filter=display_filter)

    assert target == cnt