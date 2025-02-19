from WFlib.tools.capture import *
import pyshark

baidu_proxied_file = "exp/test_dataset/realworld_dataset/www.baidu.com_proxied.pcapng"

def test_SNI_extract():
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

def test_stream_exclude_filter():
    tcp_stream_numbers, udp_stream_numbers = [], []
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = ""
    assert display_filter == target

    tcp_stream_numbers = ['1', '4', '3']
    display_filter = stream_exclude_filter(tcp_stream_numbers, udp_stream_numbers)
    target = "tcp.stream != 1 and tcp.stream != 4 and tcp.stream != 3"

    assert display_filter == target

def test_SNI_exclude_filter():
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