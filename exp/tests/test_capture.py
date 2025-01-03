from WFlib.tools.capture import *
import pyshark

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
    
    stream_number = stream_number_extract(capture=capture, check=lambda pkt: contains_SNI(SNIs, pkt))

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

def test_apply_exclude_filter():
    SNIs = []
    with open("exp/data_extract/filter.txt", 'r') as f:
        for line in f:
            SNIs.append(line.strip())

    client_hello_capture = pyshark.FileCapture(input_file="exp/test_dataset/www.baidu.com_proxied.pcapng", display_filter="tls.handshake.type == 1")
    stream_numbers = stream_number_extract(capture=client_hello_capture, check=lambda pkt: contains_SNI(SNIs, pkt))
    client_hello_capture.close()

    file = "exp/test_dataset/www.baidu.com_proxied.pcapng"
    display_filter = SNI_exclude_filter(file, SNIs)

    capture = pyshark.FileCapture(input_file="exp/test_dataset/www.baidu.com_proxied.pcapng", display_filter=display_filter)
    for pkt in capture:
        if 'TCP' in pkt:
            assert pkt['TCP'].stream not in stream_numbers 

    capture.close()