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