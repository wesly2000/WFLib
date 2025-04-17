from captum import attr
from tqdm import tqdm
import torch
import numpy as np
import pyshark 
from pathlib import Path
import re
from typing import List

def feature_attr(model, attr_method, X, y, num_classes):
    """
    Calculate feature attributions for a given model using a specified attribution method.
    
    Args:
    - model: The neural network model to interpret.
    - attr_method: The attribution method to use (e.g., 'DeepLiftShap').
    - X: The input data (features) as a numpy array or torch tensor.
    - y: The labels for the input data.
    - num_classes: The number of distinct classes in the data.
    
    Returns:
    - attr_values: An array of attribution values for each class.
    """
    
    # Set the model to evaluation mode
    model.eval()
    
    # Initialize the attribution model based on the chosen method
    if attr_method in ["DeepLiftShap"]:
        attr_model = eval(f"attr.{attr_method}")(model)
    else:
        attr_model = eval(f"attr.{attr_method}")(model.forward)
    
    # Prepare background and test data for each class
    bg_traffic = []
    test_traffic = {}
    for web in range(num_classes):
        bg_test_X = X[y == web]
        assert bg_test_X.shape[0] >= 12
        bg_traffic.append(bg_test_X[0:2])  # Use the first 2 samples as background
        test_traffic[web] = bg_test_X[2:12]  # Use the next 10 samples for testing

    # Concatenate all background traffic into a single tensor
    bg_traffic = torch.concat(bg_traffic, axis=0)

    attr_values = []
    # Iterate over each class to calculate attribution values
    for web in tqdm(range(num_classes)):
        # Calculate attributions for the test samples using the background samples
        attr_result = attr_model.attribute(test_traffic[web], bg_traffic, target=web)
        # Aggregate the attribution results
        attr_result = attr_result.detach().numpy().squeeze().sum(axis=0).sum(axis=0)
        attr_values.append(attr_result)
    
    attr_values = np.array(attr_values)
    return attr_values  # Return the attribution values

def packet_count(capture):
    """
    Count the number of packets within the given capture, possible display filter may be applied.
    """
    cnt = 0
    for _ in capture:
        cnt += 1
    return cnt

def file_count(base_dir : Path):
    '''
    For each subdirectory (per represents a website) in the base_dir,
    count the number of .pcap(ng) files and put the results in a dict.
    '''
    cnt = dict()
    subdirs = list(filter(lambda x: x.is_dir(), base_dir.iterdir()))

    for subdir in sorted(subdirs):
        cnt[subdir.name] = sum(1 for _ in filter( # Only count pcap(ng) files
                lambda x: x.is_file() and x.suffix in ['.pcapng', '.pcap'], subdir.iterdir()
                )
            )

    return cnt

# TODO: Consider replace all the non-HTTP counter's count method to only count the underlying
# TCP/UDP payload length.

class ByteCounter():
    """
    Abstraction of protocol specific byte counter.

    Attribute
    ---------
    name : str
        The name of the byte counter, commonly it should be the name the protocol.
    """
    def __init__(self, name):
        self.name = name

    def layer_count(self, layer, extra_data = None) -> int:
        """
        Count the number of layers of the given protocol within the given packet.
        """
        raise NotImplementedError()

    def packet_count(self, pkt) -> int:
        """
        Count the byte number of proto layer within the given packet.
        """
        raise NotImplementedError()
    

class HTTP3ByteCounter(ByteCounter):
    def __init__(self, name='http3'):
        super().__init__(name)
        self.uni_stream_hdr_len = 1  # The length of HTTP/3 unidirectional stream type

    def layer_count(self, layer, extra_data = None) -> int:
        cnt = 0
        # if hasattr(h3_layer, "stream_uni_type"):
        #     for sut in h3_layer.stream_uni_type.all_fields:
        #         cnt += int(sut.size)  # Uni Stream has one extra stream type byte
        if hasattr(layer, "stream_uni"):
            cnt += int(layer.stream_uni.size)
            return cnt  # It seems that in Wireshark, UNI Stream has contained the length including the frames within
        # Note that HTTP/3 frame length and type are both variable-length integers.
        if hasattr(layer, "frame_length"):
            # Some HTTP/3 packets may not have frame length/type field.
            for fl in layer.frame_length.all_fields:
                cnt += int(fl.showname_value) + int(fl.size)
            for ft in layer.frame_type.all_fields:
                cnt += int(ft.size)

        return cnt

    def packet_count(self, pkt) -> int:
        cnt = 0
        if "HTTP3" in pkt:
            h3_layers = filter(lambda layer: layer.layer_name == "http3", pkt.layers)
            h3_layer_lengths = map(self.layer_count, h3_layers)
            cnt += sum(h3_layer_lengths)

        return cnt

class HTTP2ByteCounter(ByteCounter):
    def __init__(self, name='http2'):
        super().__init__(name)
        self.preface_len = 24  # HTTP/2 Connection Preface
        self.header_len = 9  # 9-octet header

    def layer_count(self, layer, extra_data = None) -> int:
        return int(layer.length) + self.header_len if hasattr(layer, "length") else self.preface_len
    
    def packet_count(self, pkt) -> int:
        cnt = 0
        if "HTTP2" in pkt:  # Check if HTTP/2 is present in the decrypted packet
            h2_layers = filter(lambda layer: layer.layer_name == "http2", pkt.layers)
            h2_layer_lengths = map(self.layer_count, h2_layers)
            cnt += sum(h2_layer_lengths)

        return cnt
    

class TLSByteCounter(ByteCounter):
    def __init__(self, name='tls'):
        super().__init__(name)
        self.type_len = 1  # TLS record type
        self.ver_len = 2  # TLS version
        self.length_len = 1  # TLS record length

    def layer_count(self, layer, extra_data = None) -> int:
        cnt = 0
        # The method to iterate through all records within a TLS layer is provided by
        # https://github.com/KimiNewt/pyshark/issues/419
        for rl in layer.record_length.all_fields:  # Each TLS layer may contain multiple TLS records
            cnt += int(rl.showname_value) + self.type_len + self.ver_len + self.length_len

        return cnt

    def packet_count(self, pkt) -> int:
        cnt = 0
        if "TLS" in pkt:  
            tls_layers = filter(lambda layer: layer.layer_name == "tls", pkt.layers)  # One packet may contain multiple TLS layers
            tls_layer_lengths = map(self.layer_count, tls_layers)
            cnt += sum(tls_layer_lengths)

        return cnt
    

class QUICByteCounter(ByteCounter):
    def __init__(self, name='quic'):
        super().__init__(name)
        self.udp_hdr_len = 8  # UDP header length

    def layer_count(self, layer, extra_data = None) -> int:
        """
        TODO: QUIC leverages UDP to do packet counting, try to isolate this issue.
        """
        raise NotImplementedError("QUICByteCounter.layer_count is not implemented, since the isolation of UDP is not done yet.")

    def packet_count(self, pkt) -> int:
        cnt = 0
        if "QUIC" in pkt:  
            quic_packets = filter(lambda layer: layer.layer_name == "quic", pkt.layers)  # One packet may contain multiple QUIC packets (QUIC uses packet instead of layer as its PDU)
            for quic_packet in quic_packets:  
                # If the packet has coalesced padding data, the length of the packet is equal to the
                # UDP payload data length. See the discussions below:
                # https://github.com/quicwg/base-drafts/issues/3333 (0-padding outside of QUIC packets)
                # https://github.com/mozilla/neqo/pull/1850 (0-padding seems not changed)
                if hasattr(quic_packet, "coalesced_padding_data"):
                    cnt = int(pkt['udp'].length) - self.udp_hdr_len
                    break
                # It seems that a QUIC packet already contains the length of the packet.
                # We don't need to calculate each QUIC frame length as TLS records.
                cnt += int(quic_packet.packet_length)

        return cnt

class TCPByteCounter(ByteCounter):
    def __init__(self, name='tcp'):
        super().__init__(name)

    def layer_count(self, layer, extra_data = None) -> int:
        return int(layer.len) + int(layer.hdr_len)
    def packet_count(self, pkt) -> int:
        cnt = 0
        if "TCP" in pkt:  
            tcp_layer = pkt['tcp']
            cnt += self.layer_count(tcp_layer)

        return cnt
    

class UDPByteCounter(ByteCounter):
    def __init__(self, name='udp'):
        super().__init__(name)

    def layer_count(self, layer, extra_data = None) -> int:
        return int(layer.length)  # udp.length already contains the length of the UDP header
 
    def packet_count(self, pkt) -> int:
        cnt = 0
        if "UDP" in pkt:  
            udp_layer = pkt['udp']
            cnt += self.layer_count(udp_layer)

        return cnt
    

class CaptureCounter():
    def __init__(self, *counters: ByteCounter):
        self.counters = counters
        

    def count(self, cap):
        result = {counter.name: [0, 0] for counter in self.counters}  # The byte count of each protocol within the capture.
        for pkt in cap:
            for counter in self.counters:
                cnt = counter.packet_count(pkt)
                if cnt > 0:
                    result[counter.name][0] += 1  # The number of packets with non-zero byte count.
                result[counter.name][1] += cnt  

        return result
    

class Cell():
    def __init__(self, proto, abs_frame_idx):
        self.proto = proto
        self.abs_frame_idx = abs_frame_idx 
        self.rel_frame_idx = None
        self.abs_reassemble_info = []
        self.rel_reassemble_info = []


class CellExtractor(object):
    def __init__(self):
        pass 

    def extract(self, pkt, protocol) -> List[Cell]:
        """
        Extract reassembly information from the given packet with the given protocol.
        """
        if protocol not in pkt:
            return []
        
        # Despite that different protocol name its PDU in different names, e.g., packet for QUIC
        # Layer for TLS, Frame for HTTP2. We name the PDU as 'layer' for all protocols.
        proto_layers = filter(lambda layer: layer.layer_name == protocol, pkt.layers)
        raise NotImplementedError()
    

def layer_extractor(pkt, upper_protocol, lower_protocol):
    """
    Extract all layers of the given protocol, if the layer is built upon a DATA layer, 
    prepend the DATA layer to the layer list. Caller is responsible to ensure that
    the order of upper_protocol and lower_protocol is correct. Moreover, caller is
    responsible to ensure the continuity of upper_protocol and lower_protocol.

    For example, if the packet stack is TCP/TLS/HTTP2, the following params:
    {upper_protocol: 'http2', lower_protocol: 'tcp'},
    {upper_protocol: 'tls', lower_protocol: 'http2'},

    will lead to unexpected behavior. Callee does not handle the above cases since in 
    practice they are valid, e.g., HTTP tunnel may build TLS upon HTTP.

    If the packet does not contain either upper_protocol or lower_protocol, return an empty list.
    """
    upper_protocol = upper_protocol.lower()
    lower_protocol = lower_protocol.lower()

    supported_protocols = ['tcp', 'tls', 'http2', 'vmess']
    if upper_protocol not in supported_protocols or lower_protocol not in supported_protocols:
        raise ValueError(f"Unsupported protocol: only the following protocols are supported: {supported_protocols}")
    # Assure the packet protocol stack contains both upper and lower protocols.
    if upper_protocol not in pkt or lower_protocol not in pkt:
        return []  
    
    layers = []
    data_layer_marker = {'tcp': 'tcp_segments', 'tls': 'tls_segments'}

    for layer in pkt.layers:
        if layer.layer_name == 'DATA':
            if data_layer_marker[lower_protocol] in layer.field_names:
                layers.append(layer)
        elif layer.layer_name == upper_protocol:
            layers.append(layer)

    return layers


def match_segment_number(s: str): 
    """
    Extract numbers after symbol '#'.  
    """
    pattern = r'#(\d+)\((\d+)\)'
    results = re.findall(pattern, s)
    res = [(int(idx), int(size)) for idx, size in results]
    return res


def get_reassemble_info(cap: pyshark.FileCapture, protocol_stack: List[str] = ['TCP', 'TLS',]): 
    """
    Extract the reassemble information for each packet given the protocol stack. In PyShark, the reassembly
    information is wrapped in the DATA layer, which is a fake-field-wrapper. When there are multiple upper
    layers, multiple DATA layer might be used. For example, given a packet TCP/TLS/HTTP2, there are 3 possible
    cases, we list the corresponding layers for each of them:

    + 1. The TLS layer is reassembled, but HTTP2 layer is not (TCP/DATA/TLS/HTTP2/DATA);
    + 2. The TLS layer is not reassembled, but HTTP2 layer is (TCP/TLS/DATA/HTTP2/DATA);
    + 3. Both TLS and HTTP2 layers are reassembled (TCP/DATA/TLS/DATA/HTTP2/DATA),

    where the last DATA layer is for Lua-related information that should be ignored.

    However, for protocols above the transport layer, there might be multiple layers for the same protocol, e.g.,
    TCP/DATA/TLS/TLS/TLS/DATA/HTTP2/HTTP2. 
                  ^   ^         ^     ^

    One could deduce that for a given protocol, reassembly would only happen at the its first layer. Therefore, we
    need to separately handle the remaining layers (marked with ^).


    TODO: Add support to UDP stack.

    Parameters 
    ----------
    cap: pyshark.FileCapture
        The capture file.
    protocol_stack: List[str]
        The ordered list of protocols, the first one is the lower bound of the stack, the last one the upper bound.
        For example, for a protocol stack TCP/VMess/TLS/HTTP2, if we want to extract all the layer reassembly, one
        should set the protocol_stack to ['TCP', 'VMess', 'TLS', 'HTTP2'].

    Returns 
    ------- 
    res_dict: dict, {K: [v1, ...], ...} 
        K is the packet index in the same form of Wireshark, namely, starts from 1. 
        [v1, ...] denotes the reassembled indices, whose values will be K in turn and have the same reassembled list. 
        For example, {1: [1, 2], 2: [1, 2]}. 
    """
    # res_dict = {} # {index: [reassemble packets]}
    # for i in tqdm(range(packet_count(cap)), "get reassemble info"): 
    #     if cap[i].transport_layer == 'TCP': # ignore the UDP based protocols 
    #         frame_num = int(cap[i].frame_info.get_field('number')) # get the number of frame
    #         res_dict[frame_num] = [] # init i-th position as empty 
    #         segment_index = [] 
    #         # print(f'${i}$: ${pcap[i].layers}')
    #         for layer in cap[i].layers: 
    #             if layer.layer_name == 'DATA': # fake-field-wrapper is renamed to data in pyshark
    #                 for field in layer.field_names: 
    #                     if field == 'tcp_segments': # reassemble will appearance in the last packet
    #                         field_obj = layer.get_field(field) 
    #                         content = field_obj.main_field.get_default_value() 
    #                         segment_index.extend(match_segment_number(content)) 
    #         for index in segment_index: # cover related values with its reassemble info
    #             res_dict[index] = segment_index 
    
    # return res_dict
    res_dict = {protocol: [] for protocol in protocol_stack} # {index: [reassemble packets]}
    cell_extractor = CellExtractor()
    for pkt in cap: 
        # for protocol in protocol_stack: 
        #     if protocol in pkt:
        #         res_dict[protocol].extend(cell_extractor.extract(pkt, protocol))
        # if protocol in pkt:
        #     frame_num = int(pkt.frame_info.get_field('number')) # get the number of frame
        #     res_dict[frame_num] = [] # init i-th position as empty 
        #     segment_index = [] 
        #     # print(f'${i}$: ${pcap[i].layers}')
        #     for layer in pkt.layers: 
        #         if layer.layer_name == 'DATA': # fake-field-wrapper is renamed to data in pyshark
        #             for field in layer.field_names: 
        #                 if field == 'tcp_segments': # reassemble will appearance in the last packet
        #                     field_obj = layer.get_field(field) 
        #                     content = field_obj.main_field.get_default_value() 
        #                     segment_index.extend(match_segment_number(content)) 
        #     for index in segment_index: # cover related values with its reassemble info
        #         res_dict[index] = segment_index 
        frame_num = int(pkt.frame_info.get_field('number'))
        if frame_num == 58:
            pass
    
    return res_dict