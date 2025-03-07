from captum import attr
from tqdm import tqdm
import torch
import numpy as np
import pyshark 
from pathlib import Path

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

    def count(self, pkt) -> int:
        """
        Count the byte number of proto layer within the given packet.
        """
        raise NotImplementedError()
    

class HTTP2ByteCounter(ByteCounter):
    def __init__(self, name='http2'):
        super().__init__(name)
        self.preface_len = 24  # HTTP/2 Connection Preface
        self.header_len = 9  # 9-octet header
    
    def count(self, pkt) -> int:
        cnt = 0
        if "HTTP2" in pkt:  # Check if HTTP/2 is present in the decrypted packet
            h2_layers = filter(lambda layer: layer.layer_name == "http2", pkt.layers)
            h2_layer_lengths = map(lambda layer: int(layer.length) + self.header_len if hasattr(layer, "length") else self.preface_len, h2_layers)
            cnt += sum(h2_layer_lengths)

        return cnt
    

class TCPByteCounter(ByteCounter):
    def __init__(self, name='tcp'):
        super().__init__(name)

    def count(self, pkt) -> int:
        cnt = 0
        if "TCP" in pkt:  # Check if HTTP/2 is present in the decrypted packet
            tcp_layer = pkt['tcp']
            cnt += int(tcp_layer.len) + int(tcp_layer.hdr_len)

        return cnt