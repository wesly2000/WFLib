import numpy as np
import pyshark

class Extractor(object):
    """
    The class provides methods for the actual feature extraction work. This is some abstract class, and the 
    extractors used MUST inherit it.
    """
    def __init__(self, name):
        self.name = name

    def extract(self):
        raise NotImplementedError


class DirectionExtractor(Extractor):
    """
    The class provides methods for the packet direction extraction.

    Attributes
    ----------
    src : str
        The source IP address for the extractor to decide ingress or egress.
    """
    def __init__(self, src, name=None):
        self.name = "direction" if name is None else name 
        self.src = src 

    def extract(self, pkt):
        src = pkt['ip'].src
        if src == self.src: # egress packet
            return 1
        else:               # ingress packet
            return -1


class Formatter(object):
    """
    This class provides a universal format transformer between np.array (or tensor) between all other
    network files, e.g., .pcap, .csv, .json, etc.

    Since the models of WFlib and all other util functions request .npz format, this abstract class provides
    interfaces to transform arbitrary format into .npz files.

    All other formats that use the models, except for .npz itself, SHOULD inherit this class.
    All the classes that inherit this class MUST implement the load and transform methods.
    """
    def __init__(self):
        """
        Attributes
        ----------
        raw_buf : Any
            The buffer to hold the loaded data in raw form.

        buf : dict:
            The buffer to hold the dict data, which should be the form like {lable_1: data_1, lable_2: data_2, ...},
            where label_X is a string, and data_X should be a np.ndarray.
        """
        self.raw_buf = None
        self.buf = dict()

    def load(self, file):
        """
        The load method that read in files specified by path into raw_buf.

        Params
        ------
        file : file|str
            The file path to be read.
        """
        raise NotImplementedError
    
    def transform(self):
        """
        Transform the raw_buf to buf, which is the operation to transform any data into dict form.
        """
        raise NotImplementedError

    def dump(self, file):
        """
        The dump method that write the buf to the file specified by file.

        Params
        ------
        file : file|str
            The file path to be read.
        """
        np.savez(file=file, **self.buf)

class PcapFormatter(Formatter):
    def __init__(self):
        """
        Attributes
        ----------
        labels : list 
            The labels for the files used. Each file corresponds to one label.

        hosts : list
            The hostnames of the requested websites. The index of a host corresponds to the the value of the label.

        For example, for each of the hosts in [www.baidu.com, www.google.com, www.zhihu.com], we capture 3 request 
        traces (.pcap). Then the labels after performing transform should be [0, 0, 0, 1, 1, 1, 2, 2, 2].
        """
        super().__init__()
        self.buf['hosts'] = []
        self.buf['labels'] = []

    def load(self, file):
        self.raw_buf = pyshark.FileCapture(input_file=file)

    def transform(self, host : str, label : int, *extractors):
        """
        The transform method to extract features from self.raw_buf using the extractors. 
        
        NOTE: Ideally, the host and label parameters could be inferred from the filename. 
        However, the inference is considered not the duty of the formatter itself but that of
        the caller.

        Params
        ------
        host : str
            The hostname of the requested website.

        label : int
            The label assigned to the features extracted from the file.

        extractors : list of Extractor
            The extractors each of which extracts the feature named after Extractor.name, note that 
            ONLY packet-level extractors should be passed. Burst/Flow-level or higher level extractors
            should be used as extended methods.
        """
        if host not in self.hosts:
            self.hosts.append(host)

        self.labels.append(label)

        for extractor in extractors:
            # Initialize a new list for the given feature name
            if extractor.name not in self.buf:
                self.buf[extractor.name] = []
        
        for pkt in self.raw_buf:
            for extractor in extractors:
                result = extractor.extract(pkt)
                # Avoid possible non-IP packets
                if result is not None:
                    self.buf[extractor.name].append(result)