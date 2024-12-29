import numpy as np
import pyshark

class Extractor(object):
    """
    The class provides methods for the actual feature extraction work. This is some abstract class, and the 
    extractors used MUST inherit it.
    """
    def __init__(self, name):
        self._name = name
        self._buf = []

    @property
    def buf(self):
        return self._buf
    
    @property
    def name(self):
        return self._name

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
    def __init__(self, src, name="direction"):
        super().__init__(name=name)
        self._src = src 

    def extract(self, pkt):
        if 'ip' not in pkt:
            pass # Add some warning here
        src = pkt['ip'].src
        self._buf.append(1 if src == self._src else -1) # 1 for egress, -1 for ingress


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
        self._raw_buf = None
        self._buf = dict()

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
        np.savez(file=file, **self._buf)

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
        self._buf['hosts'] = []
        self._buf['labels'] = []

    def load(self, file):
        self._raw_buf = pyshark.FileCapture(input_file=file)

    def transform(self, host : str, label : int, *extractors : Extractor):
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
        if host not in self._buf['hosts']:
            self._buf['hosts'].append(host)

        self._buf['labels'].append(label)

        for extractor in extractors:
            # Initialize a new list for the given feature name
            if extractor.name not in self._buf:
                self._buf[extractor.name] = []
        
        for pkt in self._raw_buf:
            for extractor in extractors:
                extractor.extract(pkt)

        # Dump features into ndarray, and append to self._buf[name]
        for extractor in extractors:
            self._buf[extractor.name].append(np.array(extractor.buf))

    def dump(self, file):
        self._buf['hosts'] = np.array(self._buf['hosts'])
        self._buf['labels'] = np.array(self._buf['labels'])
        for k in self._buf.keys():
            if k not in ['hosts', 'labels']:
                self._buf[k] = np.stack(self._buf[k])

        super().dump(file)