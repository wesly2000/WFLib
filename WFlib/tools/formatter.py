import numpy as np
import pyshark
import json
from pathlib import Path
import warnings
from WFlib.tools.capture import SNI_exclude_filter

class Extractor(object):
    """
    The class provides methods for the actual feature extraction work. This is some abstract class, and the 
    extractors used MUST inherit it.
    """
    def __init__(self, name):
        self._name = name
        # self._buf = []

    # @property
    # def buf(self):
    #     return self._buf
    
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

    def extract(self, pkt, target : list):
        """
        Extract the direction info and store them into target.

        Params
        ------
        pkt : packet
            The packet to extract the feature.

        target : list
            The variable to store features.
        """
        if 'ip' not in pkt:
            pass # Add some warning here
        src = pkt['ip'].src

        target.append(1 if src == self._src else -1) # 1 for egress, -1 for ingress


class Formatter(object):
    """
    This class provides a universal format transformer between np.array (or tensor) between all other
    network files, e.g., .pcap, .csv, .json, etc.

    Since the models of WFlib and all other util functions request .npz format, this abstract class provides
    interfaces to transform arbitrary format into .npz files. Optionally, the implement could also
    extend methods that transform the original data into other file formats.

    All other formats that use the models, except for .npz itself, SHOULD inherit this class.
    All the classes that inherit this class MUST implement the load and transform methods.
    """
    def __init__(self, length=0):
        """
        Attributes
        ----------
        length : int
            The expected length of each feature vector, once length > 0, the resulting feature vector would be
            truncated or padded to the target length; if length <= 0, no truncation/padding is performed.
        raw_buf : Any
            The buffer to hold the loaded data in raw form.

        buf : dict:
            The buffer to hold the dict data, which should be the form like {lable_1: data_1, lable_2: data_2, ...},
            where label_X is a string, and data_X should be a np.ndarray.
        """
        self._length = length
        self._raw_buf = None
        self._buf = dict()
        self._buf['hosts'] = []
        self._buf['labels'] = []

    @property
    def length(self):
        return self._length
    
    # @length.setter
    # def length(self, length):
    #     self._length = length

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

        self._buf['hosts'] = np.array(self._buf['hosts'])
        self._buf['labels'] = np.array(self._buf['labels'])
        for k in self._buf.keys():
            if k not in ['hosts', 'labels']:
                self._buf[k] = np.stack(self._buf[k])

        np.savez(file=file, **self._buf)

class PcapFormatter(Formatter):
    """
    The class to convert .pcap files to .npz files. Moreover, it supports to convert .pcap files to .json files for
    raw feature extraction (See Attributes in __init__), where no truncation/padding would be applied.
    """
    def __init__(self, length=0, keep_packets=False, display_filter=None):
        """
        Attributes
        ----------
        labels : list 
            The labels for the files used. Each file corresponds to one label.

        hosts : list
            The hostnames of the requested websites. The index of a host corresponds to the the value of the label.

        display_filter : str
            The display filter to apply to tshark when reading .pcap files.

        keep_packets : bool
            Whether to keep packets in the capture. Setting to False largely reduce memory consumption.

        raw : bool
            The length of feature vector differs between .pcap files, since the number of valid packets differs.
            It is convenient to leverage the length variable to extract aligned feature vectors using truncation/padding.
            However, sometimes it may be useful, e.g., when the length is hard to decide, to extract the raw features 
            without truncation/padding for further processing. 

            Therefore, the raw attribute is introduced to indicate whether to truncate/pad the feature vectors. The
            reason to introduce this redundant attribute is for semantic clarity. Note that when raw is True, the data
            are stored in nested lists instead of concatenated ndarray. Further, the it would be dumped to .json files
            instead of .npz for better flexibility.

        For example, for each of the hosts in [www.baidu.com, www.google.com, www.zhihu.com], we capture 3 request 
        traces (.pcap). Then the labels after performing transform should be [0, 0, 0, 1, 1, 1, 2, 2, 2].
        """
        super().__init__(length=length)
        self._display_filter = display_filter
        self._keep_packets = keep_packets
        self._raw = length <= 0

    @property
    def display_filter(self):
        return self._display_filter
    
    @display_filter.setter
    def display_filter(self, display_filter):
        self._display_filter = display_filter

    def load(self, file):
        self._raw_buf = pyshark.FileCapture(input_file=file, 
                                            display_filter=self.display_filter,
                                            keep_packets=self._keep_packets)

    def transform(self, host : str, label : int, *extractors : Extractor):
        """
        The transform method to extract features from self.raw_buf using the extractors. 
        
        NOTE: Ideally, the host and label parameters could be inferred from the filename. 
        However, the inference is considered not the duty of the formatter itself but that of
        the caller.

        NOTE: We defer the truncation/padding to the point when the whole .pcap is iterated
        through to keep the integrity lest some extractor depends on that. Later the lazy mode
        might be introduced to make the integrity optional.

        TODO: Introduce lazy mode.

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
        tmp_buf = dict()

        for extractor in extractors:
            tmp_buf[extractor.name] = []
            # Initialize a new list for the given feature name
            if extractor.name not in self._buf:
                self._buf[extractor.name] = []
        
        # The temporaty buffer to hold the features extracted from current self._raw_buf

        for pkt in self._raw_buf:
            for extractor in extractors:
                extractor.extract(pkt, tmp_buf[extractor.name])

        self._raw_buf.close()

        # Dump features into ndarray, and append to self._buf[name]
        for extractor in extractors:
            if not self._raw:
                if self._length <= len(tmp_buf[extractor.name]): # Truncate
                    self._buf[extractor.name].append(np.array(tmp_buf[extractor.name][:self._length]))
                else:
                    padding = 0
                    padding_len = self._length - len(tmp_buf[extractor.name])
                    self._buf[extractor.name].append(np.array(tmp_buf[extractor.name] + [padding] * padding_len))
            else:
                self._buf[extractor.name].append(tmp_buf[extractor.name])

    def dump(self, file):
        if self._raw:  # Dump the file to .json format
            with open(file, "w") as f:
                json.dump(self._buf, f)
                return

        super().dump(file)

    def batch_extract(self, base_dir, output_file, SNIs=None, *extractors):
        """
        Extract all the given features from all the files in the given base directory.

        Params
        ------
        base_dir : str
            The base directory to hold all the .pcap files, the directory structure should be
            the same as that created by batch_capture.

        output_file : str
            The file to store all the features extracted.

        extractors : Extractor
            The extractors for feature extraction.
        """
        base_dir_path = Path(base_dir)
        label = 0  # Processing a hostname will increase the label by 1

        # Iterate over all subdirectories in the base directory
        for subdir in base_dir_path.iterdir():
            if subdir.is_dir():  # Check if it's a directory
                host = str(subdir).split('/')[-1]
                for file in subdir.iterdir():
                    if file.is_file():  # Ensure it's a file
                        display_filter = SNI_exclude_filter(file, SNIs)
                        self.display_filter = display_filter
                        self.load(file=file)
                        self.transform(host, label, *extractors)
                label += 1

        self.dump(output_file)

class JsonFormatter(Formatter):
    """
    The formatter for .json files. This file includes some extensive utility functions for feature post-processing.
    """
    def __init__(self):
        super().__init__()

    def load(self, file):
        self._raw_buf = json.load(file)

    def transform(self, debug=True, **kwargs):
        """
        The function to align each feature to the corresponding length. The kwargs is like {name_1: length_1, ..., name_n: length_n}.
        For each name, this function tries to fetch them and ignore those not in the self._raw_buf with warnings. 
        
        Note that the special name 'labels' and 'hosts' should not be used since they are not features. If you find the warnings
        annoying you could turn it off by setting debug=False.
        """
        if not debug:
            warnings.filterwarnings('ignore')

        self._buf['labels'] = np.array(self._raw_buf['labels'])
        self._buf['hosts'] = np.array(self._raw_buf['hosts'])

        for name, length in kwargs.items():
            if name in ['labels', 'hosts']:
                warnings.warn("Names 'labels' and 'hosts' are reserved and could not used for truncation/padding.")
                continue 
            elif name not in self._raw_buf:
                warnings.warn(f"Key {name} is not present in the data.")
                continue
            else:
                if name not in self._buf:
                    self._buf[name] = []  # Create corresponding container if not exist
                for feature in self._raw_buf[name]:  # Iterate through all the feature vectors and do truncation/padding
                    if length <= len(feature): # Truncate
                        self._buf[name].append(np.array(feature[:length]))
                    else:
                        padding = 0
                        padding_len = length - len(feature)
                        self._buf[name].append(np.array(feature + [padding] * padding_len))

    def get_feature_buf(self, name):
        """
        Get the un-transformed feature buffer by its name.
        """
        return self._raw_buf[name]