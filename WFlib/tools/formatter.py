import numpy as np


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
        origin_buf : Any
            The buffer to hold the loaded data in raw form.

        buf : dict:
            The buffer to hold the dict data, which should be the form like {lable_1: data_1, lable_2: data_2, ...},
            where label_X is a string, and data_X should be a np.ndarray.
        """
        self.origin_buf = None
        self.buf = None 

    def load(self, file):
        """
        The load method that read in files specified by path into origin_buf.

        Params
        ------
        file : file|str
            The file path to be read.
        """
        return NotImplementedError

    def transform(self):
        """
        Transform the origin_buf to buf, which is the operation to transform any data into dict form.
        """
        return NotImplementedError

    def dump(self, file):
        """
        The dump method that write the buf to the file specified by file.

        Params
        ------
        file : file|str
            The file path to be read.
        """
        np.savez(file, **self.buf)

class PCAPFormatter(Formatter):
    """
    The class that transforms .pcap file to .npz file.
    """

class JSONFormatter(Formatter):
    """
    The class that transforms .json file to .npz file.
    """