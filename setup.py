from setuptools import setup
import sys

if sys.version_info[:2] != (3, 8):
    raise RuntimeError("Python version 3.8 required")

setup(
    name='WFlib',
    version='0.2',
    description='Extended WFlib. The original library is at https://github.com/Xinhao-Deng/Website-Fingerprinting-Library, by Xinhao Deng (dengxh23@mails.tsinghua.edu.cn) and Yixiang Zhang (zhangyix24@mails.tsinghua.edu.cn).',
    author='Linxiao Yu',
    packages=[
        "WFlib",
        "WFlib.models",
        "WFlib.tools"
    ],
    install_requires=[
        "tqdm",
        "numpy",
        "pandas",
        "scikit-learn",
        "einops",
        "timm",
        "torch",
        "pytorch-metric-learning",
        "captum",
        "scapy",
        "selenium"
    ],
)