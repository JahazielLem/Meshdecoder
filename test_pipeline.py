# test_pipeline.py
import pytest
import os
import queue
import time
from modules.fifo import PipeUnix, DEFAULT_PIPEPATH
from modules.pcap import get_global_header, Pcap

class TestFifo:
  def test_pipeline(self):
    PipeUnix().create()
    assert(os.path.exists(DEFAULT_PIPEPATH))
    PipeUnix().remove()
  
  def test_pcap(self):
    testPcap = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x94\x00\x00\x00'
    assert(get_global_header() == testPcap)