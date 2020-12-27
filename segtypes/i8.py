from segtypes.i4 import PS2SegI4
from math import ceil

class PS2SegI8(PS2SegI4):
    def parse_image(self, data):
        return data

    def max_length(self):
        if self.compressed: return None
        return self.width * self.height
