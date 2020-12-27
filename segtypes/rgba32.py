from segtypes.rgba16 import PS2SegRgba16

class PS2SegRgba32(PS2SegRgba16):
    def parse_image(self, data):
        return data

    def max_length(self):
        if self.compressed: return None
        return self.width * self.height * 4
