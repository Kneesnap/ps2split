from segtypes.ia4 import PS2SegIa4

class PS2SegIa8(PS2SegIa4):
    def parse_image(self, data):
        return data

    def max_length(self):
        if self.compressed: return None
        return self.width * self.height * 2
