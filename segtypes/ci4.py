from segtypes.ci8 import PS2SegCi8

class PS2SegCi4(PS2SegCi8):
    def parse_image(self, data):
        img_data = bytearray()

        for i in range(self.width * self.height // 2):
            img_data.append(data[i] >> 4)
            img_data.append(data[i] & 0xF)

        return img_data

    def max_length(self):
        if self.compressed: return None
        return self.width * self.height // 2
