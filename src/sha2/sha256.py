#!/bin/env python3
"""SHA-256 implementation."""

import sys

K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


class MessageSchedule:
    def __init__(self, message_chunk: bytearray):
        """Initialize MessageSchedule from message."""
        self.message_schedule = []
        for i in range(0, 16):
            self.message_schedule.append(
                bytes(message_chunk[i * 4 : (i * 4) + 4])
            )
        for i in range(16, 64):
            sigma_0 = self.compute_sigma_0(self.get_word(i - 15))
            sigma_1 = self.compute_sigma_1(self.get_word(i - 2))
            self.message_schedule.append(
                (
                    (
                        self.get_word(i - 16)
                        + sigma_0
                        + self.get_word(i - 7)
                        + sigma_1
                    )
                    % 2**32
                ).to_bytes(4, "big")
            )

    def get_word(self, index: int) -> int:
        """Get chunk at index from the message schedule."""
        return int.from_bytes(self.message_schedule[index], "big")

    def __getitem__(self, key: int) -> int:
        return self.get_word(key)

    def compute_sigma_0(self, number: int) -> int:
        """Return value for sigma_0."""
        return ror(number, 7) ^ ror(number, 18) ^ (number >> 3)

    def compute_sigma_1(self, number: int) -> int:
        """Return value for sigma_1."""
        return ror(number, 17) ^ ror(number, 19) ^ (number >> 10)


def sha256(message: bytearray) -> str:
    """Return SHA-256 hash of message."""
    padding(message)

    message_chunks = message_to_chunks(message)

    h_0 = 0x6A09E667
    h_1 = 0xBB67AE85
    h_2 = 0x3C6EF372
    h_3 = 0xA54FF53A
    h_4 = 0x510E527F
    h_5 = 0x9B05688C
    h_6 = 0x1F83D9AB
    h_7 = 0x5BE0CD19

    for chunk in message_chunks:
        message_schedule = MessageSchedule(chunk)

        a = h_0
        b = h_1
        c = h_2
        d = h_3
        e = h_4
        f = h_5
        g = h_6
        h = h_7

        for i in range(64):
            s_1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
            ch = (e & f) ^ (~e & g)
            t_1 = (h + s_1 + ch + K[i] + message_schedule[i]) % 2**32

            s_0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t_2 = (s_0 + maj) % 2**32

            h = g
            g = f
            f = e
            e = (d + t_1) % 2**32
            d = c
            c = b
            b = a
            a = (t_1 + t_2) % 2**32

        h_0 = (h_0 + a) % 2**32
        h_1 = (h_1 + b) % 2**32
        h_2 = (h_2 + c) % 2**32
        h_3 = (h_3 + d) % 2**32
        h_4 = (h_4 + e) % 2**32
        h_5 = (h_5 + f) % 2**32
        h_6 = (h_6 + g) % 2**32
        h_7 = (h_7 + h) % 2**32

    return (
        (h_0).to_bytes(4, "big")
        + (h_1).to_bytes(4, "big")
        + (h_2).to_bytes(4, "big")
        + (h_3).to_bytes(4, "big")
        + (h_4).to_bytes(4, "big")
        + (h_5).to_bytes(4, "big")
        + (h_6).to_bytes(4, "big")
        + (h_7).to_bytes(4, "big")
    ).hex()
    # return [
    #     hex(h_0),
    #     hex(h_1),
    #     hex(h_2),
    #     hex(h_3),
    #     hex(h_4),
    #     hex(h_5),
    #     hex(h_6),
    #     hex(h_7),
    # ]


def padding(message: bytearray):
    """Apply padding to the message."""
    message_length = len(message) * 8
    message.append(0x80)
    while (len(message) * 8 + 64) % 512 != 0:
        message.append(0x00)
    message += message_length.to_bytes(8, "big")


def message_to_chunks(message: bytearray) -> list[bytearray]:
    """Break the message into 512-bit chunks."""
    message_chunks = []
    for i in range(0, len(message), 64):
        message_chunks.append(message[i : i + 64])
    return message_chunks


def ror(number: int, shift: int, size: int = 32):
    """Rotate a number by shift to the right."""
    return (number >> shift) | (number << size - shift)


if __name__ == "__main__":
    msg_bytearray = bytearray(sys.argv[1], "ascii")
    print(sha256(msg_bytearray))
