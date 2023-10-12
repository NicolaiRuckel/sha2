#!/bin/env python3
"""SHA-512 implementation."""

import sys

K = [
    0x428A2F98D728AE22,
    0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F,
    0xE9B5DBA58189DBBC,
    0x3956C25BF348B538,
    0x59F111F1B605D019,
    0x923F82A4AF194F9B,
    0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242,
    0x12835B0145706FBE,
    0x243185BE4EE4B28C,
    0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F,
    0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235,
    0xC19BF174CF692694,
    0xE49B69C19EF14AD2,
    0xEFBE4786384F25E3,
    0x0FC19DC68B8CD5B5,
    0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275,
    0x4A7484AA6EA6E483,
    0x5CB0A9DCBD41FBD4,
    0x76F988DA831153B5,
    0x983E5152EE66DFAB,
    0xA831C66D2DB43210,
    0xB00327C898FB213F,
    0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2,
    0xD5A79147930AA725,
    0x06CA6351E003826F,
    0x142929670A0E6E70,
    0x27B70A8546D22FFC,
    0x2E1B21385C26C926,
    0x4D2C6DFC5AC42AED,
    0x53380D139D95B3DF,
    0x650A73548BAF63DE,
    0x766A0ABB3C77B2A8,
    0x81C2C92E47EDAEE6,
    0x92722C851482353B,
    0xA2BFE8A14CF10364,
    0xA81A664BBC423001,
    0xC24B8B70D0F89791,
    0xC76C51A30654BE30,
    0xD192E819D6EF5218,
    0xD69906245565A910,
    0xF40E35855771202A,
    0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8,
    0x1E376C085141AB53,
    0x2748774CDF8EEB99,
    0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63,
    0x4ED8AA4AE3418ACB,
    0x5B9CCA4F7763E373,
    0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC,
    0x78A5636F43172F60,
    0x84C87814A1F0AB72,
    0x8CC702081A6439EC,
    0x90BEFFFA23631E28,
    0xA4506CEBDE82BDE9,
    0xBEF9A3F7B2C67915,
    0xC67178F2E372532B,
    0xCA273ECEEA26619C,
    0xD186B8C721C0C207,
    0xEADA7DD6CDE0EB1E,
    0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA,
    0x0A637DC5A2C898A6,
    0x113F9804BEF90DAE,
    0x1B710B35131C471B,
    0x28DB77F523047D84,
    0x32CAAB7B40C72493,
    0x3C9EBE0A15C9BEBC,
    0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6,
    0x597F299CFC657E2A,
    0x5FCB6FAB3AD6FAEC,
    0x6C44198C4A475817,
]


def sha512(message: bytearray) -> str:
    """Return SHA-512 hash of message."""
    padding(message)

    message_chunks = message_to_chunks(message)

    h_0 = 0x6A09E667F3BCC908
    h_1 = 0xBB67AE8584CAA73B
    h_2 = 0x3C6EF372FE94F82B
    h_3 = 0xA54FF53A5F1D36F1
    h_4 = 0x510E527FADE682D1
    h_5 = 0x9B05688C2B3E6C1F
    h_6 = 0x1F83D9ABFB41BD6B
    h_7 = 0x5BE0CD19137E2179

    for chunk in message_chunks:
        message_schedule = []
        for i in range(0, 16):
            message_schedule.append(bytes(chunk[i * 8 : (i * 8) + 8]))
        for i in range(16, 80):
            sigma_0 = compute_sigma_0(get_word(message_schedule, i - 15))
            sigma_1 = compute_sigma_1(get_word(message_schedule, i - 2))
            message_schedule.append(
                (
                    (
                        get_word(message_schedule, i - 16)
                        + sigma_0
                        + get_word(message_schedule, i - 7)
                        + sigma_1
                    )
                    % 2**64
                ).to_bytes(8, "big")
            )
        assert len(message_schedule) == 80

        a = h_0
        b = h_1
        c = h_2
        d = h_3
        e = h_4
        f = h_5
        g = h_6
        h = h_7

        for i in range(80):
            s_1 = ror(e, 14) ^ ror(e, 18) ^ ror(e, 41)
            ch = (e & f) ^ (~e & g)
            temp1 = (
                h + s_1 + ch + K[i] + get_word(message_schedule, i)
            ) % 2**64

            s_0 = ror(a, 28) ^ ror(a, 34) ^ ror(a, 39)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s_0 + maj) % 2**64

            h = g
            g = f
            f = e
            e = (d + temp1) % 2**64
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % 2**64

        h_0 = (h_0 + a) % 2**64
        h_1 = (h_1 + b) % 2**64
        h_2 = (h_2 + c) % 2**64
        h_3 = (h_3 + d) % 2**64
        h_4 = (h_4 + e) % 2**64
        h_5 = (h_5 + f) % 2**64
        h_6 = (h_6 + g) % 2**64
        h_7 = (h_7 + h) % 2**64

    return (
        (h_0).to_bytes(8, "big")
        + (h_1).to_bytes(8, "big")
        + (h_2).to_bytes(8, "big")
        + (h_3).to_bytes(8, "big")
        + (h_4).to_bytes(8, "big")
        + (h_5).to_bytes(8, "big")
        + (h_6).to_bytes(8, "big")
        + (h_7).to_bytes(8, "big")
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
    while (len(message) * 8 + 128) % 1024 != 0:
        message.append(0x00)
    message += message_length.to_bytes(16, "big")


def message_to_chunks(message: bytearray) -> list[bytearray]:
    """Break the message into 1024-bit chunks."""
    message_chunks = []
    for i in range(0, len(message), 128):
        message_chunks.append(message[i : i + 128])
    return message_chunks


def ror(number: int, shift: int, size: int = 64):
    """Rotate a number by shift to the right."""
    return (number >> shift) | (number << size - shift)


def get_word(message_schedule: list[bytes], index: int) -> int:
    """Get word at index from the message schedule."""
    return int.from_bytes(message_schedule[index], "big")


def compute_sigma_0(number: int) -> int:
    """Return value for sigma_0."""
    return ror(number, 1) ^ ror(number, 8) ^ (number >> 7)


def compute_sigma_1(number: int) -> int:
    """Return value for sigma_1."""
    return ror(number, 19) ^ ror(number, 61) ^ (number >> 6)


if __name__ == "__main__":
    msg_bytearray = bytearray(sys.argv[1], "ascii")
    print(sha512(msg_bytearray))
