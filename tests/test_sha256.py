from sha2.sha256 import sha256

TEST_MESSAGE_EMPTY = bytearray("", "ascii")
TEST_MESSAGE_24_BITS = bytearray("abc", "ascii")
TEST_MESSAGE_448_BITS = bytearray(
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "ascii"
)
TEST_MESSAGE_896_BITS = bytearray(
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnh"
    + "ijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "ascii",
)
TEST_MESSAGE_ONE_MILLION_A = bytearray("a" * 1000000, "ascii")


def test_message_empty():
    digest = sha256(TEST_MESSAGE_EMPTY)
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        == digest
    )


def test_message_24_bits():
    digest = sha256(TEST_MESSAGE_24_BITS)
    assert (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        == digest
    )


def test_message_448_bits():
    digest = sha256(TEST_MESSAGE_448_BITS)
    assert (
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        == digest
    )


def test_message_896_bits():
    digest = sha256(TEST_MESSAGE_896_BITS)
    assert (
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        == digest
    )


def test_message_one_million_as():
    digest = sha256(TEST_MESSAGE_ONE_MILLION_A)
    assert (
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        == digest
    )
