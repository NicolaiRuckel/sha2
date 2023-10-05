from sha2.sha256 import sha256


def test_empty_message():
    message = bytearray("", "ascii")
    digest = sha256(message)
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        == digest
    )


def test_message_abc():
    message = bytearray("abc", "ascii")
    digest = sha256(message)
    assert (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        == digest
    )
