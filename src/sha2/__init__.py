class MessageSchedule:
    def __init__(self, word_size: int, endianess: str = "big"):
        """Initialize a message schedule with word_size in bytes."""
        self.word_size = word_size
        self.message_schedule = []
        self.endianess = endianess

    def __getitem__(self, key: int) -> int:
        return int.from_bytes(self.message_schedule[key], "big")

    def append_number(self, number: int):
        """Add a number to the message schedule."""
        self.message_schedule.append(
            number % 2 ** (self.word_size * 8)
        ).to_bytes(self.word_size, "big")

    def append_bytearray(self, word: bytearray):
        """Append a bytearray with length of a word to the message schedule."""
        assert len(word) == self.word_size
        self.message_schedule.append(bytes(word))

    def append(self, value: bytearray | int):
        """
        Add a bytearray or an integer to the message schedule.

        If the value is a bytearray its length has the be equal to the word_size.
        If the value is an integer value % 2**word_size will be added.
        """
        if isinstance(value, bytearray):
            assert len(value) == self.word_size
            self.append_bytearray(value)
        elif isinstance(value, int):
            self.append_number(value)
        else:
            raise RuntimeError(f"Can't add {value} to MessageSchedule!")
