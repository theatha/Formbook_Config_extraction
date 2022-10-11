import re

CONFIG_PATTERNS = [
    re.compile(
        b"\x83\xc4\x0c\x6a\x14\xe8(....)\x83\xc0\x02\x50\x8d(..)\x51\xe8(....)\x83\xc4\x0c\x6a\x14\xe8(....)\x83\xc0\x02\x50\x8d(..)\x52",
        re.DOTALL,
    )
]

HASHS_PATTERNS = [
    re.compile(b"\x68(.)(\x02|\x03)\x00\x00\x8d(...)\x00\x00\xe8", re.DOTALL)
]

STRINGS_PATTERNS = [
    re.compile(
        b"\x6a\x00\x50\xc6\x85(....)\x00\xe8(....)\x83\xc4\x0c\x68(..)\x00\x00\xe8",
        re.DOTALL,
    )
]


CONFIG_DATA = []
