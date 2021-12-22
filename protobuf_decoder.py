import sys
import json
from enum import Enum

INT_MAX = 2147483647


kTagTypeBits = 3


kSlopBytes = 16


class WireType(Enum):
    WIRETYPE_VARINT = 0
    WIRETYPE_FIXED64 = 1
    WIRETYPE_LENGTH_DELIMITED = 2
    WIRETYPE_START_GROUP = 3
    WIRETYPE_END_GROUP = 4
    WIRETYPE_FIXED32 = 5


def print_usage():
    print("Usage: python protobuf_decoder.py <raw_protobuf_data_file> \n"
          "Read a binary message from input file, and print filed:value pairs in text format")


def read_tag_fallback(data, res):
    for i in range(2, 5):
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res
    return None, None


def read_tag(data):
    res = data[0]
    if res < 128:
        return data[1:], res
    second = data[1]
    res += (second - 1) << 7
    if second < 128:
        return data[2:], res
    return read_tag_fallback(data, res)


def get_tag_field_number(tag):
    return tag >> kTagTypeBits


def parse_varint_slow(data, res):
    for i in range(2, 5):
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res
    # Accept > 5 bytes
    for i in range(5, 10):
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res
    return None, None


def parse_varint(data):
    res = data[0]
    if not (res & 0x80):
        return data[1:], res
    byte = data[1]
    res += (byte - 1) << 7
    if not (byte & 0x80):
        return data[2:], res
    return parse_varint_slow(data, res)


def read_size_fallback(data, res):
    for i in range(1, 4):
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res
    byte = data[4]
    if byte >= 8:
        return None, None
    res += (byte - 1) << 28
    if res > INT_MAX - kSlopBytes:
        return None, None
    return data[5:], res


def read_size(data):
    res = data[0]
    if not (res & 0x80):
        return data[1:], res
    return read_size_fallback()


def read_string(data, size):
    str_data = str(data[:size], 'utf-8')
    return data[size:], str_data


def parse_length_delimited(data):
    data, size = read_size(data)
    return read_string(data, size)


def parse_fix32(data):
    return data[4:], int.from_bytes(data[:4], 'little')


def parse_fix64(data):
    return data[8:], int.from_bytes(data[:8], 'little')


def field_parser(tag, data):
    options = {WireType.WIRETYPE_VARINT: parse_varint,
               WireType.WIRETYPE_FIXED64: parse_fix64,
               WireType.WIRETYPE_LENGTH_DELIMITED: parse_length_delimited,
               WireType.WIRETYPE_FIXED32: parse_fix32}
    return options[WireType(tag & 7)](data)


def parse_proto(file_name):
    context = {}
    data = open(file_name, "rb").read()
    while len(data) != 0:
        data, tag = read_tag(data)
        if tag == 0 or tag & 7 == WireType(WireType.WIRETYPE_END_GROUP):
            return None
        field = get_tag_field_number(tag)
        data, res = field_parser(tag, data)
        context[str(field)] = res
    return context


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_usage()
    json_data = parse_proto(sys.argv[1])
    print(json.dumps(json_data, indent=4, ensure_ascii=False))
