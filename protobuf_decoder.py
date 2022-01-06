import sys
import json
from enum import Enum

INT_MAX = 2147483647


kTagTypeBits = 3


class WireType(Enum):
    WIRETYPE_VARINT = 0
    WIRETYPE_FIXED64 = 1
    WIRETYPE_LENGTH_DELIMITED = 2
    WIRETYPE_START_GROUP = 3
    WIRETYPE_END_GROUP = 4
    WIRETYPE_FIXED32 = 5


def print_usage():
    print("Usage: python protobuf_decoder.py <raw_protobuf_data_file> \n"
          "Read a protocol binary message from input file, and print data in json format")


def read_tag(data):
    res = data[0]
    if res < 128:
        return data[1:], res
    for i in range(1, 5):
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res
    return None, None


def get_tag_field_number(tag):
    return tag >> kTagTypeBits


def parse_varint(data):
    res = data[0]
    if not (res & 0x80):
        return data[1:], res
    for i in range(1, 10):
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res
    return None, None


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
    if res > INT_MAX:
        return None, None
    return data[5:], res


def read_size(data):
    res = data[0]
    if not (res & 0x80):
        return data[1:], res
    for i in range(1, 4):
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res
    byte = data[4]
    if byte >= 8:
        return None, None
    res += (byte - 1) << 28
    if res > INT_MAX:
        return None, None
    return data[5:], res


def read_string(data, size):
    return data[size:], str(data[:size], 'utf-8')


def read_bytes(data, size):
    return data[size:], data[:size].hex(' ')


def parse_length_delimited(data):
    data, size = read_size(data)
    res, success = parse_embedded_messages(data, size)
    if success:
        return data[size:], res
    try:
        data[:size].decode('utf-8')
        return read_string(data, size)
    except UnicodeError:
        return read_bytes(data, size)


def read_tag_limit(data, limit):
    if limit == 0:
        return None, None, False
    res = data[0]
    if res < 128:
        return data[1:], res, True
    for i in range(1, 5):
        if i >= limit:
            return None, None, False
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res, True
    return None, None


def parse_varint_limit(data, limit):
    if limit == 0:
        return None, None, False
    res = data[0]
    if not (res & 0x80):
        return data[1:], res, True

    for i in range(1, 10):
        if i >= limit:
            return None, None, False
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res, True

    return None, None, False


def parse_fix64_limit(data, limit):
    if limit < 8:
        return None, None, False
    else:
        data, res = parse_fix64(data)
        return data, res, True


def parse_fix32_limit(data, limit):
    if limit < 4:
        return None, None, False
    else:
        data, res = parse_fix64(data)
        return data, res, True


def read_size_limit(data, limit):
    if limit == 0:
        return None, None, False
    res = data[0]
    if not (res & 0x80):
        return data[1:], res, True
    for i in range(1, 4):
        if i >= limit:
            return None, None, False
        byte = data[i]
        res += (byte - 1) << 7 * i
        if byte < 128:
            return data[i + 1:], res, True
    if limit < 5:
        return None, None, False
    byte = data[4]
    if byte >= 8:
        return None, None, False
    res += (byte - 1) << 28
    if res > INT_MAX - kSlopBytes:
        return None, None, False
    return data[5:], res, True


def parse_length_delimited_limit(data, limit):
    data, size, success = read_size_limit(data, limit)
    if not success:
        return None, None, False
    res, success = parse_embedded_messages(data, size)
    if success:
        return data[size:], res, True
    if size <= limit:
        data, res = read_string(data, size)
        return data, res, True
    return None, None, False


def field_parser_limit(tag, data, limit):
    options = {WireType.WIRETYPE_VARINT: parse_varint_limit,
               WireType.WIRETYPE_FIXED64: parse_fix64_limit,
               WireType.WIRETYPE_LENGTH_DELIMITED: parse_length_delimited_limit,
               WireType.WIRETYPE_FIXED32: parse_fix32_limit}
    return options[WireType(tag & 7)](data, limit)


def parse_embedded_messages(data, size):
    context = {}
    origin_length = len(data)
    while origin_length - len(data) < size:
        data, tag, success = read_tag_limit(data, size - (origin_length - len(data)))
        if not success:
            return None, False
        if tag == 0 or (tag & 7) > 5\
                or WireType(tag & 7) == WireType(WireType.WIRETYPE_END_GROUP) \
                or WireType(tag & 7) == WireType(WireType.WIRETYPE_START_GROUP) :
            return None, False
        field = get_tag_field_number(tag)
        data, res, success = field_parser_limit(tag, data, size - (origin_length - len(data)))
        if not success:
            return None, False
        if str(field) in context:
            if type(context[str(field)]) is list:
                context[str(field)].append(res)
            else:
                arr = [context[str(field)], res]
                context[str(field)] = arr
            continue
        context[str(field)] = res
    return context, True


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


def parse_proto(data):
    context = {}
    while len(data) != 0:
        data, tag = read_tag(data)
        if tag == 0 or WireType(tag & 7) == WireType(WireType.WIRETYPE_END_GROUP):
            return None
        field = get_tag_field_number(tag)
        data, res = field_parser(tag, data)
        if str(field) in context:
            if type(context[str(field)]) is list:
                context[str(field)].append(res)
            else:
                arr = [context[str(field)], res]
                context[str(field)] = arr
            continue
        context[str(field)] = res
    return context


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_usage()
    with open(sys.argv[1], "rb") as file:
        binary_data = file.read()
    json_data = parse_proto(binary_data)
    print(json.dumps(json_data, indent=4, ensure_ascii=False))
