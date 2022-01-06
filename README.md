## Usage: python protobuf_decoder.py <binary_protobuf_data_file>
Read a protocol binary message from input file, and print data in json format

## Example
```
$ python protobuf_decoder.py example/protobuf.bin
{
    "1": "Baidu",
    "2": [
        {
            "1": "Mike",
            "2": 29,
            "3": 1,
            "4": "A123456"
        },
        {
            "1": "Amy",
            "2": 25,
            "4": "A654321"
        }
    ],
    "3": 123456789,
    "4": 100000000000000,
    "5": {
        "1": "China",
        "2": 123,
        "3": 456,
        "4": {
            "1": "haha@qq.com",
            "2": "A123456",
            "3": "dalala"
        }
    },
    "6": "ff f2 12 f4 34",
    "7": "\u0001\u0002\u0003\u0004\u0005\u0006"
}
```