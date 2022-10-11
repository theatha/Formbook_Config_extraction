import pprint
import sys 
import pefile
from utils.formbook_extractor import *
from config.patterns import *


def main():

    with open(
        sys.argv[1],
        mode="rb",
    ) as file:
        data = file.read()

        pe = pefile.PE(data=data)
        # print(pe)
        for pattern in CONFIG_PATTERNS:
            offset = re.search(pattern, data).start()

        offset += 6
        key1_offset = unpack("=I", data[offset : offset + 4])[0] + offset + 11
        key1 = data[key1_offset : key1_offset + (0x14 * 2)]
        offset += 23
        key2_offset = unpack("=I", data[offset : offset + 4])[0] + offset + 11
        key2 = data[key2_offset : key2_offset + (0x14 * 2)]
        offset += 21
        config_size = unpack("=I", data[offset : offset + 4])[0]
        offset += 5
        config_offset = unpack("=I", data[offset : offset + 4])[0] + offset + 11
        config = data[config_offset : config_offset + (config_size * 2)]
        offset += 33
        url_size = unpack("b", data[offset])[0]

        for pattern in STRINGS_PATTERNS:
            offset = re.search(pattern, data).start()

        offset += 19
        strings_size = unpack("=I", data[offset : offset + 4])[0]
        offset += 5
        strings_offset = unpack("=I", data[offset : offset + 4])[0] + offset + 11
        strings_data = data[strings_offset : strings_offset + (strings_size * 2)]

        for pattern in HASHS_PATTERNS:
            offset = re.search(pattern, data).start()

        offset += 1
        hashs_size = unpack("=I", data[offset : offset + 4])[0]
        offset += 11
        hashs_offset = unpack("=I", data[offset : offset + 4])[0] + offset + 11
        hashs_data = data[hashs_offset : hashs_offset + (hashs_size * 2)]

        CONFIG_DATA.append(
            formbook_decrypt(
                key1,
                key2,
                config,
                config_size,
                strings_data,
                strings_size,
                url_size,
                hashs_data,
                hashs_size,
            )
        )

        print(CONFIG_DATA)
        # for elem in CONFIG_DATA:
        #     pprint.pprint(elem)


if __name__ == "__main__":
    main()
