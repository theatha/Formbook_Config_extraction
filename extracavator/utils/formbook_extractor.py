from struct import unpack, unpack_from, pack
from collections import OrderedDict
from utils.formbook_decryption import FormBookDecryption
from Crypto.Hash import SHA


def sha1_revert(digest):
    tuples = unpack("<IIIII", digest)
    output_hash = ""
    for item in tuples:
        output_hash += pack(">I", item)
    return output_hash


def formbook_compute_sha1(input_buffer):
    sha1 = SHA.new()
    sha1.update(input_buffer)
    return sha1_revert(sha1.digest())


def formbook_decrypt_strings(fb_decrypt, p_data, key, encrypted_strings):
    offset = 0
    i = 0
    while offset < len(encrypted_strings):
        str_len = ord(encrypted_strings[offset])
        offset += 1
        dec_str = fb_decrypt.decrypt_func2(
            encrypted_strings[offset : offset + str_len], key
        )
        dec_str = dec_str[:-1]  # remove '\0' character
        p_data["Encoded string " + str(i)] = dec_str
        offset += str_len
        i += 1

    return p_data


def formbook_decrypt(
    key1,
    key2,
    config,
    config_size,
    strings_data,
    strings_size,
    url_size,
    hashs_data,
    hashs_size,
):
    fb_decrypt = FormBookDecryption()
    p_data = OrderedDict()

    rc4_key_one = fb_decrypt.decrypt_func1(key1, 0x14)
    rc4_key_two = fb_decrypt.decrypt_func1(key2, 0x14)
    encbuf2_s1 = fb_decrypt.decrypt_func1(hashs_data, hashs_size)
    encbuf8_s1 = fb_decrypt.decrypt_func1(config, config_size)
    encbuf9_s1 = fb_decrypt.decrypt_func1(strings_data, strings_size)

    rc4_key_1 = formbook_compute_sha1(encbuf8_s1)
    rc4_key_2 = formbook_compute_sha1(encbuf9_s1)
    rc4_key_3 = formbook_compute_sha1(rc4_key_two)
    encbuf2_s2 = fb_decrypt.decrypt_func2(encbuf2_s1, rc4_key_1)
    encbuf8_s2 = fb_decrypt.decrypt_func2(encbuf8_s1, rc4_key_2)

    n = 1
    for i in range(config_size):
        encrypted_c2c_uri = encbuf8_s2[i : i + url_size]
        encrypted_c2c_uri = fb_decrypt.decrypt_func2(encrypted_c2c_uri, rc4_key_two)
        c2c_uri = fb_decrypt.decrypt_func2(encrypted_c2c_uri, rc4_key_one)
        if "www." in c2c_uri:
            p_data["C&C URI " + str(n)] = c2c_uri
            n += 1

    encrypted_hashes_array = fb_decrypt.decrypt_func2(encbuf2_s2, rc4_key_3)
    rc4_key_pre_final = formbook_compute_sha1(encrypted_hashes_array)
    rc4_key_final = fb_decrypt.decrypt_func2(rc4_key_two, rc4_key_pre_final)

    p_data = formbook_decrypt_strings(fb_decrypt, p_data, rc4_key_final, encbuf9_s1)

    return p_data
