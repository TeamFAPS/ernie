#!/usr/bin/env python
'''
PSVita SysCon Update Decryptor

2020-2021 SocraticBliss and CelesteBlue

Dedicated to zecoxao and wildcard <3

Requires Python 3, Pycrypto
Advice: pip install pycryptodome
'''

from binascii import unhexlify as uhx
from Crypto.Cipher import AES
from hashlib import sha256 as SHA256
from hashlib import sha1 as SHA1

import struct
import sys

# Replace the 0's with the actual values! :)

KEYS = {
    '0x10' : '12B5408FD189E223B61890F488536008', # Fat v1
    '0x30' : '12B5408FD189E223B61890F488536008', # Fat v1
    '0x40' : '12B5408FD189E223B61890F488536008', # Fat v1
    '0x50' : '00000000000000000000000000000000', # PSTV prototype
    '0x60' : '8C9ED3908C4143AE02855794C025BE1A', # Fat v2
    '0x70' : '67C34253A7DE13517EC903FE1119C04C', # PSTV
    '0x80' : '523BEB53FCB95DC772AA1BFB0A96CD10', # Slim
    '0x90' : '00000000000000000000000000000000', # Unknown prototype
}

IVS = {
    '0x10' : '82D6528A87BC55B38EF29A45730EF130', # Fat v1
    '0x30' : '82D6528A87BC55B38EF29A45730EF130', # Fat v1
    '0x40' : '82D6528A87BC55B38EF29A45730EF130', # Fat v1
    '0x50' : '00000000000000000000000000000000', # PSTV prototype
    '0x60' : 'C85AE1576D5E205FE8043573F55F4E11', # Fat v2
    '0x70' : 'DB302673D69F0D513A635E68A470F9C1', # PSTV
    '0x80' : '385D67E50CE7669ECD171FE576814343', # Slim
    '0x90' : '00000000000000000000000000000000', # Unknown prototype
}

# -------------------------------------------------------------------------------------------------

# Change to True to print debug messages
DEBUG = True 

KEY_HASHES = {
    '0x10' : 'E4E6457636C49370D45BE4D4A74DB6F8E9C92580EA6DFC18DCD3B8DD5F1AD7C4',
    '0x30' : 'E4E6457636C49370D45BE4D4A74DB6F8E9C92580EA6DFC18DCD3B8DD5F1AD7C4',
    '0x40' : 'E4E6457636C49370D45BE4D4A74DB6F8E9C92580EA6DFC18DCD3B8DD5F1AD7C4',
    '0x50' : '0000000000000000000000000000000000000000000000000000000000000000',
    '0x60' : 'EF973BB6D44BDA1680F82CA3923A29AA86C2407A0339F72CA1CC30CB63ACE5CE',
    '0x70' : 'B73CCBFB88BEBC22B01430BB998062F2F31FFE2685A3E0CA20043D31D626701C',
    '0x80' : '47AC83E3F871927C79DCFD1ACCDE6EE78D086C88F89126916AC7B89247382B12',
    '0x90' : '0000000000000000000000000000000000000000000000000000000000000000',
}

IV_HASHES = {
    '0x10' : 'E971875380ECE6E2750D641B71E0E5D6F0534FD93667010D93225F16197D60F4',
    '0x30' : 'E971875380ECE6E2750D641B71E0E5D6F0534FD93667010D93225F16197D60F4',
    '0x40' : 'E971875380ECE6E2750D641B71E0E5D6F0534FD93667010D93225F16197D60F4',
    '0x50' : '0000000000000000000000000000000000000000000000000000000000000000',
    '0x60' : '44F71C37FF1ED9810E36126C31B0218FFEE4E853200E2576EAEC1BC6C8BD7E23',
    '0x70' : 'A9742080D2B6D829EA8C521F09394884CC1CC53FACEC029CF45CC5F1EFCEF303',
    '0x80' : '6886FA3A6B787E9213F6B251CAB3EA3408A66CD20E9D14CB72F1FC1EF08DCE65',
    '0x90' : '0000000000000000000000000000000000000000000000000000000000000000',
}

class Header():
    def __init__(self, f):
        self.TYPE              = struct.unpack('>B', f.read(1))[0]
        self.HEADER_SIZE       = struct.unpack('>B', f.read(1))[0]
        self.SIZE              = struct.unpack('>H', f.read(2))[0]
        if self.TYPE == 1:
            self.FW_VERSION    = struct.unpack('<I', f.read(4))[0]
            self.HW_INFO       = struct.unpack('<I', f.read(4))[0]
            self.PADDING       = struct.unpack('4x', f.read(4))
        elif self.TYPE == 2:
            self.IMG_SIZE      = struct.unpack('<I', f.read(4))[0]
            self.FW_TYPE       = struct.unpack('<I', f.read(4))[0]
            self.PADDING       = struct.unpack('4x', f.read(4))
        elif self.TYPE == 0x10:
            self.SEGMENT_NO    = struct.unpack('<I', f.read(4))[0]
            self.SEGMENT_SIZE  = struct.unpack('<I', f.read(4))[0]
            self.PADDING       = struct.unpack('4x', f.read(4))
        elif self.TYPE == 0x20:
            self.HASH          = f.read(20)
        else:
            raise SystemExit('\nError: Unsupported packet type!')

def aes_decrypt_cbc(key, iv, input):
    return AES.new(uhx(key), AES.MODE_CBC, uhx(iv)).decrypt(input)

def debug(message):
    if DEBUG:
        print(message)

# PROGRAM START

def main(argc, argv):

    # Check for valid input arguments
    if argc != 2:
        raise SystemExit('\nUsage: %s [Input]' % argv[0])

    # Open Syscon Update file
    with open(sys.argv[1], 'rb') as INPUT:

        # Parse Packet Type 1
        data = Header(INPUT)
        fw_version = '0x%08X' % data.FW_VERSION
        hw_info = '0x%08X' % data.HW_INFO
        hw_info_mask = '0x%02X' % ((data.HW_INFO & 0x00F00000) >> 0x10)
        output_filename = 'psvita_syscon_patch_' + hw_info + '_' + fw_version + '.bin'

        # Parse Packet Type 2
        data = Header(INPUT)
        img_size = '0x%02X' % (data.IMG_SIZE)
        fw_type = '0x%02X' % (data.FW_TYPE)

        # Check for valid Update Key
        try:
            if SHA256(uhx(KEYS[hw_info_mask])).hexdigest().upper() != KEY_HASHES[hw_info_mask]:
                raise SystemExit('\nError: Invalid key!')
        except KeyError:
            raise SystemExit('\nError: Unsupported model!')

        # Check for valid Update IV
        try:
            if SHA256(uhx(IVS[hw_info_mask])).hexdigest().upper() != IV_HASHES[hw_info_mask]:
                raise SystemExit('\nError: Invalid IV!')
        except KeyError:
            raise SystemExit('\nError: Unsupported model!')

        # Parse Packet Type 0x10
        header_data = Header(INPUT)
        encrypted_data = bytearray()
        segment_indexes = []

        # Loop through the input file by packets and save the encrypted data to a buffer
        while (header_data.SIZE != 0):
            #debug('')
            #debug('Type           : 0x%X' % header_data.TYPE)
            #debug('Header Size    : 0x%X' % header_data.HEADER_SIZE)
            #debug('Size           : 0x%X' % header_data.SIZE)
            body_data = INPUT.read(header_data.SIZE)
            if header_data.TYPE == 0x10:
                #debug('Segment Number : 0x%X' % header_data.SEGMENT_NO)
                #debug('Segment Size   : 0x%X' % header_data.SEGMENT_SIZE)
                segment_size = header_data.SEGMENT_SIZE
                segment_indexes.append(header_data.SEGMENT_NO)
                encrypted_data.extend(body_data)
            header_data = Header(INPUT)

    # Parse Packet Type 0x20
    hash = header_data.HASH

    # Decrypt the concatenated data
    decrypted_data = aes_decrypt_cbc(KEYS[hw_info_mask], IVS[hw_info_mask], encrypted_data)

    # Check for valid Update data
    if SHA1(decrypted_data).digest() != hash:
        raise SystemExit('\nError: Invalid Update data!')

    # Write decrypted data to a file
    with open(output_filename, 'wb') as OUTPUT:
        # Zero-ify
        OUTPUT.write(b'\0' * 0x100000)
        OUTPUT.seek(0)
		
        # Write
        debug('')
        debug('Offset   | Segment Index')
        decrypted_data_offset = 0
        for segment_no in segment_indexes:
            output_offset = segment_size * segment_no
            OUTPUT.seek(output_offset)
            OUTPUT.write(decrypted_data[decrypted_data_offset : decrypted_data_offset + segment_size])
            debug('0x%06X | 0x%X' % (output_offset, segment_no))
            decrypted_data_offset += segment_size
    print('')
    print('Syscon Update successfully decrypted to ' + output_filename)

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)

# PROGRAM END