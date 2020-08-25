#!/usr/bin/env python
'''

PS Vita Syscon Decryptor by SocraticBliss and CelesteBlue (R)

Dedicated to zecoxao <3

'''

from binascii import unhexlify as uhx
from Crypto.Cipher import AES
from hashlib import sha256 as SHA256

import struct
import sys

# Replace the 0's with the actual values! :)

KEYS = {
    '0x10' : '12B5408FD189E223B61890F488536008', # Proto
    '0x30' : '12B5408FD189E223B61890F488536008', # Proto
    '0x31' : '12B5408FD189E223B61890F488536008', # Proto
    '0x40' : '12B5408FD189E223B61890F488536008', # Proto
    '0x41' : '12B5408FD189E223B61890F488536008', # Proto
    '0x60' : '00000000000000000000000000000000', # Fat
    '0x70' : '67C34253A7DE13517EC903FE1119C04C', # TV
    '0x80' : '523BEB53FCB95DC772AA1BFB0A96CD10', # Slim
}

IVS = {
    '0x10' : '82D6528A87BC55B38EF29A45730EF130', # IRT-001
    '0x30' : '82D6528A87BC55B38EF29A45730EF130', # IRT-001
    '0x31' : '82D6528A87BC55B38EF29A45730EF130', # IRT-001
    '0x40' : '82D6528A87BC55B38EF29A45730EF130', # IRS-002  IRT-002
    '0x41' : '82D6528A87BC55B38EF29A45730EF130', # IRT-001
    '0x60' : '00000000000000000000000000000000', # IRS-1001
    '0x70' : 'DB302673D69F0D513A635E68A470F9C1', # DOL-1001 DOL-1002
    '0x80' : '385D67E50CE7669ECD171FE576814343', # USS-1001 USS-1002
}

# -------------------------------------------------------------------------------------------------

# Change to True to print debug messages
DEBUG = True 

KEY_HASHES = {
    '0x10' : 'E4E6457636C49370D45BE4D4A74DB6F8E9C92580EA6DFC18DCD3B8DD5F1AD7C4',
    '0x30' : 'E4E6457636C49370D45BE4D4A74DB6F8E9C92580EA6DFC18DCD3B8DD5F1AD7C4',
    '0x40' : 'E4E6457636C49370D45BE4D4A74DB6F8E9C92580EA6DFC18DCD3B8DD5F1AD7C4',
    '0x60' : '0000000000000000000000000000000000000000000000000000000000000000',
    '0x70' : 'B73CCBFB88BEBC22B01430BB998062F2F31FFE2685A3E0CA20043D31D626701C',
    '0x80' : '47AC83E3F871927C79DCFD1ACCDE6EE78D086C88F89126916AC7B89247382B12',
}

IV_HASHES = {
    '0x10' : 'E971875380ECE6E2750D641B71E0E5D6F0534FD93667010D93225F16197D60F4',
    '0x30' : 'E971875380ECE6E2750D641B71E0E5D6F0534FD93667010D93225F16197D60F4',
    '0x40' : 'E971875380ECE6E2750D641B71E0E5D6F0534FD93667010D93225F16197D60F4',
    '0x60' : '0000000000000000000000000000000000000000000000000000000000000000',
    '0x70' : 'A9742080D2B6D829EA8C521F09394884CC1CC53FACEC029CF45CC5F1EFCEF303',
    '0x80' : '6886FA3A6B787E9213F6B251CAB3EA3408A66CD20E9D14CB72F1FC1EF08DCE65',
}

class Header():
    
    def __init__(self, f):
        self.INDEX          = struct.unpack('>B', f.read(1))[0]
        self.HEADER_SIZE    = struct.unpack('>B', f.read(1))[0]
        self.BLOCK_SIZE     = struct.unpack('>H', f.read(2))[0]
        self.VER_UNK_IDX    = struct.unpack('<I', f.read(4))[0]
        self.HW_TYP_BLK     = struct.unpack('<I', f.read(4))[0]
        self.PADDING        = struct.unpack('4x', f.read(4))

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
    
    # Open Update File
    with open(sys.argv[1], 'rb') as INPUT:
        
        # Parse Index 1
        data = Header(INPUT)
        
        version  = '0x%08X' % data.VER_UNK_IDX
        hardware = '0x%08X' % data.HW_TYP_BLK
        mask     = '0x%02X' % ((data.HW_TYP_BLK & 0x00F00000) >> 0x10)
        output   = 'psvita_syscon_patch_' + hardware + '_' + version + '.bin'
        
        # Parse Index 2
        data = Header(INPUT)
        
        type     = '0x%02X' % (data.HW_TYP_BLK)
        
        # Check for valid Update Key
        try:
            if SHA256(uhx(KEYS[mask])).hexdigest().upper() != KEY_HASHES[mask]:
                raise SystemExit('\nError: Invalid Key!')
        
        except KeyError:
            raise SystemExit('\nError: Unsupported Model!')
        
        # Check for valid Update IV
        try:
            if SHA256(uhx(IVS[mask])).hexdigest().upper() != IV_HASHES[mask]:
                raise SystemExit('\nError: Invalid IV!')
        
        except KeyError:
            raise SystemExit('\nError: Unsupported Model!')
        
        encrypted = ''
        indexes   = []
        
        # Parse Index 10
        data = Header(INPUT)
        
        # Loop through the input file by blocks and save the encrypted data to a buffer
        while (data.BLOCK_SIZE != 0):
            
            debug('')
            debug('Index           : 0x%X' % data.INDEX)
            debug('Header Size     : 0x%X' % data.HEADER_SIZE)
            debug('Block Size      : 0x%X' % data.BLOCK_SIZE)
            debug('Block Index     : 0x%X' % data.VER_UNK_IDX)
            debug('Block Size(LE)  : 0x%X' % data.HW_TYP_BLK)
            
            indexes.append(data.VER_UNK_IDX)
            
            data = INPUT.read(data.HW_TYP_BLK)
            encrypted += data
            
            data = Header(INPUT)
    
    # Write decrypted data to a file
    with open(output, 'wb') as OUTPUT:
        
        # Zero-ify
        OUTPUT.write('\0' * 0x100000)
        OUTPUT.seek(0)
        
        decrypted = aes_decrypt_cbc(KEYS[mask], IVS[mask], encrypted)
        
        debug('')
        debug('Offset  | Block Index')
        debug('')
        
        offset = 0
        for index in indexes:
            if index >= 0xD5:
                index += 0x80
            OUTPUT.seek(0x400 * index)
            OUTPUT.write(decrypted[offset : offset + 0x400])
            offset += 0x400
            debug('0x%05X | 0x%X' % (offset, index))
    
    print('')
    print('Successfully decrypted to ' + output)


if __name__ == '__main__':
    main(len(sys.argv), sys.argv)

# PROGRAM END