#!/usr/bin/env python
'''

PS Vita Syscon Loader by SocraticBliss (R)
Dedicated to zecoxao <3

psp2_syscon.py: IDA loader for reading Sony PlayStation(R) Vita Syscon Firmware files

'''

from idaapi import *
from idc import *

import idaapi as ida
import idc

# Load Processor Details...
def processor(processor):
    
    # Processor
    idc.set_processor_type(processor, SETPROC_LOADER)
    
    # Assembler
    idc.set_target_assembler(0x0)
    
    # Compiler
    idc.set_inf_attr(INF_COMPILER, COMP_GNU)
    
    # Loader Flags
    idc.set_inf_attr(INF_LFLAGS, LFLG_PC_FLAT | LFLG_COMPRESS)
    
    # Assume GCC3 names
    idc.set_inf_attr(INF_DEMNAMES, DEMNAM_GCC3)
    
    # Analysis Flags
    idc.set_inf_attr(INF_AF, 0xBFFFBFFF)

# Pablo's Function Search...
def function_search(mode, search, address = 0):

    while address < BADADDR:
        address = ida.find_binary(address, BADADDR, search, 0x10, SEARCH_DOWN)
        if address < BADADDR:
            address += mode
            ida.do_unknown(address, 0)
            ida.add_func(address, BADADDR)
            address += 1

# Load Segment Details...
def segment(f, start, end, name, type = 'DATA', perm = SEGPERM_MAXVAL):

    f.file2base(start, start, end, FILEREG_PATCHABLE)
    ida.add_segm(0x0, start, end, name, type, 0x0)
    
    # Processor Specific Segment Details
    idc.set_segm_addressing(start, 0x1)
    idc.set_segm_alignment(start, saAbs)
    idc.set_segm_combination(start, scPriv)
    idc.set_segm_attr(start, SEGATTR_PERM, perm)


# PROGRAM START

# Open File Dialog...
def accept_file(f, n):
    
    try:
        if not isinstance(n, (int, long)) or n == 0:
            f.seek(0xC0)
            return 'PS Vita - Syscon' if f.read(4) == '\x7F\xFF\xAA\x04' else 0
    
    except:
        pass

# Load Input Binary...
def load_file(f, neflags, format):
    
    print('# PS Vita Syscon Loader')
    
    # PS Vita Syscon Processor
    processor('rl78')
        
    # Boot Cluster 0
    print('# Creating Vector Table Area 0')
    segment(f, 0x0, 0x80, 'VTA0', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
       
    print('# Creating CALLT Table Area 0')
    segment(f, 0x80, 0xC0, 'CALLTTA0')
    
    for callt in xrange(0x20):
        address  = 0x80 + (callt * 2)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
    
    print('# Creating Option Byte Area 0')
    segment(f, 0xC0, 0xC4, 'OBA0')
    
    print('# Creating On-chip Debug Security 0')
    segment(f, 0xC4, 0xCE, 'ODS0')
    
    print('# Creating Program Area 0')
    segment(f, 0xCE, 0x1000, 'PA0', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    # Boot Cluster 1
    print('# Creating Vector Table Area 1')
    segment(f, 0x1000, 0x1080, 'VTA1')
    
    for vec in xrange(0x40):
        address  = 0x1000 + (vec * 2)
        
        function = ida.get_word(address)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        
        if function:
            ida.create_insn(function)
            ida.add_func(function, BADADDR)
            ida.op_plain_offset(address, 0, 0)
    
    print('# Creating CALLT Table Area 1')
    segment(f, 0x1080, 0x10C0, 'CALLTTA1')
    
    for callt in xrange(0x20):
        address  = 0x1080 + (callt * 2)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
    
    print('# Creating Option Byte Area 1')
    segment(f, 0x10C0, 0x10C4, 'OBA1')
    
    print('# Creating On-chip Debug Security 1')
    segment(f, 0x10C4, 0x10CE, 'ODS1')
       
    # ROM
    print('# Creating Program Area 1')
    segment(f, 0x10CE, 0x60000, 'PA1', 'CODE', SEGPERM_READ | SEGPERM_EXEC)
    
    # Create Additional Functions from VTA0
    for vec in xrange(0x40):
        address  = vec * 2
        
        function = ida.get_word(address)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        
        if function:
            ida.create_insn(function)
            ida.add_func(function, BADADDR)
            ida.op_plain_offset(address, 0, 0)
    
    '''
    VTA0 = [
        'RESET',
        '', # 0x2
        'INTWDTI', 
        'INTLVI',
        'INTP0',
        'INTP1',
        'INTP2',
        'INTP3',
        'INTP4',
        'INTP5',
        'INTST2',
        'INTSR2',
        'INTSRE2',
        'INTDMA0',
        'INTDMA1',
        'INTST0',
        'INTSR0',
        'INTSRE0',
        'INTST1',
        'INTSR1',
        'INTSRE1',
        'INTIICA0',
        'INTTM00',
        'INTTM01',
        'INTTM02',
        'INTTM03',
        'INTAD',
        'INTRTC',
        'INTIT',
        'INTKR',
        'INTST3',
        'INTSR3',
        'INTTM13',
        'INTTM04',
        'INTTM05',
        'INTTM06',
        'INTTM07',
        'INTP6',
        'INTP7',
        'INTP8',
        'INTP9',
        'INTP10',
        'INTP11',
        'INTTM10',
        'INTTM11',
        'INTTM12',
        'INTSRE3',
        'INTMD',
        'INTIICA1',
        'INTFL',
        'INTDMA2',
        'INTDMA3',
        'INTTM14',
        'INTTM15',
        'INTTM16',
        'INTTM17',
        '', # 0x70
        '', # 0x72
        '', # 0x74
        '', # 0x76
        '', # 0x78
        '', # 0x7A
        '', # 0x7C
        'BRK',
    ]
    address = 0x0
    
    for vec in VTA0:
        function = ida.get_word(address)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        
        if function:
            ida.create_insn(function)
            ida.add_func(function, BADADDR)
            if vec != '':
                ret = ida.set_name(function, vec, 0)
                print('Address: 0x%X Name: %s | %i' % (function, vec, ret))
            ida.op_plain_offset(address, 0, 0)

        
        address += 2
    '''
    
    # 0x60000 - 0xF0000 : Reserved
    print('# Creating Reserved')
    segment(f, 0x60000, 0xF0000, 'RES')
    
    print('# Creating Special Function Register 2')
    segment(f, 0xF0000, 0xF0800, 'SFR2')
    
    SFR2 = [
        (0xF0001, 'ADM2', 'A/D converter mode register 2'),
        (0xF0011, 'ADUL', 'Conversion result comparison upper limit setting register'),
        (0xF0012, 'ADLL', 'Conversion result comparison lower limit setting register'),
        (0xF0013, 'ADTES', 'A/D test register'),
        (0xF0030, 'PU0', 'Pull-up resistor option register 0'),
        (0xF0031, 'PU1', 'Pull-up resistor option register 1'),
        (0xF0033, 'PU3', 'Pull-up resistor option register 3'),
        (0xF0034, 'PU4', 'Pull-up resistor option register 4'),
        (0xF0035, 'PU5', 'Pull-up resistor option register 5'),
        (0xF0036, 'PU6', 'Pull-up resistor option register 6'),
        (0xF0037, 'PU7', 'Pull-up resistor option register 7'),
        (0xF0038, 'PU8', 'Pull-up resistor option register 8'),
        (0xF0039, 'PU9', 'Pull-up resistor option register 9'),
        (0xF003A, 'PU10', 'Pull-up resistor option register 10'),
        (0xF003B, 'PU11', 'Pull-up resistor option register 11'),
        (0xF003C, 'PU12', 'Pull-up resistor option register 12'),
        (0xF003E, 'PU14', 'Pull-up resistor option register 14'),
    ]
    
    for (address, name, comment) in SFR2:
        ida.set_name(address, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.set_cmt(address, comment, False)
    
    for sfr in xrange(0x800):
        ret = ida.create_data(0xF0000 + sfr, FF_BYTE, 0x1, BADNODE)
        #print('0x%X : %i' % (0xF0000 + sfr, ret))
    
    # Reserved 2
    print('# Creating Reserved 2')
    segment(f, 0xF0800, 0xF1000, 'RES2')
    
    # DATA
    print('# Creating Data Flash Memory')
    segment(f, 0xF1000, 0xF3000, 'DFM')
    
    print('# Creating Mirror')
    segment(f, 0xF3000, 0xF9F00, 'MIRROR')
    
    # RAM
    print('# Creating RAM')
    segment(f, 0xF9F00, 0xFFEE0, 'RAM')
    
    print('# Creating General-purpose Register')
    segment(f, 0xFFEE0, 0xFFF00, 'GR')
    
    GPR = [ 'X', 'A', 'C', 'B', 'E', 'D', 'L', 'H' ]
    address = 0xFFEE0
    
    for gpr in xrange(0x4):
        for entry in GPR:
            ida.create_data(address, FF_BYTE, 0x1, BADNODE)
            ida.set_name(address, 'RB%i%s' % (gpr, entry), SN_NOCHECK | SN_NOWARN | SN_FORCE)
            address += 1
    
    print('# Creating Special Function Register')
    segment(f, 0xFFF00, 0xFFFFF, 'SFR')
    
    for sfr in xrange(0xFF):
        ret = ida.create_data(0xFFF00 + sfr, FF_BYTE, 0x1, BADNODE)
        #print('0x%X : %i' % (0xF0000 + sfr, ret))
    
    # --------------------------------------------------------------------------------------------------------
    # Common
    
    pa1    = ida.get_segm_by_name('PA1')
    res    = ida.get_segm_by_name('RES')
    mirror = ida.get_segm_by_name('MIRROR')
    
    # --------------------------------------------------------------------------------------------------------
    # sc_cmd_entry - Find Command Table
    
    COMMANDS = {
        0x05   : 'Get_Hardware_Info',
        0xD2   : 'SNVS_Read_Write',
        0x1082 : 'NVS_Read',
    }
    
    entry = idc.add_struc(BADADDR, 'sc_cmd_entry', False)
    idc.add_struc_member(entry, 'cmd',  0x0, 0x10000400, BADADDR, 0x2)
    idc.add_struc_member(entry, 'flag', 0x2, 0x10000400, BADADDR, 0x2)
    idc.add_struc_member(entry, 'func', 0x4, 0x20500400, 0x0, 0x4, 0xFFFFFFFF, 0x0, 0x2)
    
    # --------------------------------------------------------------------------------------------------------
    # PA1 sc_cmd_entry    
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '00 04 00 00 00 00 ?? ?? 03 00', 0x10, SEARCH_DOWN) + 0x2
    #print('0x%X' % address)
    
    while True:
        command  = ida.get_word(address)
        flags    = ida.get_word(address + 0x2)
        function = ida.get_dword(address + 0x4)
        
        command = COMMANDS.get(command, 'cmd_0x%X_flags_0x%X' % (command, flags))
        ida.set_name(function, command, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_struct(address, 0x8, entry)
        if ida.get_word(address) == 0x2085:
            break
        address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror sc_cmd_entry
        
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '00 04 00 00 00 00 ?? ?? 03 00', 0x10, SEARCH_DOWN) + 0x2
    #print('0x%X' % address)
    
    while True:
        ida.create_struct(address, 0x8, entry)
        if ida.get_word(address) == 0x2085:
            break
        address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # sc_ext_cmd_entry - Find External Command Table
    
    entry = idc.add_struc(BADADDR, 'sc_ext_cmd_entry', False)
    idc.add_struc_member(entry, 'id', 0x0, 0x10000400, BADADDR, 0x2)
    idc.add_struc_member(entry, 'func',	0x2, 0x20500400, 0x0, 0x4, 0xFFFFFFFF, 0x0, 0x2)
    idc.add_struc_member(entry, 'flags', 0x6, 0x10000400, BADADDR, 0x2)
    
    # --------------------------------------------------------------------------------------------------------
    # PA1 sc_ext_cmd_entry
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '97 D5 00 01 ?? ?? 00 00 00 00', 0x10, SEARCH_DOWN) + 0x2
    #print('0x%X' % address)
      
    while True:
        command  = ida.get_word(address)
        function = ida.get_dword(address + 0x2)
        flags    = ida.get_word(address + 0x6)
        
        ida.set_name(function, 'ext_cmd_0x%X_flags_0x%X' % (command, flags), SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_struct(address, 0x8, entry)
        if ida.get_word(address) == 0x301:
            break
        address += 0x8
        
    # --------------------------------------------------------------------------------------------------------
    # Mirror sc_ext_cmd_entry
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '97 D5 00 01 ?? ?? 00 00 00 00', 0x10, SEARCH_DOWN) + 0x2
    #print('0x%X' % address)
      
    while True:
        ida.create_struct(address, 0x8, entry)
        if ida.get_word(address) == 0x301:
            break
        address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # sc_ext_cmd_entry - Find External Command Table 2  
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '97 D5 00 01 ?? ?? 01', 0x10, SEARCH_DOWN) + 0x2
    #print('0x%X' % address)

    while True:
        command  = ida.get_word(address)
        function = ida.get_dword(address + 0x2)
        flags    = ida.get_word(address + 0x6)
        
        ida.set_name(function, 'ext_cmd_0x%X_flags_0x%X' % (command, flags), SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_struct(address, 0x8, entry)
        if ida.get_word(address) == 0x969:
            break
        address += 0x8
    
    # --------------------------------------------------------------------------------------------------------
    # renesas_cmd_entry - Find Renesas Command Table
    
    COMMANDS = {
        0x00 : 'Reset',
        0x13 : 'Verify',
        0x14 : 'OCD_Related',
        0x20 : 'Chip_Erase',
        0x22 : 'Block_Erase',
        0x32 : 'Block_Blank_Check',
        0x40 : 'Programming',
        0x9A : 'Baud_Rate_Set',
        0xA0 : 'Security_Set',
        0xA1 : 'Security_Get',
        0xA2 : 'Security_Release',
        0xB0 : 'Checksum',
        0xC0 : 'Silicon_Signature',
        0xC5 : 'Version_Get',
    }
    
    entry = idc.add_struc(BADADDR, 'renesas_cmd_entry', False)
    idc.add_struc_member(entry, 'version',	0x0, 0x10000400, BADADDR, 0x2)
    idc.add_struc_member(entry, 'ext_function_address', 0x2, 0x10000400, BADADDR, 0x32)
    idc.add_struc_member(entry, 'ext_function_code', 0x34,	0x400, BADADDR, 0xC)
    idc.add_struc_member(entry, 'unknown',	0x40, 0x400, BADADDR, 0x20)
    idc.add_struc_member(entry, 'int_function_address', 0x60, 0x10000400, BADADDR, 0x10)
    idc.add_struc_member(entry, 'int_function_code', 0x70,	0x400, BADADDR, 0x8)
    idc.add_struc_member(entry, 'unknown2', 0x78, 0x400, BADADDR, 0x1A)
    
    address = ida.find_binary(res.start_ea, res.end_ea, '03 03', 0x10, SEARCH_DOWN) + 0x2
    #print('0x%X' % address)
    
    ida.create_struct(address - 0x2, 0x92, entry)
    
    # --------------------------------------------------------------------------------------------------------
    # External Functions
    
    ext_functions = []
    while ida.get_word(address) != 0x1300:
        ext_function = ida.get_word(address) + 0xE0000
        #print('ext_function: 0x%X' % ext_function)
        
        ida.create_insn(ext_function)
        if ida.print_insn_mnem(ext_function) != 'nop':
            ida.add_func(ext_function, BADADDR)
        
        '''
        print(ida.print_insn_mnem(ext_function + 0x3))
        if ida.print_insn_mnem(ext_function + 0x3) == 'br':
            ida.add_func(ext_function, ext_function + 0x5)
        else:
            ida.add_func(ext_function, BADADDR)
        '''
        
        ext_functions.append(ext_function)
        
        address += 2
    
    # --------------------------------------------------------------------------------------------------------
    # External Commands
    
    while ida.get_byte(address) != 0x3:
        command = ida.get_byte(address)
        #print('ext_function: 0x%X' % ext_functions[0])
        
        command = COMMANDS.get(command, 'renesas_ext_cmd_0x%X' % command)
        ida.set_name(ext_functions[0], command, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        ext_functions.pop(0)
        
        address += 0x1
    
    address += 0x20
    #print('int_function_start: 0x%X' % address)
    
    # --------------------------------------------------------------------------------------------------------
    # Internal Functions
    
    int_functions = []
    while ida.get_word(address) != 0xCD0E:
        int_function = ida.get_word(address) + 0xE0000
        #print('int_function: 0x%X' % int_function)
        
        ida.create_insn(int_function)
        if ida.print_insn_mnem(int_function) != 'nop':
            ida.add_func(int_function, BADADDR)
        
        int_functions.append(int_function)
        
        address += 2
    
    # --------------------------------------------------------------------------------------------------------
    # Internal Commands
    
    while ida.get_byte(address) != 0x87:
        command = ida.get_byte(address)
        #print('int_function: 0x%X' % int_functions[0])
        
        command = COMMANDS.get(command, 'renesas_int_cmd_0x%X' % command)
        ida.set_name(int_functions[0], command, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        
        int_functions.pop(0)
        
        address += 0x1
    
    # --------------------------------------------------------------------------------------------------------
    # Signature Data

    entry = idc.add_struc(BADADDR, 'signature_data', False)
    idc.add_struc_member(entry, 'device_code', 0x0,	0x400, BADADDR, 0x3);
    idc.add_struc_member(entry, 'device_name', 0x3,	0x5000c400,	0,	0xA);
    idc.add_struc_member(entry, 'code_flash_mem_area_last_address',	0xD, 0x9400, BADADDR, 0x3);
    idc.add_struc_member(entry, 'data_flash_mem_area_last_address', 0x10, 0x400, BADADDR, 0x3);
    idc.add_struc_member(entry, 'firmware_version', 0x13, 0x400, BADADDR, 0x3);
    
    address = ida.find_binary(res.start_ea, res.end_ea, '10 00 06', 0x10, SEARCH_DOWN)
    #print('0x%X' % address)
    
    ida.create_struct(address, 0x16, entry)
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Command Keys    
   
    KEYS = [
        'SharedData_B',
        'SharedKey_B_A',
        'SharedKey_B_B',
        'SharedData_F_A',
        'SharedData_F_B',
        'SharedKey_F_A',
        'SharedKey_F_B',
        'SharedKey_F_C',
    ]    
    
    entry = idc.add_struc(BADADDR, 'key', False)
    idc.add_struc_member(entry, 'key', 0, 0x400, BADADDR, 0x10)    
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, 'CF 2E 93 E9 F9 4E 28 CC', 0x10, SEARCH_DOWN)
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x80)
    
    for count, key in enumerate(KEYS):
        ida.create_data(address + (count * 0x10), FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address + (count * 0x10), 0x10, entry)
        ida.set_name(address + (count * 0x10), key, SN_NOCHECK | SN_NOWARN | SN_FORCE)    
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Unknown Command Keys
    
    KEYS = [
        'SharedData_0',
        'SharedKey_0_A',
        'SharedKey_0_B',
        'SharedData_1',
        'SharedKey_1_A',
        'SharedKey_1_B',
        'SharedData_E',
        'SharedKey_E_A',
        'SharedKey_E_B',
    ]
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '80 99 6F BB C8 B4 EB A3', 0x10, SEARCH_DOWN)
    shared = address
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x90)
    
    for count, key in enumerate(KEYS):
        ida.create_data(address + (count * 0x10), FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address + (count * 0x10), 0x10, entry)
        ida.set_name(address + (count * 0x10), key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 g_debug_challenge_key
    
    address += 0x90
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x20)
    
    ida.create_data(address, FF_BYTE, 0x20, BADNODE)
    ida.set_name(address, 'g_debug_challenge_key', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 jigkick_expansion Keys
    
    address += 0x20
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0xE0)
    
    for key in xrange(13):
        ida.create_data(address + (key * 0x10), FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address + (key * 0x10), 0x10, entry)
        ida.set_name(address + (key * 0x10), 'jigkick_expansion_%X' % key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Unknown Shared Keys    
    
    KEYS = [
        'SharedKey_0',
        'SharedKey_1',
        'SharedKey_E',
    ]
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '%02X %02X 00 00' % (shared & 0xFF, ((shared >> 0x8) & 0xFF)), 0x10, SEARCH_DOWN) - 0xA
    #print('address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x2A)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA, FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    ida.del_items(address, 0, 0x2A)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA, FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 Shared Keys        
    
    KEYS = [
        'SharedKey_B',
        'SharedKey_F',
    ]
    
    ida.del_items(address, 0, 0x2C)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xE,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x12, FF_DWORD, 0x4, BADNODE)
        
        address += 0x16

    ida.del_items(address, 0, 0x2A)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA,  FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    # --------------------------------------------------------------------------------------------------------
    # SP1 MISC Keys/Data
    
    MISC = [
        'AES_KEY',
        'AES_IV',
        'XOR_KEY',
    ]
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, 'DB D9 45 0A CC A8 54 48', 0x10, SEARCH_DOWN)
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x30)
    
    for count, key in enumerate(MISC):
        ida.create_data(address + (count * 0x10), FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address + (count * 0x10), 0x10, entry)
        ida.set_name(address + (count * 0x10), key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # PA1 SERVICE_0x900_DATA Key
    
    address = ida.find_binary(pa1.start_ea, pa1.end_ea, '93 CE 8E BE DF 7F 69 A9', 0x10, SEARCH_DOWN)
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x10)
    ida.create_data(address, FF_BYTE, 0x10, BADNODE)
    ida.create_struct(address, 0x10, entry)
    ida.set_name(address, 'SERVICE_0x900_DATA', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    address += 0x10
    
    address = ida.find_binary(address, pa1.end_ea, '93 CE 8E BE DF 7F 69 A9', 0x10, SEARCH_DOWN)
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x10)
    ida.create_data(address, FF_BYTE, 0x10, BADNODE)
    ida.create_struct(address, 0x10, entry)
    ida.set_name(address, 'SERVICE_0x900_DATA', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror Command Keys    
   
    KEYS = [
        '_SharedData_B',
        '_SharedKey_B_A',
        '_SharedKey_B_B',
        '_SharedData_F_A',
        '_SharedData_F_B',
        '_SharedKey_F_A',
        '_SharedKey_F_B',
        '_SharedKey_F_C',
    ]
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, 'CF 2E 93 E9 F9 4E 28 CC', 0x10, SEARCH_DOWN)
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x80)
    
    for count, key in enumerate(KEYS):
        ida.create_data(address + (count * 0x10), FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address + (count * 0x10), 0x10, entry)
        ida.set_name(address + (count * 0x10), key, SN_NOCHECK | SN_NOWARN | SN_FORCE) 
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror Unknown Command Keys
    
    KEYS = [
        '_SharedData_0',
        '_SharedKey_0_A',
        '_SharedKey_0_B',
        '_SharedData_1',
        '_SharedKey_1_A',
        '_SharedKey_1_B',
        '_SharedData_E',
        '_SharedKey_E_A',
        '_SharedKey_E_B',
    ]    
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '80 99 6F BB C8 B4 EB A3', 0x10, SEARCH_DOWN)
    shared = address
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x90)
    
    for count, key in enumerate(KEYS):
        ida.create_data(address + (count * 0x10), FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address + (count * 0x10), 0x10, entry)
        ida.set_name(address + (count * 0x10), key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror g_debug_challenge_key
    
    address += 0x90
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x20)
    
    ida.create_data(address, FF_BYTE, 0x20, BADNODE)
    ida.set_name(address, '_g_debug_challenge_key', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror jigkick_expansion Keys
    
    address += 0x20
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0xE0)
    
    for key in xrange(13):
        ida.create_data(address + (key * 0x10), FF_BYTE, 0x10, BADNODE)
        ida.create_struct(address + (key * 0x10), 0x10, entry)
        ida.set_name(address + (key * 0x10), '_jigkick_expansion_%X' % key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror Unknown Shared Keys    
    
    KEYS = [
        '_SharedKey_0',
        '_SharedKey_1',
        '_SharedKey_E',   
    ]    
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '%02X %02X 00 00' % (shared & 0xFF, ((shared >> 0x8) & 0xFF)), 0x10, SEARCH_DOWN) - 0xA
    #print('address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x2A)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA, FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    ida.del_items(address, 0, 0x2A)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6, FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA, FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror Shared Keys        
    
    KEYS = [
        '_SharedKey_B',
        '_SharedKey_F',
    ]
    
    ida.del_items(address, 0, 0x2C)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xE,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x12, FF_DWORD, 0x4, BADNODE)
        
        address += 0x16

    ida.del_items(address, 0, 0x2A)
    
    for count, key in enumerate(KEYS):
        ida.set_name(address, key, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        ida.create_data(address, FF_WORD, 0x2, BADNODE)
        ida.create_data(address + 0x2,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0x6,  FF_DWORD, 0x4, BADNODE)
        ida.create_data(address + 0xA,  FF_DWORD, 0x4, BADNODE)
        
        address += 0xE
    
    # --------------------------------------------------------------------------------------------------------
    # Mirror SERVICE_0x900_DATA Key
    
    address = ida.find_binary(mirror.start_ea, mirror.end_ea, '93 CE 8E BE DF 7F 69 A9', 0x10, SEARCH_DOWN)
    #print('key address: 0x%X' % address)
    
    ida.del_items(address, 0, 0x10)
    ida.create_data(address, FF_BYTE, 0x10, BADNODE)
    ida.create_struct(address, 0x10, entry)
    ida.set_name(address, '_SERVICE_0x900_DATA', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    
    # --------------------------------------------------------------------------------------------------------
    
    
    print('# Search Function Start')
    function_search(1, 'D7 61 DD')
    function_search(1, 'FF C3 31 17')
    function_search(1, 'FB C3 31 17')
    function_search(1, 'FF 61 DD 8E FA')
    function_search(1, 'FF 61 DD C7')
    function_search(0, '61 DD C7')
    function_search(1, 'D7 C7 C3 C1')
    function_search(1, 'D7 C7 16')
    function_search(1, 'D7 30 02 00 C1')
    function_search(1, 'D7 C7 C1')
    function_search(1, 'D7 C7 88')
    function_search(1, 'D7 C7 20')
    function_search(1, 'D7 C7 41')
    function_search(1, 'D7 C7 36')
    function_search(1, '00 C7 C3 C1 FB')
    function_search(1, 'FF C7 57')
    function_search(2, '00 00 C7 C5 C1')
    
    
    # --------------------------------------------------------------------------------------------------------
    
    print('# Done!')
    return 1

# PROGRAM END