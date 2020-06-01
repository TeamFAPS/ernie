#python2
import struct

with open("USS-1001.bin", "rb") as f:
	f.seek(0x26BE)
	print '{:<6} {:<5} {:<7}'.format("Number", "Flags", "Address")
	for i in xrange(0, 70):
		num = "0x" + hex(struct.unpack('<H', f.read(2))[0])[2:].upper()
		flags = "0x" + hex(struct.unpack('<H', f.read(2))[0])[2:].upper()
		address = "0x" + hex(struct.unpack('<I', f.read(4))[0])[2:].upper()
		print '{:<6} {:<5} {:<7}'.format(num, flags, address)