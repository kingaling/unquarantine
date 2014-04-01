__author__ = 'Shane The King'

# Usage: python unquarantine.py some.vbn
# If file that was quarantined was name badguy.exe, the output file will be badguy.exe.malware

# !!! Note: I have not put any error checking in yet with regards to open and closing files.
# If the destination file already exists, it will be overwritten.

# Have a nice day.

import struct
import sys
import os


def dataread(size, key):
    i = bytearray(f.read(size))
    i = xor(i, key)

    return i


def xor(data, key):
    for i in xrange(len(data)):
        data[i] ^= key

    return data


def unquarantine(size, key):
    i = dataread(size, key)
    f.seek(f.tell() + 1)

    return i


fName = ''
orSize = 0
garbage = 0
vbnSize = os.path.getsize(sys.argv[1])

f = open(sys.argv[1], 'rb')

f.seek(0x4)
while True:
    fn = f.read(1)
    if fn != '\x00':
        fName += fn
    else:
        break

fName = fName[(fName.rfind('\\') + 1):]
fName += '.malware'
f.seek(0xD40)
if struct.unpack('<I', f.read(4))[0] == 2:
    f.seek(0xD54)
    orSize = struct.unpack('<I', f.read(4))[0]

if orSize > vbnSize:
    f.close()
    print "Variable defining quarantined file size is larger then the whole VBN file. Somethings wrong... aborting :/"
    quit()

f.seek(0x12A0)
mSize = struct.unpack('<I', str(dataread(4, 0x5A)))[0]

f.seek(0x12B0)
aftermetaSize = struct.unpack('<I', str(dataread(4, 0x5A)))[0]

f.seek(0x12B8 + mSize)
f.seek(f.tell() + 8)

x = struct.unpack('<I', str(dataread(4, 0x5A)))[0]

md5 = dataread(x, 0x5A)

f.seek(f.tell() + 15)

firstX = struct.unpack('<I', str(dataread(4, 0x5A)))[0]

if orSize > 0:
    garbage = firstX - orSize
else:
    orSize = firstX

f.seek(f.tell() + 4)
x = ord(f.read(1))

if x == 82:
    x = struct.unpack('<I', str(dataread(4, 0x5A)))[0]
    f.seek(f.tell() + x + 6)
    secondX = struct.unpack('<I', str(dataread(4, 0x5A)))[0]
    if firstX != secondX:
        print '!!PANIC!!  Two file different size values encountered after md5 section.'
        print "Need to learn what caused this. I couldn't test for this cause none of my samples did this."
        print "\nAborting..."
        f.close()
        exit()

    f.seek(f.tell() + 4)
    x = ord(f.read(1))

if x == 83:
    u = open(fName, 'w')
    while True:
        if f.tell() > vbnSize:
            u.close()
            break
        else:
            chunkSize = struct.unpack('<I', str(dataread(4, 0x5A)))[0]
            if garbage > 0:
                f.seek(f.tell() + garbage)
                chunkSize -= garbage
                garbage = 0

            newData = unquarantine(chunkSize, 0xA5)
            u.write(newData)

    if not u.closed:
        u.close()

print str(fName) + " should have been written to your current working directory."