import idaapi

print 'Evaluating MD5'
# As a test, the following line detects a string in Password2.exe
#s = FindBinary(0, SEARCH_DOWN, "52 53 44 53 14 e0 67 e8 2d 3f d3 4f bc 1c 66 91")
s = FindBinary(0, SEARCH_DOWN, "d7 6a a4 78 e8 c7 b7 56 24 20 70 db c1 bd ce ee")

if s != 0xffffffff:
    print 'MD5 Constants present: 0x%x' % s
else:
    print 'No MD5'
