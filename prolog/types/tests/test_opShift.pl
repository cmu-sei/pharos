opAsr(0x1, 0x2, 0x3).
value(0x3, 0x1f). % required 

opRol(0x4, 0x5, 0x6).
value(0x6, 0x1f). % required

opRor(0x7, 0x8, 0x9).
value(0x9, 0xf1). % required



% tests for Asr
expectedPointer(0x1, isnot).
expectedPointer(0x2, isnot).
expectedPointer(0x3, isnot).
expectedSigned(0x3, isnot).

% tests for Rol
expectedPointer(0x4, isnot).
expectedPointer(0x5, isnot).
expectedPointer(0x6, isnot).
expectedSigned(0x6, isnot).

% tests for ror
expectedPointer(0x7, isnot).
expectedPointer(0x8, isnot).
expectedPointer(0x9, isnot).
expectedSigned(0x9, isnot).

