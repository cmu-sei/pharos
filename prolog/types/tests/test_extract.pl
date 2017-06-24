opExtract(0x1, 0x2, 0x3, 0x4).

value(0x2, 0x1f).
value(0x3, 0x20).

bitwidth(0x4, 0x21).
bitwidth(0x1, 0x1).
bitwidth(0x2, 0x20).
bitwidth(0x3, 0x20).


expectedPointer(0x1, isnot). % result of extract is not a pointer
expectedPointer(0x2, isnot). % start of extraction is not a pointer (is it signed?)
expectedPointer(0x3, isnot). % end of extraction is not a pointer (is it signed?)

% the begin and end signed values are not signed as the are never negative
expectedSigned(0x2, isnot).
expectedSigned(0x3, isnot).
             
