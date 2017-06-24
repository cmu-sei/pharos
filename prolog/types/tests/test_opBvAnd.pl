% test to evaluate pointerness with an opBvAnd. In this example, we
% expect the following results

% 0x1) is NOT a pointer because it is used in an AND without the align value

opBvAnd(0x1, [0x2, 0x3]).

% test the stack pointer exception
% 0x6) is a pointer because 0x4) has the value of 0xfffffff0
value(0x4, 0xfffffff0).
bitwidth(0x4, 0x20).
opBvAnd(0x6, [0x5, 0x4]).

value(0x7, 0xffffffff).
bitwidth(0x7, 0x20).
opBvAnd(0x9, [0x8, 0x7]).

bitwidth(0x6, 0x20).
bitwidth(0x7, 0x20).
bitwidth(0x1, 0x20).
bitwidth(0x4, 0x20).
bitwidth(0x6, 0x20).
bitwidth(0x9, 0x20).

expectedPointer(0x6, is).
expectedPointer(0x7, isnot).
expectedPointer(0x1, isnot).
expectedPointer(0x4, isnot).

expectedPointer(0x6, is).
expectedPointer(0x9, isnot).

expectedSigned(0x4, is).
expectedSigned(0x7, is).
expectedSigned(0x6, isnot). % because it is a pointer

