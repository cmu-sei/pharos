% test to evaluate pointerness with a memaddr. In this example, we
% expect the following results
% 0x1) is identified as a memaddr so it is a pointer

memaddr(0x1). % indicate 0x1) is a pointer
bitwidth(0x1,0x20). % pointers are 32 or 64 bits

expectedPointer(0x1, is).
expectedSigned(0x1, isnot).

bitwidth(0x2,0x21). % pointers are 32 or 64 bits

expectedPointer(0x2, isnot).

memaddr(0x3). % indicate 0x2) is a pointer
value(0x3, 42).       % conflicting information == bottom
bitwidth(0x3, 0x20).

expectedPointer(0x3, bottom).
expectedSigned(0x3, isnot).
