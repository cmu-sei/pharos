% test to evaluate pointerness with an opUextend. In this example, we
% expect the following results
%
% treeNode(0x1) is NOT a pointer because it is used in a UEXTEND fact
% treeNode(0x2) is NOT a pointer because it is used in a UEXTEND fact
% treeNode(0x3) is not a pointer because it is used in a UEXTEND fact

opUextend(0x1, 0x2, 0x3).
 
% the expected results
expectedPointer(0x1, isnot).
expectedPointer(0x2, isnot).
expectedPointer(0x3, isnot).

bitwidth(0x1, 0x20).
bitwidth(0x2, 0x20).
bitwidth(0x3, 0x20).

expectedSigned(0x1, isnot).
