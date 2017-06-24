% test to evaluate pointerness with an opEq. In this example, we
% expect the following results
% treeNode(0x2) is NOT a pointer because it is used in an INVERT fact


opInvert(0x1, 0x2).

expectedPointer(0x2,isnot).
