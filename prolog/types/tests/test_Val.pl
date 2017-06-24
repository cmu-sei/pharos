% this 32b value is signed
value(0x1), 0xffffffff).
bitwidth(0x1), 0x20).

%% % this 32b value is unsigned
value(0x1a), 0x7fffffff).
bitwidth(0x1a), 0x20).

%% % this 32b value is unsigned
value(0x1b), 0xff).
bitwidth(0x1b), 0x20).

%% % ====================================================================

% this 64b value is signed
value(0x2), 0xFFFFFFFFFFFFFFFF).
bitwidth(0x2), 0x40).

% This 64b value is unsigned
value(0x2a), 0x10).
bitwidth(0x2a), 0x40).

%% % This 64b value is unsigned
value(0x2b), 0x7fffffffffffffff).
bitwidth(0x2b), 0x40).

%% % ====================================================================

%% % This 16b value is signed
value(0x3), 0xff00).
bitwidth(0x3), 0x10).

%% % This 16b value is unsigned
value(0x3a), 0x1fff).
bitwidth(0x3a), 0x10).

%% % This 16b value is unsigned
value(0x3b), 0xff).
bitwidth(0x3b), 0x10).

%% % ====================================================================

%% % This 8b value is signed
value(0x4), 0xff).
bitwidth(0x4), 0x8).

%% % This 8b value is unsigned
value(0x4a), 0x1f).
bitwidth(0x4a), 0x8).

%% % This 8b value is unsigned
value(0x4b, 0x4).
bitwidth(0x4b, 0x8).

%% % ====================================================================

%% % 1bit wide treenodes are not pointers
bitwidth(0x7 ,0x1).

pointer(0x8, is). % should be unsigned

signed(0x9, is).

% Expected results

expectedSigned(0x1, is).
expectedSigned(0x1a, isnot).
expectedSigned(0x1b, isnot).

expectedSigned(0x2, is).
expectedSigned(0x2a, isnot).
expectedSigned(0x2b, isnot).

expectedSigned(0x3, is).
expectedSigned(0x3a, isnot).
expectedSigned(0x3b, isnot).

expectedSigned(0x4, is).
expectedSigned(0x4a, isnot).
expectedSigned(0x4b, isnot).

expectedSigned(0x7, isnot). % 1b wide treeNodes are not signed
expectedSigned(0x8, isnot).
