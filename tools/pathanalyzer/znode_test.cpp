// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/defuse.hpp>
#include <gtest/gtest.h>
#include <libpharos/znode.hpp>

using namespace pharos;

class Z3TreeNodeTestFixture : public ::testing::Test {
 public:
  Z3TreeNodeTestFixture() { /* Nothing to do here*/ }
  virtual ~Z3TreeNodeTestFixture() { /* Nothing to do here*/ }
  virtual void SetUp() { /*/ No setup needed */ }
  virtual void TearDown() { /* No teardown needed*/ }
};

// Simple integer treenode
TEST_F(Z3TreeNodeTestFixture, TEST_INT) {

  TreeNodePtr tn = SymbolicExpr::makeIntegerConstant(32, 0x42);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  // declared here to avoid strange type warnings
  ASSERT_EQ(*result->toUnsigned(), static_cast<uint64_t>(0x42));
}

// Disabled until the possible bug in ROSE is explored
TEST_F(Z3TreeNodeTestFixture, TEST_BITVECTOR_CONSTANT) {

  // 0x000000000000000000000042[96]
  auto bv = Sawyer::Container::BitVector(96);
  bv.fromInteger(uint64_t(0x42));
  bv.signExtend(bv.hull(),
                Sawyer::Container::BitVector::BitRange::baseSize(0, 96));
  TreeNodePtr tn = SymbolicExpr::makeIntegerConstant(bv);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e << LEND;
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));

}

TEST_F(Z3TreeNodeTestFixture, TEST_VAR) {
  TreeNodePtr tn = SymbolicExpr::makeIntegerVariable(32, "tn1");

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original true treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

// Boolean treenode, which is really an integer
TEST_F(Z3TreeNodeTestFixture, TEST_BOOL) {

  TreeNodePtr true_tn = SymbolicExpr::makeBooleanConstant(true);
  TreeNodePtr false_tn = SymbolicExpr::makeBooleanConstant(false);

  PharosZ3Solver z3;

  z3::expr true_e = z3.treenode_to_z3(true_tn);
  z3::expr false_e = z3.treenode_to_z3(false_tn);
  TreeNodePtr true_result = z3.z3_to_treenode(true_e);
  TreeNodePtr false_result = z3.z3_to_treenode(false_e);

  OINFO << "Original true treendode: " << *true_tn
        << ", z3::expr: " << true_e
        << ", Result treenode: " << *true_result << LEND;

  OINFO << "Original false treendode: " << *false_tn
        << ", z3::expr: " << false_e
        << ", Result treenode: " << *false_result << LEND;

  uint64_t expected_true = 1;
  uint64_t expected_false = 0;
  // Booleans are 1-bit integers
  ASSERT_EQ(*true_result->toUnsigned(), expected_true);
  ASSERT_EQ(*false_result->toUnsigned(), expected_false);
}

// (and[32] t1[32] t2[32])
TEST_F(Z3TreeNodeTestFixture, TEST_AND) {

  TreeNodePtr tn = SymbolicExpr::makeAnd(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                         SymbolicExpr::makeIntegerVariable(32, "tn2"));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_COMPOSED_AND) {

  TreeNodePtr tn1 = SymbolicExpr::makeIntegerVariable(32, "tn1");
  TreeNodePtr tn2 = SymbolicExpr::makeIntegerVariable(32, "tn2");
  TreeNodePtr tn3 = SymbolicExpr::makeIntegerVariable(32, "tn3");
  TreeNodePtr tn = SymbolicExpr::makeAnd(tn3, SymbolicExpr::makeAnd(tn1, tn2));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_DEEP_COMPOSED) {

  TreeNodePtr tn1 = SymbolicExpr::makeIntegerVariable(32, "tn1");
  TreeNodePtr tn2 = SymbolicExpr::makeIntegerVariable(32, "tn2");
  TreeNodePtr tn3 = SymbolicExpr::makeIntegerVariable(32, "tn3");
  TreeNodePtr tn4 = SymbolicExpr::makeIntegerVariable(32, "tn4");
  TreeNodePtr tn = SymbolicExpr::makeAnd(tn3,
                                         SymbolicExpr::makeAnd(tn1,
                                                               SymbolicExpr::makeOr(tn2, tn4)));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

// (and[32] t1[32] t2[32])
TEST_F(Z3TreeNodeTestFixture, TEST_OR) {

  TreeNodePtr tn1 = SymbolicExpr::makeIntegerVariable(32, "tn1");
  TreeNodePtr tn2 = SymbolicExpr::makeIntegerVariable(32, "tn2");
  TreeNodePtr tn = SymbolicExpr::makeOr(tn1, tn2);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

// address not part of condition
TEST_F(Z3TreeNodeTestFixture, TEST_COMPOSED_OR) {

  TreeNodePtr tn1 = SymbolicExpr::makeIntegerVariable(32, "tn1");
  TreeNodePtr tn2 = SymbolicExpr::makeIntegerVariable(32, "tn2");
  TreeNodePtr tn3 = SymbolicExpr::makeIntegerVariable(32, "tn3");
  TreeNodePtr tn = SymbolicExpr::makeOr(tn3, SymbolicExpr::makeOr(tn1, tn2));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_EQ) {

  TreeNodePtr tn = SymbolicExpr::makeEq(SymbolicExpr::makeIntegerVariable(32, "tn1"), SymbolicExpr::makeIntegerVariable(32, "tn2"));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

// Test for not equal, which corresponds to Z3's distinct
TEST_F(Z3TreeNodeTestFixture, TEST_NE) {

  TreeNodePtr tn = SymbolicExpr::makeNe(SymbolicExpr::makeIntegerVariable(32, "tn1"), SymbolicExpr::makeIntegerVariable(32, "tn2"));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

// Test for negation
TEST_F(Z3TreeNodeTestFixture, TEST_NEGATE) {

  TreeNodePtr tn = SymbolicExpr::makeNegate(SymbolicExpr::makeIntegerVariable(32, "tn1"));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

// Test OP_READ
TEST_F(Z3TreeNodeTestFixture, TEST_READ) {

  // make some dummy memory for the sake of the test
  TreeNodePtr tn = SymbolicExpr::makeRead(SymbolicExpr::makeMemoryVariable(32, 32),
                                          SymbolicExpr::makeIntegerVariable(32, "tn2"));

  PharosZ3Solver z3;
  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_ADD_VAR) {

  TreeNodePtr tn = SymbolicExpr::makeAdd(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                         SymbolicExpr::makeIntegerVariable(32, "tn2"));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_ADD_INT) {

  TreeNodePtr tn = SymbolicExpr::makeAdd(
    SymbolicExpr::makeIntegerConstant(32, 2), SymbolicExpr::makeIntegerConstant(32, 3));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_EQ(*result->toUnsigned(), static_cast<uint64_t>(5));
  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_ASR) {

  TreeNodePtr tn = SymbolicExpr::makeAsr(SymbolicExpr::makeIntegerConstant(32, 3),
                                         SymbolicExpr::makeIntegerVariable(32, "tn1"));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_XOR_VAR) {

  TreeNodePtr tn = SymbolicExpr::makeXor(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                         SymbolicExpr::makeIntegerVariable(32, "tn2"));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_XOR_INT) {

  TreeNodePtr tn = SymbolicExpr::makeXor(
    SymbolicExpr::makeIntegerConstant(32, 2),
    SymbolicExpr::makeIntegerConstant(32, 3)); // should be 1 :)
  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_EQ(*result->toUnsigned(), static_cast<uint64_t>(1));
  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_CONCAT) {

  TreeNodePtr tn = SymbolicExpr::makeConcat(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                            SymbolicExpr::makeIntegerVariable(32, "tn2"));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_EXTRACT) {

  auto lo = SymbolicExpr::makeIntegerConstant(32, 0);
  auto hi = SymbolicExpr::makeIntegerConstant(32, 8);
  TreeNodePtr tn = SymbolicExpr::makeExtract(
    lo, hi, SymbolicExpr::makeIntegerVariable(32, "tn1"));
  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);

  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_EQ(*lo->toUnsigned(), static_cast<uint64_t>(e.lo()));
  // Z3/smtlib is inclusive, ROSE is not
  ASSERT_EQ(*hi->toUnsigned(), static_cast<uint64_t>(e.hi()+1));

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

// Test for ZEROP Risc OP.
TEST_F(Z3TreeNodeTestFixture, TEST_ZEROP) {

  TreeNodePtr tn1 = SymbolicExpr::makeIntegerVariable(32, "tn1");
  TreeNodePtr tn = SymbolicExpr::makeZerop(tn1);

  // When converted to a z3 expression, ZEROP operations seem to become (= v43 #x00000000),
  // which then become OP_EQ when they are exported
  TreeNodePtr tn_eq_zero = SymbolicExpr::makeEq(
    tn1, SymbolicExpr::makeIntegerConstant(tn1->nBits(), 0));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original (equals) treendode: " << *tn_eq_zero
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn_eq_zero));
}

// Test an ITE
TEST_F(Z3TreeNodeTestFixture, TEST_ITE) {

  TreeNodePtr zero = SymbolicExpr::makeIntegerConstant(32, 0);
  TreeNodePtr cond = SymbolicExpr::makeEq(SymbolicExpr::makeIntegerVariable(32), zero);
  TreeNodePtr true_branch = SymbolicExpr::makeIntegerConstant(32, 0x1234);
  TreeNodePtr false_branch = SymbolicExpr::makeIntegerConstant(32, 0x4567);
  TreeNodePtr original_ite = InternalNode::instance(SymbolicExpr::OP_ITE, cond, true_branch, false_branch);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(original_ite);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *original_ite
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(original_ite));
}

TEST_F(Z3TreeNodeTestFixture, TEST_ROL) {

  TreeNodePtr sa = SymbolicExpr::makeIntegerConstant(32, 3);
  TreeNodePtr expr = SymbolicExpr::makeIntegerVariable(32, "tn");
  TreeNodePtr tn = SymbolicExpr::makeRol(sa, expr);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);

  // The ROL treenode is translated in a slightly convoluted way: rol becomes ((_ extract 63
  // 32) (bvshl (concat v1 v1) #x0000000000000003)) So, assuming this is right, the following
  // treenode is the "expected" result

  size_t w = expr->nBits();
  TreeNodePtr rol_tn = SymbolicExpr::makeExtract(
    SymbolicExpr::makeIntegerConstant(32, w),
    SymbolicExpr::makeIntegerConstant(32, 2*w),
    makeShl0(SymbolicExpr::makeConcat(expr, expr),
             SymbolicExpr::makeExtend(SymbolicExpr::makeIntegerConstant(32, 2*w), sa)));

  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Expected conversion: " << *rol_tn
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(rol_tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_ROR) {

  TreeNodePtr sa = SymbolicExpr::makeIntegerConstant(32, 3);
  TreeNodePtr expr = SymbolicExpr::makeIntegerVariable(32, "tn");
  TreeNodePtr tn = SymbolicExpr::makeRor(sa, expr);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);

  // The ROR treenode is translated in a slightly convoluted way:
  // Original treendode: (ror[32] 0x00000003[32] tn[32])
  // z3::expr: ((_ extract 31 0) (bvlshr (concat v1 v1) #x0000000000000003))
  // Expected conversion: (extract[32] 0x00000000[32] 0x00000020[32] (shr0[64] (concat[64] tn[32] tn[32]) 0x0000000000000003[64]))

  size_t w = expr->nBits();
  TreeNodePtr ror_tn = SymbolicExpr::makeExtract(
    SymbolicExpr::makeIntegerConstant(32, 0),
    SymbolicExpr::makeIntegerConstant(32, w),
    makeShr0(SymbolicExpr::makeConcat(expr, expr),
             SymbolicExpr::makeExtend(SymbolicExpr::makeIntegerConstant(32, 2*w), sa)));

  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Expected conversion: " << *ror_tn
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(ror_tn));
}

TEST_F(Z3TreeNodeTestFixture, DISABLED_TEST_OP_SET) {
  // IDK how to test this one effectively without API changes. It seems to work
}

TEST_F(Z3TreeNodeTestFixture, DISABLED_TEST_OP_SEXTEND) {
  // Not sure how to test this given the conversion
}

TEST_F(Z3TreeNodeTestFixture, DISABLED_TEST_OP_UEXTEND) {
  // Not sure how to test this given the conversion
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_ULT) {

  TreeNodePtr tn = SymbolicExpr::makeLt(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                        SymbolicExpr::makeIntegerConstant(32, 42));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_SLT) {

  TreeNodePtr tn = SymbolicExpr::makeSignedLt(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                              SymbolicExpr::makeIntegerConstant(32, 42));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_SLEQ) {

  TreeNodePtr tn = SymbolicExpr::makeSignedLe(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                              SymbolicExpr::makeIntegerConstant(32, 42));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_UGT) {

  TreeNodePtr tn = SymbolicExpr::makeGt(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                        SymbolicExpr::makeIntegerConstant(32, 42));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_SGT) {

  TreeNodePtr tn = SymbolicExpr::makeSignedGt(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                              SymbolicExpr::makeIntegerConstant(32, 42));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_SGE) {

  TreeNodePtr tn = SymbolicExpr::makeSignedGe(SymbolicExpr::makeIntegerVariable(32, "tn1"),
                                              SymbolicExpr::makeIntegerConstant(32, 42));

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_SHL0) {

  TreeNodePtr sa = SymbolicExpr::makeIntegerConstant(32, 3);
  TreeNodePtr expr = SymbolicExpr::makeIntegerVariable(32, "tn");
  TreeNodePtr tn = SymbolicExpr::makeShl0(sa, expr);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}



TEST_F(Z3TreeNodeTestFixture, TEST_OP_SHL1) {

  TreeNodePtr sa = SymbolicExpr::makeIntegerConstant(32, 3);
  TreeNodePtr expr = SymbolicExpr::makeIntegerVariable(32, "tn");
  TreeNodePtr tn = SymbolicExpr::makeShl1(sa, expr);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_SHR0) {

  TreeNodePtr sa = SymbolicExpr::makeIntegerConstant(32, 3);
  TreeNodePtr expr = SymbolicExpr::makeIntegerVariable(32, "tn");
  TreeNodePtr tn = SymbolicExpr::makeShr0(sa, expr);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_OP_SHR1) {

  TreeNodePtr sa = SymbolicExpr::makeIntegerConstant(32, 3);
  TreeNodePtr expr = SymbolicExpr::makeIntegerVariable(32, "tn");
  TreeNodePtr tn = SymbolicExpr::makeShr1(sa, expr);

  PharosZ3Solver z3;

  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e);

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(tn));
}

TEST_F(Z3TreeNodeTestFixture, TEST_COMPLEX_SIMPLIFY) {

  // (and[1]
  //  (eq[1] A[32] 259[32])
  //  (eq[1] B[32] 1000[32])
  //  (invert[1] (eq[1] B[32] 0[32])))
  //
  // This is really "A==259 && B==1000 && !(B==0)" ... the !B==0 clause can be eliminated

  auto B = SymbolicExpr::makeIntegerVariable(32, "B");
  auto A = SymbolicExpr::makeIntegerVariable(32, "A");
  TreeNodePtr tn = SymbolicExpr::makeAnd(
    SymbolicExpr::makeEq(A, SymbolicExpr::makeIntegerConstant(32, 259)),
    SymbolicExpr::makeEq(B, SymbolicExpr::makeIntegerConstant(32, 1000)));
  tn = SymbolicExpr::makeAnd(
    tn, SymbolicExpr::makeInvert(
      SymbolicExpr::makeEq(B, SymbolicExpr::makeIntegerConstant(32, 0))));

  // the expected treenode has no !B==0 clause
  TreeNodePtr uber_simple_tn = SymbolicExpr::makeAnd(
    SymbolicExpr::makeEq(A, SymbolicExpr::makeIntegerConstant(32, 259)),
    SymbolicExpr::makeEq(B, SymbolicExpr::makeIntegerConstant(32, 1000)));

  PharosZ3Solver z3;
  z3::expr e = z3.treenode_to_z3(tn);
  z3::expr e0 = z3.simplify(e);
  TreeNodePtr result = z3.z3_to_treenode(e0);

  OINFO << "Original treendode: " << *tn << LEND;
  OINFO << "Original z3::expr: " << e << LEND;
  OINFO << "Uber-simpified expr: " << e0 << LEND;
  OINFO << "Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(uber_simple_tn));
}

// test simplifier for A && !A
TEST_F(Z3TreeNodeTestFixture, TEST_EASY_SIMPLIFY) {

  TreeNodePtr A = SymbolicExpr::makeIntegerVariable(1, "A");
  TreeNodePtr NotA = SymbolicExpr::makeInvert(A);
  TreeNodePtr tn = SymbolicExpr::makeAnd(A, NotA);

  TreeNodePtr false_tn = SymbolicExpr::makeBooleanConstant(false);

  PharosZ3Solver z3;
  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e.simplify());

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(false_tn));
}

// test simplifier for A && !A
TEST_F(Z3TreeNodeTestFixture, TEST_SPACER) {

  TreeNodePtr A = SymbolicExpr::makeIntegerVariable(1, "A");
  TreeNodePtr NotA = SymbolicExpr::makeInvert(A);
  TreeNodePtr tn = SymbolicExpr::makeAnd(A, NotA);

  TreeNodePtr false_tn = SymbolicExpr::makeBooleanConstant(false);

  PharosZ3Solver z3;
  z3::expr e = z3.treenode_to_z3(tn);
  TreeNodePtr result = z3.z3_to_treenode(e.simplify());

  OINFO << "Original treendode: " << *tn
        << ", z3::expr: " << e
        << ", Result treenode: " << *result << LEND;

  ASSERT_TRUE(result->isEquivalentTo(false_tn));
}

// Driver for the program
static int z3treenode_test_main(int argc, char **argv) {
  olog.initialize("OINFO");
  ::testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}

int main(int argc, char **argv) {

  return pharos_main("ZNODE", z3treenode_test_main, argc, argv, STDERR_FILENO);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
