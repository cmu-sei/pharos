// Copyright 2015-2023 Carnegie Mellon University.  See LICENSE file for terms.

#include <libpharos/defuse.hpp>
#include <gtest/gtest.h>

using namespace pharos;
using namespace Rose::BinaryAnalysis::SymbolicExpression;

class MergeTestFixture : public ::testing::Test {
 protected:
  TreeNodePtr nullnode;
 public:
  MergeTestFixture() {
    nullnode = TreeNodePtr();
  }
  virtual ~MergeTestFixture() { /* Nothing to do here*/ }
  virtual void SetUp() { /*/ No setup needed */ }
  virtual void TearDown() { /* No teardown needed*/ }
};

// address not part of condition
TEST_F(MergeTestFixture, TEST_MERGE_MISSING_ADDR) {

  TreeNodePtr zero = SymbolicExpr::makeIntegerConstant(32, 0);
  TreeNodePtr C1 = makeEq(SymbolicExpr::makeIntegerVariable(32), zero);
  TreeNodePtr T1 = SymbolicExpr::makeIntegerConstant(32, 0x1234);
  TreeNodePtr F1 = SymbolicExpr::makeIntegerConstant(32, 0x4567);
  TreeNodePtr ITE1 = InternalNode::instance(OP_ITE, C1, T1, F1);
  SymbolicValuePtr ITE_sv = SymbolicValue::treenode_instance(ITE1);

  OINFO << "Full ITE: " << *ITE1 << LEND;
  TreeNodePtr leaf = SymbolicExpr::makeIntegerConstant(32, 0xABCD);
  SymbolicValuePtr result = get_leaf_condition(ITE_sv, leaf, nullnode);
  SymbolicValuePtr expected_sv = SymbolicValue::incomplete(1);

  OINFO << "Condition: " << *result->get_expression() << LEND;

  // ASSERT_FALSE(retval);
  ASSERT_TRUE(result->is_incomplete());
}

// (ITE C1 T1 F1), T1 -> C1
TEST_F(MergeTestFixture, TEST_MERGE_TRUE_ADDR) {

  TreeNodePtr zero = SymbolicExpr::makeIntegerConstant(32, 0);
  TreeNodePtr C1 = makeEq(SymbolicExpr::makeIntegerVariable(32), zero);
  TreeNodePtr T1 = SymbolicExpr::makeIntegerConstant(32,0x1234);
  TreeNodePtr F1 = SymbolicExpr::makeIntegerConstant(32, 0x4567);
  TreeNodePtr ITE1 = InternalNode::instance(OP_ITE, C1, T1, F1);
  SymbolicValuePtr ITE_sv = SymbolicValue::treenode_instance(ITE1);

  OINFO << "Full ITE: " << *ITE1 << LEND;

  // (ITE C1 T1 F1), T1 -> C1
  SymbolicValuePtr result = get_leaf_condition(ITE_sv, T1, nullnode);
  // get_leaf_condition(ITE_sv, addr, condition_list, result);

  SymbolicValuePtr C1_sv = SymbolicValue::treenode_instance(C1);
  OINFO << "Condition: " << *result->get_expression() << LEND;

  ASSERT_TRUE(result->can_be_equal(C1_sv));
}

// (ITE C1 T1 F1), F1 -> !C1
TEST_F(MergeTestFixture, TEST_MERGE_FALSE_ADDR) {

  TreeNodePtr zero = SymbolicExpr::makeIntegerConstant(32, 0);
  TreeNodePtr C1 = makeEq(SymbolicExpr::makeIntegerVariable(32), zero);
  TreeNodePtr T1 = SymbolicExpr::makeIntegerConstant(32,0x1234);
  TreeNodePtr F1 = SymbolicExpr::makeIntegerConstant(32, 0x4567);
  TreeNodePtr ITE1 = InternalNode::instance(OP_ITE, C1, T1, F1);
  SymbolicValuePtr ITE_sv = SymbolicValue::treenode_instance(ITE1);

  OINFO << "Full ITE: " << *ITE1 << LEND;

  // (ITE C1 T1 F1), F1 -> !C1
  SymbolicValuePtr result  = get_leaf_condition(ITE_sv, F1, nullnode);
  SymbolicValuePtr not_C1_sv = SymbolicValue::treenode_instance(makeInvert(C1));
  OINFO << "Condition: " << *result->get_expression() << LEND;

  ASSERT_TRUE(result->can_be_equal(not_C1_sv));
}

// (ITE C1 (ITE C2 T2 F2) F1): T2 -> C1 & C2
TEST_F(MergeTestFixture, TEST_MERGE_COMPLEX_T2) {

  TreeNodePtr zero = SymbolicExpr::makeIntegerConstant(32, 0);
  TreeNodePtr one = SymbolicExpr::makeIntegerConstant(32, 1);

  TreeNodePtr C1 = makeEq(SymbolicExpr::makeIntegerVariable(32), zero);
  TreeNodePtr F1 = SymbolicExpr::makeIntegerConstant(32, 0x1234);
  TreeNodePtr C2 = makeEq(SymbolicExpr::makeIntegerVariable(32), one);

  TreeNodePtr T2 = SymbolicExpr::makeIntegerConstant(32,0x2468);
  TreeNodePtr F2 = SymbolicExpr::makeIntegerConstant(32,0x369C);
  TreeNodePtr ITE2 = InternalNode::instance(OP_ITE, C2, T2, F2);

  TreeNodePtr ITE1 = InternalNode::instance(OP_ITE, C1, ITE2, F1);
  SymbolicValuePtr ITE_sv = SymbolicValue::treenode_instance(ITE1);
  SymbolicValuePtr result = get_leaf_condition(ITE_sv, T2, nullnode);

  // expected: C1 && C2
  SymbolicValuePtr expected_sv = SymbolicValue::treenode_instance(makeAnd(C1, C2));

  OINFO << "Full ITE: " << *ITE1 << LEND;
  OINFO << "Condition: " << *result->get_expression() << LEND;

  ASSERT_TRUE(result->can_be_equal(expected_sv));
}

// (ITE C1 (ITE C2 T2 F2) F1): F2 -> C1 & !C2
TEST_F(MergeTestFixture, TEST_MERGE_COMPLEX_F2) {

  TreeNodePtr zero = SymbolicExpr::makeIntegerConstant(32, 0);
  TreeNodePtr one = SymbolicExpr::makeIntegerConstant(32, 1);

  TreeNodePtr C1 = makeEq(SymbolicExpr::makeIntegerVariable(32), zero);
  TreeNodePtr F1 = SymbolicExpr::makeIntegerConstant(32, 0x1234);
  TreeNodePtr C2 = makeEq(SymbolicExpr::makeIntegerVariable(32), one);

  TreeNodePtr T2 = SymbolicExpr::makeIntegerConstant(32,0x2468);
  TreeNodePtr F2 = SymbolicExpr::makeIntegerConstant(32,0x369C);
  TreeNodePtr ITE2 = InternalNode::instance(OP_ITE, C2, T2, F2);

  TreeNodePtr ITE1 = InternalNode::instance(OP_ITE, C1, ITE2, F1);

  SymbolicValuePtr ITE_sv = SymbolicValue::treenode_instance(ITE1);
  SymbolicValuePtr result  = get_leaf_condition(ITE_sv, F2, nullnode);

  // expected: C1 && !C2
  SymbolicValuePtr expected_sv = SymbolicValue::treenode_instance(makeAnd(C1, makeInvert(C2)));

  OINFO << "Full ITE: " << *ITE1 << LEND;
  OINFO << "Condition: " << *result->get_expression() << LEND;

  ASSERT_TRUE(result->can_be_equal(expected_sv));
}

// (ITE C1 (ITE C2 T2 F2) F1): F1 -> !C1
TEST_F(MergeTestFixture, TEST_MERGE_COMPLEX_F1) {

  TreeNodePtr zero = SymbolicExpr::makeIntegerConstant(32, 0);
  TreeNodePtr one = SymbolicExpr::makeIntegerConstant(32, 1);

  TreeNodePtr C1 = makeEq(SymbolicExpr::makeIntegerVariable(32), zero);
  TreeNodePtr F1 = SymbolicExpr::makeIntegerConstant(32, 0x1234);
  TreeNodePtr C2 = makeEq(SymbolicExpr::makeIntegerVariable(32), one);

  TreeNodePtr T2 = SymbolicExpr::makeIntegerConstant(32,0x2468);
  TreeNodePtr F2 = SymbolicExpr::makeIntegerConstant(32,0x369C);
  TreeNodePtr ITE2 = InternalNode::instance(OP_ITE, C2, T2, F2);

  TreeNodePtr ITE1 = InternalNode::instance(OP_ITE, C1, ITE2, F1);

  SymbolicValuePtr ITE_sv = SymbolicValue::treenode_instance(ITE1);
  SymbolicValuePtr result = get_leaf_condition(ITE_sv, F1, nullnode);

  // expected: !C1
  SymbolicValuePtr expected_sv = SymbolicValue::treenode_instance(makeInvert(C1));

  OINFO << "Full ITE: " << *ITE1 << LEND;
  OINFO << "Condition: " << *result->get_expression() << LEND;

  ASSERT_TRUE(result->can_be_equal(expected_sv));
}


// (ITE C1 (ITE C2 T2 (ITE C3 T3 F3)) F1): F3 -> C1 & !C2 & !C3
TEST_F(MergeTestFixture, TEST_MERGE_THRICE_NESTED_ITE_F3) {
  TreeNodePtr zero = SymbolicExpr::makeIntegerConstant(32, 0);
  TreeNodePtr one = SymbolicExpr::makeIntegerConstant(32, 1);
  TreeNodePtr two = SymbolicExpr::makeIntegerConstant(32, 2);

  TreeNodePtr C1 = makeEq(SymbolicExpr::makeIntegerVariable(32), zero);
  TreeNodePtr F1 = SymbolicExpr::makeIntegerConstant(32, 0x1234);

  TreeNodePtr C2 = makeEq(SymbolicExpr::makeIntegerVariable(32), one);
  TreeNodePtr T2 = SymbolicExpr::makeIntegerConstant(32,0x2468);

  TreeNodePtr T3 = SymbolicExpr::makeIntegerConstant(32,0xABCD);
  TreeNodePtr F3 = SymbolicExpr::makeIntegerConstant(32,0xEF01); // target!
  TreeNodePtr C3 = makeEq(SymbolicExpr::makeIntegerVariable(32), two);

  TreeNodePtr ITE3 = InternalNode::instance(OP_ITE, C3, T3, F3);
  TreeNodePtr ITE2 = InternalNode::instance(OP_ITE, C2, T2, ITE3);
  TreeNodePtr ITE1 = InternalNode::instance(OP_ITE, C1, ITE2, F1);
  SymbolicValuePtr ITE_sv = SymbolicValue::treenode_instance(ITE1);

  SymbolicValuePtr result = get_leaf_condition(ITE_sv, F3, nullnode);

  // expected: !C1

  SymbolicValuePtr expected_sv = SymbolicValue::treenode_instance(makeAnd(C1, makeAnd(makeInvert(C3), makeInvert(C2))));

  OINFO << "Full ITE: " << *ITE1 << LEND;
  OINFO << "Condition: " << *result->get_expression() << LEND;
  OINFO << "Expected: " << *expected_sv->get_expression() << LEND;

  ASSERT_TRUE(result->can_be_equal(expected_sv));
}

static int merge_test_main(int argc, char **argv) {
  olog.initialize("OINFO");
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

int main(int argc, char **argv) {
  return pharos_main("MEGTEST", merge_test_main, argc, argv, STDERR_FILENO);
}

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
