// Copyright 2015-2018 Carnegie Mellon University.  See LICENSE file for terms.

#include <stdio.h>
#include <iostream>
#include <time.h>

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_utility.hpp>
#include <boost/graph/depth_first_search.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/connected_components.hpp>
#include <boost/foreach.hpp>

// Must be before "stat.h", which is included by "gtest.h"
#include <rose.h>

#include <gtest/gtest.h>

#include <libpharos/pdg.hpp>
#include <libpharos/misc.hpp>
#include <libpharos/descriptors.hpp>
#include <libpharos/masm.hpp>
#include <libpharos/defuse.hpp>
#include <libpharos/sptrack.hpp>
#include <libpharos/options.hpp>

#include <libpharos/apigraph.hpp>
#include <libpharos/apisig.hpp>

using namespace pharos;

Sawyer::Message::Facility glog("APIT");

// Thisis the main test fixture
class ApiAnalyzerTest : public testing::Test {

protected:

  ApiGraph api_graph_;
  std::vector<rose_addr_t> component_list_;

  ApiAnalyzerTest() {

    component_list_.push_back(0x00401000);
    component_list_.push_back(0x00401250);
    component_list_.push_back(0x00401300);
    component_list_.push_back(0x00401550);
    component_list_.push_back(0x00401580);
    component_list_.push_back(0x004017F0);
    component_list_.push_back(0x0040182D);

    // These components no longer exist in partitioner2
    //component_list_.push_back(0x00401A01);
    //component_list_.push_back(0x00401A15);
    //component_list_.push_back(0x00401A31);
    //component_list_.push_back(0x00401A51);
    //component_list_.push_back(0x00401D3E);
    //component_list_.push_back(0x00401D64);
    // end functions to remove in the partitioner2

    component_list_.push_back(0x00401B0B);
    component_list_.push_back(0x00401B15);
    component_list_.push_back(0x00401C1B);
    component_list_.push_back(0x00401C72);
    component_list_.push_back(0x00401D0A);
    component_list_.push_back(0x00401D13);

    component_list_.push_back(0x00401F39);

    // component_list_.push_back(0x00401F5E); // this is incorrectly reported as 0x00401F60

    component_list_.push_back(0x00401F89);
  }

  virtual void SetUp() {
    // Code here will be called immediately after the constructor (right
    // before each test).
    api_graph_.Build();
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test (right
    // before the destructor).
    api_graph_.Reset();
  }
};

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerTest, TestGraphViz) {
  std::string gv_file = "apitests.dot";
  std::ofstream graphviz_file(gv_file.c_str());
  api_graph_.GenerateGraphViz(graphviz_file);
}

// these are tests that concern the ApiCfgComponent class
class ApiAnalyzerApiCfgComponentTest : public ApiAnalyzerTest { };

// tests around graph construction

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_ALL_COMPONENTS_HAVE_ENTRY) {

  api_graph_.Print();


  BOOST_FOREACH(std::vector<rose_addr_t>::value_type caddr, component_list_) {
    ApiCfgComponentPtr c = api_graph_.GetComponent(caddr);

    if (c == NULL) {
      FAIL() << "Failing test: Cannot find component " << addr_str(caddr);
      return;
    }

    EXPECT_TRUE(c!=NULL) << "Could not find component " << std::hex << caddr << std::endl;
  }
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_EXIT_CORRECT) {
  rose_addr_t exitea = 0x0040123D;
  ApiCfgComponentPtr ci = api_graph_.GetComponent(0x00401000);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000";
    return;
  }

  EXPECT_EQ(exitea, ci->GetExitAddr());
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_ENTRY_CORRECT) {
  rose_addr_t r = 0x00401000;
  ApiCfgComponentPtr ci = api_graph_.GetComponent(r);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component " << addr_str(r);
    return;
  }
  EXPECT_EQ(r, ci->GetEntryAddr());
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_API_CALLS_CORRECTLY_IDENTIFIED) {
  rose_addr_t r = 0x00401000;
  rose_addr_t callea = 0x0040105C;

  ApiCfgComponentPtr ci = api_graph_.GetComponent(r);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component " << addr_str(r);
    return;
  }

  ApiCfg *cfg = ci->GetCfg();
  ApiCfgVertex callv = ci->GetVertexByAddr(callea);

  ApiVertexInfo &vertex_info = (*cfg)[callv];

  EXPECT_EQ(vertex_info.block->get_address(), callea);

  std::string CreatePipe = "KERNEL32.DLL!CREATEPIPE";
  EXPECT_EQ(CreatePipe, vertex_info.api_name);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_API_CALL_CORRECTLY_IDENTIFIED_AT_ENTRY) {
  rose_addr_t entry_ea = 0x00401250;
  ApiCfgComponentPtr ci = api_graph_.GetComponent(entry_ea);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component " << addr_str(entry_ea);
    return;
  }

  EXPECT_EQ(entry_ea, ci->GetEntryAddr());

  ApiCfgVertex entry_vtx = ci->GetEntryVertex();
  ApiCfg *cfg = ci->GetCfg();
  const ApiVertexInfo& vi = (*cfg)[entry_vtx];

  EXPECT_EQ(vi.GetType(),ApiVertexInfo::API);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_CALL_CORRECTLY_IDENTIFIED_AT_ENTRY) {

  rose_addr_t entry_ea = 0x004017F0;
  ApiCfgComponentPtr ci = api_graph_.GetComponent(entry_ea);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component " << addr_str(entry_ea);
    return;
  }

  EXPECT_EQ(entry_ea, ci->GetEntryAddr());

  ApiCfgVertex entry_vtx = ci->GetEntryVertex();
  ApiCfg *cfg = ci->GetCfg();
  const ApiVertexInfo& vi = (*cfg)[entry_vtx];

  EXPECT_EQ(vi.GetType(),ApiVertexInfo::CALL);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_HANDLE_THUNK_IN_MIDDLE) {

  // check to see if the thunk is part of the graph

  ApiCfgComponentPtr ci = api_graph_.GetComponent(0x00401000);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000";
    return;
  }

  ApiCfg *cfg = ci->GetCfg();
  rose_addr_t memset_ea = 0x0040115F;// 0x00401818; // import address for memset
  ApiCfgVertex memset_vtx = ci->GetVertexByAddr(memset_ea);

  EXPECT_NE(memset_vtx, NULL_VERTEX);

  const ApiVertexInfo& vertex_info = (*cfg)[memset_vtx];

  std::string memset_str = "MSVCR100.DLL!MEMSET";

  EXPECT_EQ(memset_str, vertex_info.api_name);

  EXPECT_EQ(boost::out_degree(memset_vtx,*cfg),ApiCfg::degree_size_type(1));
  std::pair<ApiCfgOutEdgeIter, ApiCfgOutEdgeIter> oei = boost::out_edges(memset_vtx,*cfg);
  ApiCfgEdge tgt_edge = *(oei.first);
  ApiCfgVertex tgt_vtx = boost::target(tgt_edge, *cfg);
  const ApiVertexInfo& tgt_info = (*cfg)[tgt_vtx];

  EXPECT_EQ(boost::in_degree(memset_vtx,*cfg),ApiCfg::degree_size_type(1));
  std::pair<ApiCfgInEdgeIter, ApiCfgInEdgeIter> iei = boost::in_edges(memset_vtx,*cfg);
  ApiCfgEdge src_edge = *(iei.first);
  ApiCfgVertex src_vtx = boost::source(src_edge, *cfg);
  const ApiVertexInfo& src_info = (*cfg)[src_vtx];

  EXPECT_EQ(src_info.block->get_address(),0x0040113Au);
  EXPECT_EQ(tgt_info.block->get_address(),0x0040117Cu);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_HANDLE_THUNK_AT_ENTRY) {
  rose_addr_t entry_ea = 0x00401F5E; // This should really be 0x00401F5E;
  ApiCfgComponentPtr ci = api_graph_.GetComponent(entry_ea);
  if (!ci) {
    FAIL() << "Function 0x00401F5E not found!";
    return;
  }
  ApiCfg *cfg = ci->GetCfg();

  ApiCfgVertex ev = ci->GetEntryVertex();
  const ApiVertexInfo& evi = (*cfg)[ev];

  EXPECT_EQ(evi.GetType(), ApiVertexInfo::API);
  EXPECT_EQ(evi.block->get_address(), entry_ea);
  EXPECT_EQ(evi.block->get_address(),ci->GetEntryAddr());
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_DISCONNECT_ENTRY) {

  rose_addr_t entry_ea = 0x00401000;
  ApiCfgComponentPtr ci = api_graph_.GetComponent(entry_ea);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component " << addr_str(entry_ea);
    return;
  }

  ApiCfg *cfg = ci->GetCfg();

  ApiCfgVertex target =  ci->GetVertexByAddr(entry_ea);

  size_t old_size = boost::num_vertices(*cfg);

  ci->DisconnectVertex(target);

  // disconnecting the entry vertex

  target =  ci->GetVertexByAddr(entry_ea);

  // the previous vertex is now gone and the size is reduced by 1
  EXPECT_EQ(target, NULL_VERTEX);
  EXPECT_EQ(old_size-1, boost::num_vertices(*cfg));
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_DISCONNECT_EXIT) {

  rose_addr_t exit_ea = 0x0040123D, comp_ea = 0x00401000;
  ApiCfgComponentPtr ci = api_graph_.GetComponent(comp_ea);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component " << addr_str(comp_ea);
    return;
  }

  ApiCfg *cfg = ci->GetCfg();

  ApiCfgVertex target = ci->GetVertexByAddr(exit_ea);

  size_t old_size = boost::num_vertices(*cfg);

  ci->DisconnectVertex(target);

  // disconnecting the exit vertex

  target = ci->GetVertexByAddr(exit_ea);

  // the previous vertex is now gone and the size is reduced by 1
  EXPECT_EQ(target, NULL_VERTEX);
  EXPECT_EQ(old_size-1, boost::num_vertices(*cfg));
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_DISCONNECT_MIDDLE) {

  rose_addr_t entry_ea = 0x00401000;
  rose_addr_t blockea = 0x00401115;

  ApiCfgComponentPtr ci = api_graph_.GetComponent(entry_ea);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component " << addr_str(entry_ea);
    return;
  }

  ApiCfg *cfg = ci->GetCfg();

  ApiCfgVertex target = ci->GetVertexByAddr(blockea);

  size_t old_size = boost::num_vertices(*cfg);
  ci->DisconnectVertex(target);
  size_t new_size = boost::num_vertices(*cfg);

  target = ci->GetVertexByAddr(blockea);

  EXPECT_EQ(target, NULL_VERTEX);
  // removing exactly one vertex
  EXPECT_EQ(old_size-1,new_size);
}

// testing vertex/component information

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_APICFG_CONTAINS_API_CALLS) {
  ApiCfgComponentPtr ci = api_graph_.GetComponent( 0x00401000 );

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000";
    return;
  }

  EXPECT_TRUE(ci->ContainsApiCalls());
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TestApiCfgComponentContainsApi) {
  ApiCfgComponentPtr ci = api_graph_.GetComponent( 0x00401000 );
  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000";
    return;
  }
  EXPECT_TRUE(ci->ContainsApi("KERNEL32.DLL!CREATEPIPE"));
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_APICFG_CONTAINS_CALLS) {

  // only contains non-API calls
  ApiCfgComponentPtr ci = api_graph_.GetComponent( 0x004017F0 );
  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component 0x004017F0";
    return;
  }
  EXPECT_TRUE(ci->ContainsCalls());

  // only contains API calls
  ApiCfgComponentPtr ci2 = api_graph_.GetComponent( 0x00401550 );

  if (ci2== NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401550";
    return;
  }

  EXPECT_TRUE(ci2->ContainsCalls());

}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_SHOULD_NOT_FIND_INVALID_COMPONENT) {
  // doesn't exist
  ApiCfgComponentPtr ci = api_graph_.GetComponent( 0x004017B0 );

  // Given the component doesn't exist, the pointer should be NULL
  EXPECT_TRUE(ci==NULL);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_MERGE_MIDDLE) {

  ApiCfgComponentPtr in = api_graph_.GetComponent( 0x00401000 );
  ApiCfgComponentPtr to = api_graph_.GetComponent( 0x0040182D );

  if (in == NULL || to == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000 or 0x0040182D";
    return;
  }

  ApiCfg* cfg = in->GetCfg();

  EXPECT_TRUE(in != NULL);
  EXPECT_TRUE(to != NULL);

  rose_addr_t merge_ea = 0x40113A;

  size_t old_size = boost::num_vertices(*cfg);
  bool result = in->Merge(to, merge_ea,false);

  EXPECT_TRUE(result);
  ApiCfgVertex merged_vtx = in->GetVertexByAddr(merge_ea);

  ApiCfgVertex prev = NULL_VERTEX;
  BGL_FORALL_INEDGES(merged_vtx, in_edge, *cfg, ApiCfg) {
    prev = boost::source(in_edge, *cfg);
    break;
  }
  const ApiVertexInfo & prev_info = (*cfg)[prev];
  EXPECT_EQ(prev_info.block->get_address(), 0x00401877u);

  size_t merged_size = boost::num_vertices(*cfg);

  // The merge should insert four new vertices

  EXPECT_EQ(merged_size-old_size,4u);//expected_size_after_merge, merged_size);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_MERGE_AT_ENTRY_WITH_CALL) {

  rose_addr_t entry_addr = 0x0040182D;
  size_t expected_size_after_merge = 22;

  ApiCfgComponentPtr in = api_graph_.GetComponent( entry_addr );
  ApiCfgComponentPtr to = api_graph_.GetComponent( 0x00401000 );

  if (in == NULL || to == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000 or 0x0040182D";
    return;
  }

  rose_addr_t merge_ea = entry_addr;

  bool result = in->Merge(to, merge_ea,false);


  EXPECT_TRUE(result);

  ApiCfg* cfg = in->GetCfg();
  size_t merged_size = boost::num_vertices(*cfg);
  EXPECT_EQ(expected_size_after_merge, merged_size);

  // The entry should be the entry of the inserted function
  EXPECT_EQ(in->GetEntryAddr(),(rose_addr_t)0x00401000);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_MERGE_AT_ENTRY_WITHOUT_CALL) {

  rose_addr_t entry_addr = 0x00401550;
  size_t expected_size_after_merge = 20;
  ApiCfgComponentPtr in = api_graph_.GetComponent( entry_addr );
  ApiCfgComponentPtr to = api_graph_.GetComponent( 0x00401000 );

  if (in == NULL || to == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000 or 0x00401550";
    return;
  }

  rose_addr_t merge_ea = entry_addr;

  if (!in || !to) {
    FAIL() << "Cannot find components";
    return;
  }

  bool result = in->Merge(to, merge_ea,false);

  EXPECT_TRUE(result);

  ApiCfg* cfg = in->GetCfg();
  size_t merged_size = boost::num_vertices(*cfg);
  EXPECT_EQ(expected_size_after_merge, merged_size);

  // The entry should be the entry of the inserted function
  EXPECT_EQ(in->GetEntryAddr(),(rose_addr_t)0x00401000);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiCfgComponentTest, TEST_MERGE_AT_EXIT) {

  ApiCfgComponentPtr in = api_graph_.GetComponent( 0x00401550 );
  ApiCfgComponentPtr to = api_graph_.GetComponent( 0x00401000 );
  rose_addr_t merge_ea = 0x00401576;
  size_t expected_size_after_merge = 20;

  if (!in || !to) {
    FAIL() << "Cannot find components";
    return;
  }

  bool result = in->Merge(to, merge_ea, false);

  EXPECT_TRUE(result);

  ApiCfg* cfg = in->GetCfg();
  size_t merged_size = boost::num_vertices(*cfg);
  EXPECT_EQ(expected_size_after_merge,merged_size);
  EXPECT_EQ(in->GetExitAddr(),(rose_addr_t)0x0040123D);
}

// This test case is for testing vertex information. Specifically, test the correct assignment of
// vertex type information and vertex functions
class ApiAnalyzerApiVertexInfoTest : public ApiAnalyzerTest { };

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiVertexInfoTest, TEST_VERTEX_INFO_CALL_TYPE) {
  ApiCfgComponentPtr c = api_graph_.GetComponent( 0x00401580 );

  if (c == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401580";;
    return;
  }

  ApiCfg *cfg = c->GetCfg();

  ApiCfgVertex v = c->GetVertexByAddr(0x004016F2);
  const ApiVertexInfo &vi = (*cfg)[v];
  EXPECT_TRUE(vi.GetType() == ApiVertexInfo::CALL);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiVertexInfoTest, TEST_VERTEX_RETN_TYPE) {
  ApiCfgComponentPtr c = api_graph_.GetComponent( 0x00401000 );

  if (c == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000";;
    return;
  }


  ApiCfg *cfg = c->GetCfg();

  ApiCfgVertex v = c->GetVertexByAddr(0x0040123D);
  const ApiVertexInfo &vi = (*cfg)[v];
  EXPECT_TRUE(vi.GetType() == ApiVertexInfo::RETN);

  ApiCfgVertex nv = c->GetVertexByAddr(0x00401000);
  const ApiVertexInfo &nvi = (*cfg)[nv];
  EXPECT_FALSE(nvi.GetType() == ApiVertexInfo::RETN);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiVertexInfoTest, TEST_VERTEX_API_TYPE) {
  ApiCfgComponentPtr c = api_graph_.GetComponent( 0x00401000 );

  if (c == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000";;
    return;
  }

  ApiCfg *cfg = c->GetCfg();

  ApiCfgVertex v = c->GetVertexByAddr(0x00401000);
  const ApiVertexInfo &vi = (*cfg)[v];

  EXPECT_TRUE(vi.GetType() == ApiVertexInfo::API);
  EXPECT_EQ("KERNEL32.DLL!CREATEPIPE",vi.api_name);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiVertexInfoTest, TEST_VERTEX_UNKN_TYPE) {
  ApiCfgComponentPtr ci = api_graph_.GetComponent(0x00401550);

  if (ci == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401550";;
    return;
  }

  ApiCfg *cfg = ci->GetCfg();

  ApiCfgVertex v = ci->GetVertexByAddr(0x00401550);
  const ApiVertexInfo &vi = (*cfg)[v];
  EXPECT_TRUE(vi.GetType() == ApiVertexInfo::UNKN) << vi.GetType();
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiVertexInfoTest, TEST_VALID_CALL_TARGET) {

  rose_addr_t callv_ea = 0x004016F2;
  ApiCfgComponentPtr c = api_graph_.GetComponent(0x00401580);

  if (c == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401580";;
    return;
  }


  ApiCfg *cfg = c->GetCfg();

  ApiCfgVertex call_vtx = c->GetVertexByAddr(callv_ea);
  const ApiVertexInfo &vi = (*cfg)[call_vtx];
  ASSERT_EQ(vi.target_address, 0x00401550u);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzerApiVertexInfoTest, TEST_VERTEX_ENDS_IN_CALL) {

  rose_addr_t callv_ea=0x004016F2, apiv_ea=0x00401580;
  ApiCfgComponentPtr c = api_graph_.GetComponent(0x00401580);

  ApiCfg *cfg = c->GetCfg();

  ApiCfgVertex api_vtx = c->GetVertexByAddr(apiv_ea);
  ApiCfgVertex call_vtx = c->GetVertexByAddr(callv_ea);

  const ApiVertexInfo &api_vi = (*cfg)[api_vtx];
  const ApiVertexInfo &call_vi = (*cfg)[call_vtx];

  EXPECT_TRUE(api_vi.EndsInCall());
  EXPECT_TRUE(call_vi.EndsInCall());

  EXPECT_FALSE(call_vi.GetType() == ApiVertexInfo::API);
  EXPECT_FALSE(api_vi.GetType() == ApiVertexInfo::CALL);
}

TEST_F(ApiAnalyzerApiVertexInfoTest, TestApiVertexInfoContainsAddress) {

  ApiCfgComponentPtr c = api_graph_.GetComponent( 0x00401000 );

  if (c == NULL) {
    FAIL() << "Failing test: Cannot find component 0x00401000";;
    return;
  }

  ApiCfg *cfg = c->GetCfg();

  ApiCfgVertex v = c->GetVertexByAddr(0x00401000);
  const ApiVertexInfo &vi = (*cfg)[v];

  EXPECT_TRUE(vi.ContainsAddress(0x0040101D));

  // should return false for garbage address
  EXPECT_FALSE(vi.ContainsAddress(0xd34db33f));
}

class ApiAnalyzertSearchManagerTest : public ApiAnalyzerTest { };

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_FIND_VALID_MULTIELEMENT_SIG) {

  ApiSig sig;
  sig.name = "TEST_SHOULD_FIND_VALID_MULTIELEMENT_SIG";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPROCESSA"));
  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector search_result;
  bool result = api_graph_.Search(sig, &search_result);

  EXPECT_TRUE(result);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_NOT_FIND_INVALID_API_SIG) {

  ApiSig sig;
  sig.name = "TEST_SHOULD_NOT_FIND_INVALID_API_SIG";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
  sig.api_calls.push_back(new ApiSigFunc("Kernel32.dll!GarbageApi"));
  sig.api_count = 3;

  ApiSearchResultVector search_result;
  bool result = api_graph_.Search(sig, &search_result);

  EXPECT_FALSE(result);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_NOT_FIND_WITH_VALID_UNCONNECTED_APIS) {

  ApiSig sig;
  sig.name = "TEST_SHOULD_NOT_FIND_WITH_VALID_UNCONNECTED_APIS";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GETPROCESSID"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GETSYSTEMTIMEASFILETIME"));
  sig.api_count = 2;

  ApiSearchResultVector search_result;
  bool result = api_graph_.Search(sig, &search_result);

  EXPECT_FALSE(result);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_HANDLE_MULTIPLE_SAME_SIG_MATCHES) {
  ApiSig sig;
  sig.name = "TEST_SHOULD_HANDLE_MULTIPLE_SAME_SIG_MATCHES";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPROCESSA"));
  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  size_t count = 0;
  size_t addr = 3;
  for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
    if (boost::iequals(ri->match_name,sig.name)) {
      count++;
    }
    if (ri->match_component_start==0x00401000) addr--;
    if (ri->match_component_start==0x00401300) addr--;
    if (ri->match_component_start==0x00401580) addr--;
  }
  EXPECT_EQ(count,3u);
  EXPECT_EQ(addr,0u);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_HANDLE_EMPTY_SIG) {

  ApiSig sig;
  sig.name = "EmptySig";
  sig.api_count = 0;

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_FALSE(r);

}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_FIND_ONE_API_SIG) {

  ApiSig sig;
  sig.name = "TEST_SHOULD_FIND_ONE_API_SIG";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!ISDEBUGGERPRESENT"));
  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);

  EXPECT_TRUE(r);

  EXPECT_EQ(results.size(),ApiSearchResultVector::size_type(1));

  ApiSearchResult res = *(results.begin());

  EXPECT_EQ(res.match_component_start, 0x0401B15u);
  EXPECT_EQ(res.search_tree.size(), decltype(res.search_tree.size())(1));
  EXPECT_EQ(res.search_tree.at(0).block->get_address(),0x0401B15u);

}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_HANDLE_BACKTRACKING_INTRAPROCEDURAL) {

  ApiSig sig;
  sig.name = "TEST_SHOULD_HANDLE_BACKTRACKING_INTRAPROCEDURAL";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GETTICKCOUNT"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!GETCURRENTPROCESSID"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!EXITPROCESS"));
  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);
  EXPECT_TRUE(r);

  std::string st = "";
  for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
    if (boost::iequals(ri->match_name,sig.name)) {
      for (std::vector<ApiWaypointDescriptor>::iterator pi=ri->search_tree.begin(); pi!=ri->search_tree.end(); pi++) {
        st += addr_str(pi->block->get_address());
      }
    }
    break;
  }
  // this is the valid signature for
  std::string expected_st = "0x0040125D0x004012AB0x004012BE0x004012D50x004012DF0x004012E5";
  EXPECT_EQ(st, expected_st);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_CORRECTLY_HANDLE_SELF_LOOPS_START_OUTSIDE_OF_LOOP) {

  // self-loop + additional APIs
  ApiSig sig;
  sig.name = "SELF_LOOPS_START_OUTSIDE_OF_LOOP";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!PEEKNAMEDPIPE")); // Forces ReadFile selfloop
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);
  EXPECT_TRUE(r);

  std::string st = "";
  for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
    if (ri->match_component_start==0x00401000) {
      for (std::vector<ApiWaypointDescriptor>::iterator pi=ri->search_tree.begin(); pi!=ri->search_tree.end(); pi++) {
        st += addr_str(pi->block->get_address());
      }
      break;
    }
  }

  std::string expected_st="0x0040113A0x0040115F0x0040117C0x0040117C0x0040117C0x0040117C0x0040117C";

  // "0x0040113A0x004018180x0040117C0x0040113A0x0040113A0x0040113A0x0040113A";
  EXPECT_EQ(expected_st,st);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_CORRECTLY_HANDLE_START_END_IN_SELF_LOOPS) {

  // start/terminate in self-loop
  ApiSig sig2;
  sig2.name = "TEST_SHOULD_CORRECTLY_HANDLE_START_END_IN_SELF_LOOPS";
  sig2.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig2.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig2.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig2.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!READFILE"));
  sig2.api_count = sig2.api_calls.size();

  ApiSearchResultVector results2;
  bool r2 = api_graph_.Search(sig2, &results2);
  EXPECT_TRUE(r2);

  std::string st2 = "";
  for (ApiSearchResultVector::iterator ri2=results2.begin(), end2=results2.end(); ri2!=end2; ri2++) {
    if (ri2->match_component_start==0x00401000) {
      for (std::vector<ApiWaypointDescriptor>::iterator pi2=ri2->search_tree.begin(); pi2!=ri2->search_tree.end(); pi2++) {
        st2 += addr_str(pi2->block->get_address());
      }
      break;
    }
  }

  std::string expected_st2="0x0040117C0x0040117C0x0040117C0x0040117C";
  EXPECT_EQ(st2,expected_st2);
}

// *****************************************************************************
// Begin test
TEST_F(ApiAnalyzertSearchManagerTest, TEST_SHOULD_PRODUCE_CORRECT_SEARCHTREE_FOR_INTRA_FUNCTION_SEARCH) {

  ApiSig sig;
  sig.name = "TEST_SHOULD_PRODUCE_CORRECT_SEARCHTREE_FOR_INTRA_FUNCTION_SEARCH";
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!CREATEPIPE"));
  sig.api_calls.push_back(new ApiSigFunc("KERNEL32.DLL!WRITEFILE"));
  sig.api_count = sig.api_calls.size();

  ApiSearchResultVector results;
  bool r = api_graph_.Search(sig, &results);
  EXPECT_TRUE(r);

  std::string st = "";
  for (ApiSearchResultVector::iterator ri=results.begin(), end=results.end(); ri!=end; ri++) {
    if (ri->match_component_start==0x00401000) {
      for (std::vector<ApiWaypointDescriptor>::iterator pi=ri->search_tree.begin(); pi!=ri->search_tree.end(); pi++) {
        st += addr_str(pi->block->get_address());
      }
      break;
    }
  }
  std::string expected_st = "0x004010000x0040105C0x004010870x004010940x004011000x004011150x0040113A0x0040115F0x0040117C0x004011AA0x004011BF";
  EXPECT_EQ(st, expected_st);
}

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);

  ProgOptVarMap vm = parse_cert_options(argc, argv, cert_standard_options());

  // Find calls, functions, and imports.
  DescriptorSet ds(vm);
  if (ds.get_interp() == NULL) {
    GFATAL << "Unable to analyze file (no executable content found)." << LEND;
    return EXIT_FAILURE;
  }
  // Resolve imports, load API data, etc.
  ds.resolve_imports();

  BottomUpAnalyzer bua(&ds, vm);
  bua.analyze();

  int rc = RUN_ALL_TESTS();
  global_rops.reset();
  return rc;
}
