/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer;

//import static org.junit.Assert.assertTrue;

import java.nio.file.Path;
import java.nio.file.Paths;

import java.io.File;
import java.util.Optional;
import java.util.ArrayList;
import java.util.List;

import ooanalyzer.OOAnalyzerGhidraPlugin;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ghidra.program.util.GhidraProgramUtilities;

import ghidra.program.model.listing.Program;

class OOAnalyzerTest extends AbstractGhidraHeadedIntegrationTest {

  private TestEnv env;
  private OOAnalyzerGhidraPlugin plugin;
  private Path testDir;

  OOAnalyzerTest () throws Exception {
  }

  public void doTest (Path exe, Path json, Boolean useNs) throws Exception {
    env = new TestEnv ();
    setErrorGUIEnabled (false);

    // Import the program
    Program p = env.getGhidraProject ().importProgram (exe.toFile ());

    // Open in the tool
    env.open (p);

    // Analyze it
    env.getGhidraProject ().analyze (p);

    // And mark it as analyzed?  Ok ghidra whatever.
    GhidraProgramUtilities.setAnalyzedFlag (p, true);

    plugin = env.addPlugin(OOAnalyzerGhidraPlugin.class);

    // Import json.
    OOAnalyzerGhidraPlugin.ImportCommand cmd = plugin.configureAndExecute (json.toFile (), useNs);

    // Use a semaphore or something. Get the tool's TaskMonitor?
    while (!cmd.getCompleted ()) {
      Msg.debug (this, "Sleeping until completed.");
      Thread.sleep(1000);
    }

    Msg.info (this, "We didn't crash! \\o/");

    env.dispose ();

  }

}
