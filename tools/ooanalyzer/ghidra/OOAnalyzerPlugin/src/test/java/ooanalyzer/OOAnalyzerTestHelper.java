/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Stream;
import java.util.stream.Collectors;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.net.URL;
import java.net.URLClassLoader;

//import ooanalyzer.OOAnalyzertest;

// For some reason, gradle can't find JUnit tests in a class that extends
// AbstractGhidraHeadedIntegrationTest.  So we'll make the JUnit tests in this class and call
// OOAnalyzerTest
class OOAnalyzerTestHelper {

  final private String testNameSeparator = "_";

  //private OOAnalyzerTest ooatest;
  private Set<Path> testJsons;

  private Path exeDirectory;
  private Path jsonDirectory;

  OOAnalyzerTestHelper () throws java.io.IOException {
    exeDirectory = Paths.get("..", "..", "..", "..", "tests");
    jsonDirectory = Paths.get(exeDirectory.toString (), "..", "tools", "ooanalyzer", "tests");
    testJsons =
      Files.find(jsonDirectory, 999, (p, bfa) -> p.getFileName ().toString ().endsWith (".json") && bfa.isRegularFile ())
      .collect(Collectors.toSet ());

  }

  @TestFactory
  public Stream<DynamicTest> makeTests () {
    return testJsons.stream ()
      .flatMap (json -> {
          var testName = jsonDirectory.relativize (json);
          var exe = Paths.get (exeDirectory.resolve (testName).toString ().replace (".json", ".exe"));

          return (Arrays.asList(new Boolean[] { true, false })
                  .stream ().map (useNs -> {
                      var name = testName.toString () + testNameSeparator + (useNs ? "useNs" : "noUseNs");
                      return DynamicTest.dynamicTest(name, () ->
                                              {
                                                OOAnalyzerTest ooatest = new OOAnalyzerTest ();
                                                ooatest.doTest (exe, json, useNs);
                                              });
                                    }));

        });
  }
}
