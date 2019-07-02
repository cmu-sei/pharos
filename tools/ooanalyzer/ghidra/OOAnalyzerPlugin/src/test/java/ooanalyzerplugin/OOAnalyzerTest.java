/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/
// This is commented out because it requires work but is really just test code
package ooanalyzerplugin;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Optional;
import java.util.ArrayList;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;

import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ooanalyzerplugin.OOAnalyzer;
import ooanalyzerplugin.jsontypes.OOAnalyzerClassList;
import ooanalyzerplugin.jsontypes.OOAnalyzerType;

import ghidra.program.model.listing.Program;

public class OOAnalyzerTest extends AbstractProgramBasedTest {

	@Before
	public void setUp() {
		Msg.info(this, "@Before called");
		try {
			
			initialize();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Override
	protected String getProgramName() {
		return "oo.exe.gzf";
		//	return "oo.exe";
	}

	@After
	public void tearDown() {
		Msg.info(this, "@After called");	
	}

	@Test
	@DisplayName("Add operation test")
	public void testOO()  {
			
		File json = new File("data/oo.json");
		Optional<List<OOAnalyzerType>> optList = OOAnalyzer.parseJsonFile(json);

		assertTrue(optList.isPresent());

		// TODO: this looks broken since jsg refactored
		List<OOAnalyzerType> typeList = optList.get();
		//Msg.info(this, ((OOAnalyzerClassList) typeList).getOOAnalyzerClassTypes().size());

		Msg.info(this, typeList.size());

		// Try this:
		//typeList.forEach((ooaType) -> {
		//	Msg.info(this, ooaType.toString());                 
		//});
		int count = 0;
		TaskMonitor monitor = null;
		int tid = program.startTransaction("OOA");
		boolean result = false;
		try {
		    OOAnalyzer ooa = new OOAnalyzer(program);
		    Msg.info(this, ooa.toString());
		    //ooa.setMonitor(monitor);
		    count = ooa.analyzeClasses(optList.get());

		    if (count > 0) {
			Msg.info(this,
				 "OOAnalyzer loaded " + count + " classes from JSON file.");
			result = true;
		    } else {
			Msg.info(this,
				 "OOAnalyzer could not load classes from JSON file.");
		    }
		} finally {
		    program.endTransaction(tid, result);
		}

		//OOAnalyzer ooa = new OOAnalyzer(program);
		//int count = ooa.analyzeClasses(optList.get());
		//int count = ooa.analyzeClasses(typeList);

		assertTrue(count > 0);
	}

}
