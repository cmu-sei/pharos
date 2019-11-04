/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

// An example script to import Pharos OOAnalyzer results.  
//@author Jeffrey Gennari
//@category CERT.DataTypes
//@classification UNCLASSIFIED
//@menupath CERT.OOAnalyzer

import java.io.File;
import java.util.List;
import java.util.Optional;

import docking.widgets.OptionDialog;
import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import ooanalyzer.OOAnalyzer;
import ooanalyzer.OOAnalyzerDialog;
import ooanalyzer.jsontypes.OOAnalyzerType;

public class OOAExampleScript extends GhidraScript {

	@Override
	public void run() throws Exception {

		// A program must be open in order to run the plugin
		if (currentProgram == null) {
			popup("This script should be run from a tool with an open program");
			return;
		}

		// The dialog is used to configure the plugin.
		OOAnalyzerDialog ooaDialog = new OOAnalyzerDialog("OOAnalyzer Settings");

		state.getTool().showDialog(ooaDialog);
		File jsonFile = ooaDialog.getJsonFile();
		if (jsonFile == null) {
			printerr("No JSON file selected");
			return;
		}

		// Verify the JSON file is the intended file
		String baseJsonName = jsonFile.getName().split("\\.(?=[^\\.]+$)")[0];
		String baseProgName = currentProgram.getName().split("\\.(?=[^\\.]+$)")[0];
		if (baseJsonName.equalsIgnoreCase(baseProgName) == false) {
			if (!askYesNo("JSON file name mismatch", "The selected JSON name does not match the executable, continue?")) {
				return;
			}			
		}

		try {

			// Parse the JSON file and run the analysis
			Optional<List<OOAnalyzerType>> optList = OOAnalyzer.parseJsonFile(jsonFile);

			if (optList.isEmpty()) {
				Msg.showError(this, null, "Error",  "Could not load JSON from " + jsonFile.getName());
				return;
			}

			int count = OOAnalyzer.execute(optList.get(), currentProgram, ooaDialog.useOOAnalyzerNamespace());

			// The result returned by the analysis is the number of classes added to the
			// project. If this number is <0 then something went wrong. 

			if (count < 0) {
				Msg.showError(this,null,"Error", "No current program for OOAnalyzer.");
				
			} else if (count > 0) {
				Msg.showInfo(this, null, "Results", "OOAnalyzer loaded " + count + " classes");

			} else {
				
				// No classes found
				
				Msg.showInfo(this, null, "Results", "OOAnalyzer could not find any classes");
			}
		} catch (Exception e) {
			e.printStackTrace();

		}
	}
}
