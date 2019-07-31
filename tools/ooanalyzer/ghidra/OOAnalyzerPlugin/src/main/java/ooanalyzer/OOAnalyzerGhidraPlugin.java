/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer;

import java.awt.event.KeyEvent;
import java.io.File;
import java.util.List;
import java.util.Optional;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ooanalyzer.jsontypes.OOAnalyzerType;

// @formatter:off
@PluginInfo(status = PluginStatus.STABLE, 
			packageName = OOAnalyzerGhidraPlugin.NAME, 
			category = PluginCategoryNames.ANALYSIS, 
			shortDescription = "CERT OOAnalyzer JSON results importer.", 
			description = "Import and apply CERT OOAnalyzer results to a Ghidra project.")
// @formatter:on

/**
 * The main OOAnalyzer Plugin
 *
 */
public class OOAnalyzerGhidraPlugin extends ProgramPlugin {

	private static final String CERT_MENU = "&CERT";
	public static final String NAME = "OOAnalyzer";
	private DockingAction ooaAction = null;

	/**
	 * Setup the plugin
	 */
	public OOAnalyzerGhidraPlugin(PluginTool tool) {
		super(tool, true, true);
		setupActions();
	}
	
	/**
	 * Run the script
	 */
	private void configureAndExecute() {

		OOAnalyzerDialog ooaDialog = new OOAnalyzerDialog("OOAnalyzer Settings");
		OOAnalyzerGhidraPlugin.this.tool.showDialog(ooaDialog);
		File jsonFile = ooaDialog.getJsonFile();

		if (ooaDialog.isCancelled()) {
			return;
		}
		else if (jsonFile == null) {
			new OptionDialog("Error", "Invalid JSON file", OptionDialog.ERROR_MESSAGE, null).show();
			return;
		}

		if (!OOAnalyzer.doNamesMatch(jsonFile.getName(), currentProgram.getName())) {
			return;
		}

		Optional<List<OOAnalyzerType>> optJson = OOAnalyzer.parseJsonFile(jsonFile);
		if (optJson.isEmpty()) {
			new OptionDialog("Error", "Could not load/parse JSON file " + jsonFile.getName(),
					OptionDialog.ERROR_MESSAGE, null).show();

		} else {
			if (OOAnalyzerGhidraPlugin.this.currentProgram != null) {

				// Actually run the plugin
				int result = -1;
				int tid = OOAnalyzerGhidraPlugin.this.currentProgram.startTransaction("OOA");
				try {
					result = OOAnalyzer.execute(optJson.get(), OOAnalyzerGhidraPlugin.this.currentProgram,
							ooaDialog.useOOAnalyzerNamespace());
					if (result < 0) {
						new OptionDialog("Error", "No current program for OOAnalyzer.", OptionDialog.ERROR_MESSAGE,
								null).show();
					} else if (result > 0) {
						new OptionDialog("Results", "OOAnalyzer loaded " + result + " classes.", 
								OptionDialog.INFORMATION_MESSAGE, null).show();
					} else {
						new OptionDialog("Results", "OOAnalyzer could not load any classes",
								OptionDialog.WARNING_MESSAGE, null).show();
					}
				} finally {
					OOAnalyzerGhidraPlugin.this.currentProgram.endTransaction(tid, (result > 0));
				}
			}
		}
	}

	private void setupActions() {

		ooaAction = new DockingAction("OOAnalyzer", getName()) {

			@Override
			public void actionPerformed(ActionContext context) {
				configureAndExecute();
			}
		};

		final String ooaActionName = OOAnalyzerGhidraPlugin.NAME;
		final String ooaMenu = CERT_MENU;

		ooaAction.setMenuBarData(new MenuData(new String[] { ooaMenu, ooaActionName }, null, OOAnalyzerGhidraPlugin.NAME,
				MenuData.NO_MNEMONIC, null));

		ooaAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F12, 0));
		ooaAction.setEnabled(false);
		ooaAction.markHelpUnnecessary();

		tool.addAction(ooaAction);
	}

	/**
	 * Called when program activated
	 */
	@Override
	protected void programActivated(Program activatedProgram) {
		ooaAction.setEnabled(true);
	}

}
