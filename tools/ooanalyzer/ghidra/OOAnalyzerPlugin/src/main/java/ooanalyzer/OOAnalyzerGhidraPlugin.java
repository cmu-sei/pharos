/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer;

import java.awt.event.KeyEvent;
import java.io.File;
import java.util.List;
import java.util.Optional;

import javax.swing.JOptionPane;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.AskDialog;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ooanalyzer.jsontypes.OOAnalyzerType;

// @formatter:off
@PluginInfo(status = PluginStatus.STABLE, packageName = OOAnalyzerGhidraPlugin.NAME, category = PluginCategoryNames.ANALYSIS, shortDescription = "CERT OOAnalyzer JSON results importer.", description = "Import and apply CERT OOAnalyzer results to a Ghidra project.")
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
		} else if (jsonFile == null) {
			Msg.showError(this, null, "Error", "Invalid JSON file");
			return;
		}

		String baseJsonName = jsonFile.getName().split("\\.(?=[^\\.]+$)")[0];
		String baseProgName = currentProgram.getName().split("\\.(?=[^\\.]+$)")[0];
		if (baseJsonName.equalsIgnoreCase(baseProgName) == false) {
			if (0 != JOptionPane.showConfirmDialog(null, "JSON file name mismatch",
					"The selected JSON name does not match the executable, continue?", JOptionPane.YES_NO_OPTION,
					JOptionPane.WARNING_MESSAGE)) {
				Msg.info(null, "OOAnalyzer cancelled");
				return;
			}
		}

		Optional<List<OOAnalyzerType>> optJson = OOAnalyzer.parseJsonFile(jsonFile);
		if (optJson.isEmpty()) {
			Msg.showError(this, null, "Error", "Could not load/parse JSON file " + jsonFile.getName());
		} else {
			if (OOAnalyzerGhidraPlugin.this.currentProgram != null) {

				// Actually run the plugin
				int result = -1;
				int tid = OOAnalyzerGhidraPlugin.this.currentProgram.startTransaction("OOA");
				try {
					result = OOAnalyzer.execute(optJson.get(), OOAnalyzerGhidraPlugin.this.currentProgram,
							ooaDialog.useOOAnalyzerNamespace());
					if (result < 0) {
						Msg.showError(this, null, "Error", "No current program for OOAnalyzer");
					} else if (result > 0) {
						Msg.showInfo(this, null, "Results", "OOAnalyzer loaded " + result + " classes");
					} else {
						Msg.showInfo(this, null, "Results", "OOAnalyzer could not find any classes");
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

		ooaAction.setMenuBarData(new MenuData(new String[] { ooaMenu, ooaActionName }, null,
				OOAnalyzerGhidraPlugin.NAME, MenuData.NO_MNEMONIC, null));

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
