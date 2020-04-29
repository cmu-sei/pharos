/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.SystemUtilities;

/**
 * Dialog for the plugin
 *
 */
public class OOAnalyzerDialog extends DialogComponentProvider {

	// The JSON file containing OO data
	private File jsonFile = null;

	// Assume we will organize data types into 
	private Boolean useOOAnalyzerNamespace = true;
	
	private Boolean isCancelled = false;

	/**
	 * Open the dialog.
	 * 
	 * @param c      the control manager
	 * @param parent the parent window
	 */
	public OOAnalyzerDialog(String title) {
		super(title);

		JPanel workPanel = new JPanel(new GridBagLayout());
		GridBagConstraints cs = new GridBagConstraints();

		cs.fill = GridBagConstraints.HORIZONTAL;

		JButton selectJsonFile = new JButton("JSON File");
		selectJsonFile.setToolTipText("Select the OOAnalyzer JSON file.");

		selectJsonFile.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {

				GhidraFileChooser chooser = new GhidraFileChooser(null);
				AtomicReference<File> selectedFileRef = new AtomicReference<>();

				Runnable r = () -> {
					chooser.setTitle("OOAnalyzer JSON File");
					chooser.setSelectedFile(selectedFileRef.get());
					chooser.setApproveButtonText("Select");
					chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
					selectedFileRef.set(chooser.getSelectedFile());
				};

				SystemUtilities.runSwingNow(r);

				jsonFile = selectedFileRef.get();
				if (jsonFile != null) {
					JButton button = ((JButton) e.getSource());
					button.setText("Selected File: " + jsonFile.getName());
				}
			}
		});

		cs.gridx = 0;
		cs.gridy = 0;
		cs.gridwidth = 1;
		workPanel.add(selectJsonFile, cs);

		JCheckBox cbNamespace = new JCheckBox("Use OOAnalyzer namespace");

		cbNamespace.setToolTipText(
				"Organize standard classes added or changed by OOAnalyzer in a namespace named 'OOAnalyzer'.");
		cbNamespace.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				useOOAnalyzerNamespace = (e.getStateChange() == ItemEvent.SELECTED);
			}
		});

		cbNamespace.setSelected(useOOAnalyzerNamespace);
		cs.gridx = 0;
		cs.gridy = 1;
		cs.gridwidth = 1;
		workPanel.add(cbNamespace, cs);

		addOKButton();
		setOkEnabled(true);

		addCancelButton();
		setCancelEnabled(true);

		addWorkPanel(workPanel);
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	protected void cancelCallback() {
		setCancelled(true);
		close();
	}

	@Override
	protected void escapeCallback() {
		setCancelled(true);
		close();
	}

	public Boolean useOOAnalyzerNamespace() {
		return this.useOOAnalyzerNamespace;
	}

	public File getJsonFile() {
		return this.jsonFile;
	}

	/**
	 * @return the isCancelled
	 */
	public Boolean isCancelled() {
		return isCancelled;
	}

	/**
	 * @param isCancelled the isCancelled to set
	 */
	public void setCancelled(Boolean isCancelled) {
		this.isCancelled = isCancelled;
	}
}
