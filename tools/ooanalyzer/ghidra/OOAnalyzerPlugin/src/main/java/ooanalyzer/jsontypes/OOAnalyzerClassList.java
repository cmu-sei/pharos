/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/
/**
 * The unamed top-level object that contains a list of structures
 * 
 * @author jsg
 *
 */

package ooanalyzer.jsontypes;

import java.util.List;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * This class is basically a wrapper to enable JSON loading through GSON 
 */
public class OOAnalyzerClassList {
	
	@SerializedName("Structures")
	@Expose
    private List<OOAnalyzerType> types;

    public List<OOAnalyzerType> getOOAnalyzerClassTypes() {
        return types;
    }
}
