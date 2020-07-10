/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/
/**
 * The unamed top-level object that contains a list of structures
 *
 * @author jsg
 *
 */

package ooanalyzer.jsontypes;

import java.util.Map;
import java.util.Collection;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import ghidra.util.Msg;

/**
 * This class is basically a wrapper to enable JSON loading through GSON
 */
public class OOAnalyzerJsonRoot {

  public static final String EXPECTED_JSON_VERSION = "2.1.0";

  @SerializedName("filemd5")
  @Expose
  private String md5;

  @SerializedName("filename")
  @Expose
  private String fname;

  @SerializedName("version")
  @Expose
  private String version;

  @SerializedName("structures")
  @Expose
  private Map<String, OOAnalyzerClassType> types;

  public Collection<OOAnalyzerClassType> getStructures() {
    if (!version.equals(EXPECTED_JSON_VERSION)) {
      Msg.warn(this, "Unable to locate allowSwingToProcessEvents. The GUI may be irresponsive.");
      throw new IllegalArgumentException(String.format("Expected JSON version '%s' but got '%s'", EXPECTED_JSON_VERSION, version));
    }
    return types.values ();
  }

  public String getFilename () {
    return fname;
  }

  public String getMd5 () {
    return md5;
  }
}
