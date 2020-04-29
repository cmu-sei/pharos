/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/
package ooanalyzer.jsontypes;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * Represents a class method. Nothing in this class is optional
 */
public class Method {

	@Expose
	@SerializedName("ea")
	private String ea;
	
	@Expose
	@SerializedName("type")
	private String type;
	
	@Expose
	@SerializedName("name")
	private String name;

	@Expose
	@SerializedName("demangled_name")
	private String demangledName;
	
	@Expose
	@SerializedName("import")
	private String imported;
	
	public String getEa() {
		return ea;
	}

	public String getType() {
		return type;
	}

	public String getName() {
		return name;
	}

	@Override
	public String toString() {
		return "[ea=" + ea + ", type=" + type + ", name=" + name + "]";
	}
}
