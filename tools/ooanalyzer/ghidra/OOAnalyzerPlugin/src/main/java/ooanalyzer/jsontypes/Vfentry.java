/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer.jsontypes;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;

/**
 * A virtual function table entry
 */

public class Vfentry {
	
	@Expose
	@SerializedName("ea")
    private String ea;
	
	@Expose
	@SerializedName("offset")
    private String offset;
	
	@Expose
	@SerializedName("name")
    private String name;
	
	@Expose
	@SerializedName("demangled_name")
    private String demangeledName;
	
	@Expose
	@SerializedName("import")
    private String imported;
	
	@Expose
	@SerializedName("type")
    private String type;

    public String getEa() {
        return ea;
    }

    public String getDemangeledNname() {
        return demangeledName;
    }

  public String getImported() {
      return this.imported;
  }
    
    public Integer getOffset() {
        return Integer.parseInt(offset);
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }
    
    public void setEa(String ea) {
		this.ea = ea;
	}

	public void setOffset(String offset) {
		this.offset = offset;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setDemangeledName(String demangeled_name) {
		this.demangeledName = demangeled_name;
	}

	public void setImported(String imported) {
		this.imported = imported;
	}

	public void setType(String type) {
		this.type = type;
	}

	@Override
    public String toString() {
        return "[ea=" + ea + ", offset=" + offset + ", name=" + name
                + ", demangled name= " + demangeledName + ", imported= "
                + imported + ", type=" + type + "]";
    }
}
