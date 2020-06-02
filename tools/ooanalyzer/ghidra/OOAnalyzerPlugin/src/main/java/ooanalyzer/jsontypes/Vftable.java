/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer.jsontypes;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;

/**
 * A class to represent a virtual function table.
 */
public class Vftable {

  @Expose
  @SerializedName("ea")
  private String ea;

  @Expose
  @SerializedName("vftptr")
  private String vftptr;

  @Expose
  @SerializedName("entries")
  private Map<String, Vfentry> entries;

  public Long getEa() {
    return Long.decode (ea);
  }

  public Integer getVftptr() {
    return Integer.decode (vftptr);
  }

  public Collection<Vfentry> getEntries() {
    return entries.values ();
  }

  @Override
  public String toString() {
    String str = "[ea=" + ea + ", vftptr=" + vftptr + ", ";

    if (entries != null) {
      str += "entries={";

      for (Vfentry vfe : entries.values ()) {
        str += vfe.toString() + " ";
      }
      str += "}";
    } else {
      str += "entries={None}";
    }
    return str + "]";
  }
}
