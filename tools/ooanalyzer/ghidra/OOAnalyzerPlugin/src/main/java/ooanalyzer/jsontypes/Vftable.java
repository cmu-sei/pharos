/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer.jsontypes;

import java.util.List;
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
	@SerializedName("vfptr")
	private String vfptr;

	@Expose
	@SerializedName("entries")
	private List<Vfentry> entries;

	public Long getEa() {
		return Long.parseLong(ea, 16);
	}

	public Integer getVfptr() {
		return Integer.parseInt(vfptr);
	}

	public Optional<List<Vfentry>> getEntries() {
		return Optional.ofNullable(entries);
	}

	@Override
	public String toString() {
		String str = "[ea=" + ea + ", vfptr=" + vfptr + ", ";

		if (entries != null) {
			str += "entries={";

			for (Vfentry vfe : entries) {
				str += vfe.toString() + " ";
			}
			str += "}";
		} else {
			str += "entries={None}";
		}
		return str + "]";
	}
}
