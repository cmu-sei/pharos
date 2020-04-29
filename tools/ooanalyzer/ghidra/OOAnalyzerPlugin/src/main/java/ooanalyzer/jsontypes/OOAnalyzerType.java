
/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer.jsontypes;

import java.util.List;
import java.util.Optional;

import com.google.gson.JsonArray;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.Demangler;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;

/**
 * A JSON representation of a C++ class from OOAnalyzer
 */
public class OOAnalyzerType {

	@Expose
	@SerializedName("Name")
	private String name;

	@Expose
	@SerializedName("DemangledName")
	private String demangledName;

	// The namespace is not part of the JSON
	private String namespace;

	@Expose
	@SerializedName("Size")
	private Integer size;

	@Expose
	@SerializedName("Members")
	private List<Member> members;

	@Expose
	@SerializedName("Methods")
	private List<Method> methods;

	@Expose
	@SerializedName("Vftables")
	private List<Vftable> vftables;

	public OOAnalyzerType(String name, String demangledName, String namespace, Integer size, List<Member> members,
			List<Method> methods, List<Vftable> vftables) {

		this.name = name;
		this.demangledName = demangledName;
		this.namespace = namespace;
		this.size = size;
		this.members = members;
		this.methods = methods;
		this.vftables = vftables;
	}

	/**
	 * Return mangled name for this type
	 *
	 * @return the name recovered from JSON
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * Return the (possibly unspecified) demangled name
	 * 
	 * @return
	 */
	public Optional<String> getDemangledName() {
		return (this.demangledName != null && this.demangledName.length() > 0) ? Optional.of(this.demangledName)
				: Optional.empty();
	}

	/**
	 * 
	 * @return
	 */
	public String getNameWithoutNamespace() {

		if (this.demangledName != null && this.demangledName.length() > 0) {
			if (this.namespace != null && this.namespace.length() > 0) {
				return this.demangledName.substring(this.namespace.length() + "::".length());
			}
			return this.demangledName;
		}
		return this.name;
	}

	public Optional<String> getNamespace() {
		if (namespace != null && namespace.length() > 0) {
			return Optional.of(namespace);
		}
		return Optional.empty();
	}
	
	public void setNamespace(String namespace) {
		this.namespace = namespace;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Integer getSize() {
		return this.size;
	}

	public Optional<List<Member>> getMembers() {
		return Optional.ofNullable(members);
	}

	public Optional<List<Method>> getMethods() {
		return Optional.ofNullable(methods);
	}

	public Optional<List<Vftable>> getVftables() {
		return Optional.ofNullable(vftables);
	}

	@Override
	public String toString() {

		String str = "[name=" + name + ", demangled name= " + demangledName + ", size=" + size + ", ";
		if (members == null) {
			str += "members=[None], ";
		} else {

			str += "members=[";
			for (Member mbr : members) {
				if (mbr != null) {
					str += mbr.toString() + " ";
				}
			}
			str += "], ";
		}

		if (methods == null) {
			str += "methods=[None]";
		} else {
			str += "methods=[";
			for (Method mtd : methods) {
				if (mtd != null) {
					str += mtd.toString() + " ";
				}
			}
			str += "], ";
		}
		if (vftables == null) {
			str += "vftables=[None]";
		} else {
			str += "vftables=[";

			for (Vftable vft : vftables) {
				if (vft != null) {
					str += vft.toString() + " ";
				}
			}
			str += "]";
		}
		return str;
	}
}
