/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.text.StringCharacterIterator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;

import docking.widgets.OptionDialog;
import ghidra.app.util.demangler.CharacterIterator;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.Demangler;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.AutoParameterImpl;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ooanalyzer.jsontypes.Member;
import ooanalyzer.jsontypes.Method;
import ooanalyzer.jsontypes.OOAnalyzerClassList;
import ooanalyzer.jsontypes.OOAnalyzerType;
import ooanalyzer.jsontypes.Vfentry;
import ooanalyzer.jsontypes.Vftable;

/**
 * The main OOAnalyzer engine. This class actually updates the Ghidra dataype
 * manager and symbol table with OOAnalyzer class information.
 */
public class OOAnalyzer {

	// elements needed to work with Ghidra
	private FlatProgramAPI flatApi;
	private Program program;
	private TaskMonitor monitor;
	private DataTypeManager dataTypeMgr;
	private SymbolTable symbolTable;

	// The category paths for OOAnalyzer a d virtual function tables
	public static final CategoryPath ooanalyzerCategory = new CategoryPath("/OOAnalyzer");
	private final CategoryPath ooanalyzerVirtualFunctionsCategory = new CategoryPath("/OOAnalyzer/VirtualFunctions");

	// by default organize new data types / symbols in the OOAnalyzer namespace for
	// clarity on what changed.
	private Boolean useOOAnalyzerNamespace = true;
	private Namespace ooanalyzerNamespace = null;

	private final String autoFuncNamePrefix = "FUN_";

	// keep track of virtual function tables
	private HashMap<Address, Structure> vftableMap = new HashMap<>();

	// This is a mapping of the JSON OOAnalyzer type to the selected Ghidra type
	private HashMap<OOAnalyzerType, Structure> classTypeMap = new HashMap<>();

	// Keppe track of symbol to structure
	private HashMap<Structure, Symbol> classSymbolMap = new HashMap<>();

	/***
	 * Different types of methods that are reported via JSON.
	 */
	private enum MethodType {
		CTOR, DTOR, METHOD, VIRTUAL, VIRTUAL_DTOR;
	}

	/**
	 * Enum way to map json to ghidra types.
	 *
	 */
	private enum MemberType {
		STRUC {
			@Override
			public String jsonTypeName() {
				return "struc";
			}
		},
		ASCII {
			@Override
			public String jsonTypeName() {
				return "ascii";
			}

			@Override
			public String ghidraTypeName() {
				return "string";
			}
		},
		QWORD {
			@Override
			public String jsonTypeName() {
				return "qword";
			}

			@Override
			public String ghidraTypeName() {
				return "/qword";
			}
		},
		DWORD {
			@Override
			public String jsonTypeName() {
				return "dword";
			}

			@Override
			public String ghidraTypeName() {
				return "/dword";
			}
		},
		WORD {
			@Override
			public String jsonTypeName() {
				return "word";
			}

			@Override
			public String ghidraTypeName() {
				return "/word";
			}
		},
		BYTE {
			@Override
			public String jsonTypeName() {
				return "byte";
			}

			@Override
			public String ghidraTypeName() {
				return "/byte";
			}
		},
		VFPTR {
			@Override
			public String jsonTypeName() {
				return "vfptr";
			}

			@Override
			public String ghidraTypeName() {
				return "LPVOID";
			}
		};

		public abstract String jsonTypeName();

		// The default here is the empty string because the 'struct' type is
		// generic and can be many things
		public String ghidraTypeName() {
			return "";
		}
	}

	/**
	 * API to run the OOAnalyzer importer
	 * 
	 * @param ooaClassList           the class list to import
	 * @param prog                   the program the program to use
	 * @param useOOAnalyzerNamespace flag on how to organize types
	 * @return the number of classes imported
	 */
	public static int execute(List<OOAnalyzerType> ooaClassList, final Program prog, Boolean useOOAnalyzerNamespace) {

		if (prog == null) {
			return -1;
		}

		return new OOAnalyzer(prog, useOOAnalyzerNamespace).analyzeClasses(ooaClassList);
	}

	/**
	 * Analyze a program.
	 * 
	 * @param p                      the program
	 * @param useOOAnalyzerNamespace flag on how to organize types
	 */
	public OOAnalyzer(Program p, Boolean useOOAnalyzerNamespace) {

		this.program = p;
		this.dataTypeMgr = this.program.getDataTypeManager();
		this.symbolTable = this.program.getSymbolTable();
		this.flatApi = new FlatProgramAPI(this.program);
		this.monitor = TaskMonitor.DUMMY;
		this.useOOAnalyzerNamespace = useOOAnalyzerNamespace;
	}

	/**
	 * Set a task monitor
	 * 
	 * @param m the task monitor
	 */
	public void setMonitor(TaskMonitor m) {
		this.monitor = m;
	}

	/**
	 * Find the Ghidra structure types by name.
	 * 
	 * @param strucName
	 * @return the found structure or empty
	 */
	private Optional<Structure> findStructure(String strucName) {

		Iterable<Structure> sitr = () -> dataTypeMgr.getAllStructures();

		// This will look for an exact match among the Ghidra structures
		String normalizedName = strucName.replaceAll("::", "/");

		for (Structure struct : sitr) {
			String normalizedGhidraName = struct.getPathName().replaceAll("::", "/");

			// Sometimes the ghidra path name starts with '/'
			if (normalizedGhidraName.equalsIgnoreCase(normalizedName)
					|| normalizedGhidraName.equalsIgnoreCase("/" + normalizedName)) {

				return Optional.of(struct);
			}
		}

		return Optional.empty();
	}

	/**
	 * Find a data type by name.
	 * 
	 * @param name the name to the type to find
	 * @return the found data type or empty
	 */
	private Optional<DataType> findDataType(String name) {

		Iterable<DataType> itr = () -> dataTypeMgr.getAllDataTypes();

		// use the stream API to either find the type or return null. Note that
		// this is not an exact match
		return StreamSupport.stream(itr.spliterator(), true)
				.filter(dt -> dt.getName().toUpperCase().indexOf(name.toUpperCase()) != -1).findAny();
	}

	/**
	 * Parse and apply the OOAnanlyzer recoverd JSON classes to Ghidra.
	 * 
	 * @param structs The list of structures parsed from the JSON file
	 * @return true on success, false otherwise
	 */
	public int analyzeClasses(List<OOAnalyzerType> typeList) {

		if (typeList == null) {
			return 0;
		}

		if (!dataTypeMgr.isUpdatable()) {
			return 0;
		}

		// List<OOAnalyzerType> typeList = structs.getOOAnalyzerClassTypes();

		if (typeList.isEmpty()) {
			return 0;
		}

		if (this.useOOAnalyzerNamespace) {
			// Create the OOAnalyzer namespace under which all symbols will be organized, if
			// that is what the user desires
			try {

				this.ooanalyzerNamespace = this.symbolTable.createNameSpace(null, ooanalyzerCategory.getName(),
						SourceType.ANALYSIS);

			} catch (DuplicateNameException | InvalidInputException e) {
				// Nothing to do here
			}
		}

		// There a few passes made over the structs list:
		//
		// Pass 1: Type/Name selection
		// Pass 2: Symbol selection
		// Pass 3: Update type manager
		// Pass 4: Update method definition
		// Pass 5: Update method/vftables

		monitor.initialize(5);

		// Pass 1:
		// Decide which name and tyoe to use

		typeList.forEach(ooaType -> {

			// There was class name information in the ghidra-defined methods, try to
			// use it
			Optional<DataType> optType = scanMethodsForType(ooaType);

			optType.ifPresent(t -> ooaType.setName(t.getName()));

			// Attempt to use the ghidra-defined structure name. If there is no structure
			// name then we'll go with the OOAnalyzer type

			String ooaTypeName = ooaType.getDemangledName().orElse(ooaType.getName());

			Structure foundType = findStructure(ooaTypeName).orElse(null);

			Optional<Structure> selectedType = compareTypes(ooaType, foundType);

			selectedType.ifPresentOrElse(ghidraType -> classTypeMap.put(ooaType, ghidraType),
					() -> Msg.warn(this, "Could not select type for " + ooaTypeName));
		});

		Msg.info(this, classTypeMap.size() + " types selected out of " + typeList.size()
				+ " defined in OOAnalyzer JSON file.");

		monitor.incrementProgress(1);

		// Pass 2:
		// Associate symbols with the classes

		classTypeMap.forEach((ooaType, ghidraType) -> {
			if (ghidraType != null) {
				selectClassSymbol(ghidraType);
			} else {
				Msg.warn(this, "There is no type defined for " + ooaType.getDemangledName().orElse(ooaType.getName()));
			}
		});

		Msg.info(this, "Symbol table updated.");
		monitor.incrementProgress(1);

		// Pass 3:
		// Fill in the members. This will update the types, but not commit to
		// the type manager. The reason the types are created in a separate pass
		// is because some members themselves may be class types

		classTypeMap.forEach((ooaType, ghidraType) -> {
			ghidraType.setDescription("C++ Class updated via OOAanalyzer.");
			analyzeMembers(ooaType, ghidraType);
		});
		Msg.info(this, "Type definition complete.");
		monitor.incrementProgress(1);

		// Pass 4:
		// The types are now complete (including members). Update the datatype
		// manager.

		updateTypeManager(classTypeMap.values().stream().toArray(DataType[]::new), true);
		Msg.info(this, "Type manager updated.");

		// Pass 5:
		// Update methods/vftables

		classTypeMap.forEach((ooaType, ghidraType) -> {
			analyzeMethods(ghidraType, ooaType.getMethods().orElse(null));
			analyzeVftables(ghidraType, ooaType.getVftables().orElse(null));
		});
		Msg.info(this, "Methods and virtual functions analyzed.");
		monitor.incrementProgress(1);

		return classTypeMap.size();
	}

	/**
	 * Compare two same-named types. Decide if the Ghidra or OOAnalyzer type should
	 * be used. Currently the selection is based on which type (ghidra or
	 * OOAnalyzer) is better defined. If the OOAnalyzer type is preferred, then
	 * create it.
	 * 
	 * @param ooaType    the OOAnalyzer type
	 * @param ghidraType the current ghidra type
	 * @return a Structure representing the selected type, or empty if no type is
	 *         selected
	 */
	private Optional<Structure> compareTypes(OOAnalyzerType ooaType, Structure ghidraType) {

		// Decide whether to organize the type in the OOAnalyzer category. If the ghidra
		// type is not found, then always use OOAnalyzer category

		CategoryPath categoryPath = ooanalyzerCategory;
		if (!this.useOOAnalyzerNamespace && ghidraType != null) {
			categoryPath = ghidraType.getCategoryPath();
		}

		if (ooaType != null && ghidraType != null) {

			if (ghidraType.getLength() == ooaType.getSize()) {

				// Favor the OOA class if it has more elements
				List<Member> members = ooaType.getMembers().orElse(null);
				if (members != null && members.size() >= ghidraType.getNumComponents()) {
					return Optional.of(
							new StructureDataType(categoryPath, ooaType.getNameWithoutNamespace(), ooaType.getSize()));

				}
				// Ghidra type better defined
				return Optional.of(ghidraType);
			}

			// Otherwise the larger type wins. The assumption is that that bigger types
			// are generally better than smaller ones
			return Optional.of((ghidraType.getLength() > ooaType.getSize()) ? ghidraType
					: new StructureDataType(categoryPath, ooaType.getNameWithoutNamespace(), ooaType.getSize()));

		} else if (ooaType != null) {
			// Only found OOA type
			return Optional
					.of(new StructureDataType(categoryPath, ooaType.getNameWithoutNamespace(), ooaType.getSize()));

		} else if (ghidraType != null) {
			// Only found Ghidra type
			return Optional.of(ghidraType);
		}

		Msg.error(this, "Could not compare two null types");

		// both submitted types are null. This should not happen
		return Optional.empty();
	}

	/**
	 * There are cases where Ghidra infers a typename from a method somehow. This
	 * method attempts to use that information.
	 * 
	 * @param ooaType the data structure information to scan for a better name
	 * @return The data type found, or empty
	 */
	private Optional<DataType> scanMethodsForType(OOAnalyzerType ooaType) {

		try {
			if (ooaType == null) {
				return Optional.empty();
			}

			// Accumulate all the defined Functions found for this type by
			// OOAnalyzer.
			//
			// Unfortunately, functions are not comparable so we must specify a
			// comparator.
			// For the sake of this comparison, let's assume functions are equal
			// if they
			// share an entry address

			TreeSet<Function> methodSet = new TreeSet<>(new Comparator<Function>() {
				@Override
				public int compare(Function f1, Function f2) {
					return f1.getEntryPoint().compareTo(f2.getEntryPoint());
				}
			});

			// Scan methods for class names
			Optional<List<Method>> optMethods = ooaType.getMethods();
			if (optMethods.isPresent()) {

				List<Method> methods = optMethods.get();

				for (Method m : methods) {

					try {
						Function f = flatApi.getFunctionAt(flatApi.toAddr(Integer.parseInt(m.getEa(), 16)));
						if (f != null) {
							methodSet.add(f);
						} else {
							Msg.error(this, "No function at " + m.getEa());
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}

			// Scan vftables for class names
			Optional<List<Vftable>> optVtables = ooaType.getVftables();

			if (optVtables.isPresent()) {

				List<Vftable> vftables = optVtables.get();

				for (Vftable vtab : vftables) {
					if (vtab != null) {
						Optional<List<Vfentry>> optEntries = vtab.getEntries();
						optEntries.ifPresent(vftEntries -> {
							for (Vfentry vf : vftEntries) {
								try {
									Function f = flatApi
											.getFunctionAt(flatApi.toAddr(Integer.parseInt(vf.getEa(), 16)));
									if (f != null) {
										methodSet.add(f);
									} else {
										Msg.error(this, "No function at " + vf.getEa());
									}
								} catch (Exception e) {
								}
							}
						});
					}
				}
			}

			// No methods ...
			if (methodSet.isEmpty()) {
				return Optional.empty();
			}

			TreeSet<DataType> candidateTypes = new TreeSet<>(new Comparator<DataType>() {

				@Override
				public int compare(DataType d1, DataType d2) {
					// This comparison may be too strict.
					if (d1 != null && d2 != null) {

						// It turns out that the abstract base class for
						// all data types returns null by
						// default for the universal ID

						UniversalID d1ID = d1.getUniversalID();
						UniversalID d2ID = d2.getUniversalID();

						if (d1ID != null && d2ID != null) {
							if (d1ID.equals(d2ID)) {
								return 0; // match
							}
						}
					}
					return 1;
				}
			});

			// Now check the methods for type based on known object-ness.
			for (Function ghidraMethod : methodSet) {

				if (ghidraMethod == null) {
					continue;
				}

				PrototypeModel convention = ghidraMethod.getCallingConvention();
				if (convention != null
						&& convention.getGenericCallingConvention() == GenericCallingConvention.thiscall) {

					// This is already a thiscall method. Leverage this to
					// determine something about
					// the class type.

					if (ghidraMethod.getParameterCount() > 0) {
						Parameter thisParam = ghidraMethod.getParameter(0);
						if (thisParam != null) {
							candidateTypes.add(DataTypeUtilities.getBaseDataType(thisParam.getFormalDataType()));

						}
					}
				}
			}

			if (candidateTypes.size() == 1) {

				DataType dt = candidateTypes.first();

				// The built-in types seem to be the primative types. We will
				// avoid these

				if (new ClassTypeChecker().isValid(dt)) {
					return Optional.of(dt);
				}

			}
		} catch (Exception e) {
			// So much can go wrong, just give up
		}

		return Optional.empty();
	}

	/**
	 * analyze virtual function tables reported by both Ghidra and OOAnalyzer
	 * 
	 * @param ooaType    the OOAnalyzer type
	 * @param ghidraType The Ghidra type
	 */
	private void analyzeVftables(final Structure ghidraType, final List<Vftable> vftables) {

		Map<Function, Vfentry> functionToVfentryMap = new HashMap<>();

		// These are the accumulated virtual function tables.
		Map<Address, List<Function>> ooaVirtualFunctionTables = new ConcurrentHashMap<>();
		Map<Address, List<Function>> ghdVirtualFunctionTables = new ConcurrentHashMap<>();

		// First, consider what OOAnalyzer says about vftables

		if (vftables != null) {

			for (Vftable ooaVftable : vftables) {
				Address ooaVftAddr = null;

				List<Function> ooaVfFuncList = new ArrayList<>();

				try {
					// Convert the vftable from a list of VfEntry
					// classes to a
					// list of Ghidra Functions.

					ooaVftAddr = flatApi.toAddr(ooaVftable.getEa());

					// The entry list may be null
					List<Vfentry> ooaVfEntryList = ooaVftable.getEntries().get();
					if (ooaVfEntryList != null && !ooaVfEntryList.isEmpty()) {

						ooaVfFuncList = ooaVfEntryList.stream()
								// We want functions
								.map(entry -> flatApi.getFunctionAt(flatApi.toAddr(entry.getEa())))
								// A list of functions
								.collect(Collectors.toList());

						// Save the mapping of Function to VfEtnry
						// because there is more information in
						// the VfEntry
						for (int i = 0; i < ooaVfEntryList.size(); i++) {
							functionToVfentryMap.putIfAbsent(ooaVfFuncList.get(i), ooaVfEntryList.get(i));
						}
					}
				} catch (Exception e) {
					// Just move on to the next entry
				}

				if (ooaVftAddr != null && !ooaVfFuncList.isEmpty()) {
					ooaVirtualFunctionTables.put(ooaVftAddr, ooaVfFuncList);
				}
			}
		}

		Symbol ghidraClsSymbol = classSymbolMap.getOrDefault(ghidraType, null);

		// The class is indeed defined. See if it includes a vftable in its
		// children
		if (ghidraClsSymbol != null) {

			// Accumulate the vftable symbols that are defined
			Iterable<Symbol> symitr = () -> symbolTable.getChildren(ghidraClsSymbol);
			List<Symbol> vftableSymbols = StreamSupport.stream(symitr.spliterator(), true)
					// "vftable is the default name for virtual func table
					// symbols"
					.filter(child -> "vftable".equals(child.getName()))
					// improve vftable label
					.map(child -> {
						try {
							child.setName(child.getName() + "_" + child.getAddress(), SourceType.USER_DEFINED);
						} catch (Exception x) {
						}
						return child;
					})
					// Make it a list
					.collect(Collectors.toList());

			// If virtual function tables found, accumulate the methods therein
			if (vftableSymbols != null && !vftableSymbols.isEmpty()) {
				for (Symbol vft : vftableSymbols) {

					Data ghidraVft = flatApi.getDataAt(vft.getAddress());

					if (ghidraVft == null) {
						Msg.warn(this, "Could not analyze virtual functions at " + vft.getAddress());
						continue;
					}

					List<Function> ghidraVfList = new ArrayList<>(ghidraVft.getNumComponents());

					for (int offset = 0; offset < ghidraVft.getNumComponents(); offset++) {
						Data vfuncPtr = ghidraVft.getComponent(offset);

						if (vfuncPtr != null && vfuncPtr.isPointer()) {

							Address addr = flatApi.toAddr(vfuncPtr.getDefaultValueRepresentation());
							if (addr != null) {
								Function vf = flatApi.getFunctionAt(addr);
								if (vf != null) {
									ghidraVfList.add(vf);
									functionToVfentryMap.putIfAbsent(vf, null);
								}
							}
						}
					}

					ghdVirtualFunctionTables.put(vft.getAddress(), ghidraVfList);
				}
			}

			// The following iterates over the entries of the ghidra virtual
			// function table. For each entry, merge (key, value, remapper) is called on
			// on the OOA virtual function tables creating the entry under the key and
			// value if the key didn't exist or it will invoke the given remapping function
			// if they already existed. This function takes the 2 lists to merge, which in
			// this case, are first added to a TreeSet to ensure both unique and sorted
			// elements and converted back into a list. In other words, add the Ghidra
			// entries to the OOA entries only if the OOA entries don't exist or are
			// different

			ghdVirtualFunctionTables.entrySet().parallelStream()
					.forEach(e -> ooaVirtualFunctionTables.merge(e.getKey(), e.getValue(), (v1, v2) -> {
						Set<Function> set = new HashSet<>(v1);
						set.addAll(v2);
						return new ArrayList<Function>(set);
					}));

			// There are virtual functions, but no vftable_X symbol defined
			if (!ooaVirtualFunctionTables.isEmpty() && vftableSymbols == null) {
				vftableSymbols = new ArrayList<>();
				for (var vtableAddr : ooaVirtualFunctionTables.keySet()) {

					Namespace clsScope = symbolTable.getNamespace(ghidraClsSymbol.getName(),
							ghidraClsSymbol.getParentNamespace());

					Optional<Symbol> optSym = createNewLabel(vtableAddr, "vtable_" + vtableAddr.toString(), clsScope,
							SourceType.USER_DEFINED);

					if (optSym.isPresent()) {
						vftableSymbols.add(optSym.get());
					}
				}
			}

			applyVirtualFunctons(ghidraType, functionToVfentryMap);

			ooaVirtualFunctionTables.forEach((vtableAddr, vfuncList) -> {

				if (vftableMap.containsKey(vtableAddr)) {

					Structure vftableStruct = vftableMap.get(vtableAddr);
					populateVftable(vftableStruct, vfuncList);
					updateTypeManager(vftableStruct, true);

					try {
						flatApi.removeDataAt(vtableAddr);
						flatApi.createData(vtableAddr, vftableStruct);
					} catch (Exception e) {
						Msg.warn(this, "Could not create virtual function table at " + vtableAddr);
					}
				} else {
					Msg.warn(this, "There is no virtual function table at address " + vtableAddr.toString());
				}

			});
		}
	}

	/**
	 * Associate ghidra symbols with data types for a given class. This method also
	 * reorganizes the symbol table so that things touched by OOAnalyzer are under
	 * the OOAnalyzer namespace.
	 * 
	 * @param ghidraClassType the type to ass
	 */
	private void selectClassSymbol(Structure ghidraClassType) {

		if (ghidraClassType != null) {
			for (var sym : symbolTable.getDefinedSymbols()) {
				if (sym.getSymbolType() == SymbolType.CLASS) {

					if (sym.toString().equalsIgnoreCase(ghidraClassType.getName())) {

						classSymbolMap.put(ghidraClassType, sym);

						try {

							Namespace parentNs = sym.getParentNamespace();

							if (this.useOOAnalyzerNamespace && !parentNs.equals(this.ooanalyzerNamespace)) {

								// Can't move the global namespace under OOAnalyzer, so just move the symbol
								if (!(parentNs instanceof GlobalNamespace)) {
									parentNs.setParentNamespace(this.ooanalyzerNamespace);
								} else {
									sym.setNamespace(this.ooanalyzerNamespace);
								}
							}
						} catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
							// Not sure what to do here ...
						}

						return;
					}
				}
			}

			// No known ghidra type, create a new symbol in the OOAnalyzer namespace
			try {

				GhidraClass newSymCls = symbolTable.createClass(this.ooanalyzerNamespace,
						ghidraClassType.getDisplayName(), SourceType.USER_DEFINED);

				classSymbolMap.put(ghidraClassType, newSymCls.getSymbol());

			} catch (DuplicateNameException | InvalidInputException e) {
				// Nothing to do here, the name exists
			}
		}
	}

	/**
	 * Apply a virtual function table.
	 * 
	 * @param ghidraType              the Ghidra data type.
	 * @param ghidraVirtualMethodInfo information on known virtual functions.
	 */
	private void applyVirtualFunctons(Structure ghidraType, Map<Function, Vfentry> ghidraVirtualMethodInfo) {

		// This is entirely about adding things to the symbol table.

		if (ghidraType != null) {
			ghidraVirtualMethodInfo.forEach((vfunc, vfEntry) -> {

				// Assume a normal method until proven
				// otherwise
				MethodType mType = MethodType.METHOD;

				if (vfEntry != null && vfEntry.getType().equals("dtor")) {
					mType = MethodType.VIRTUAL_DTOR;
				}

				try {
					applyClassToMethod(ghidraType, vfunc, mType);
				} catch (Exception e) {
					e.printStackTrace();
				}

				// Create a new virtual function in the proper class namespace. Re-lableing the
				// function in a class namespace will make it appear in the symbol table.
				// However, this gets confusing in the cases where virtual functions appear in
				// multiple tables.

				Symbol ghidraClassSymbol = classSymbolMap.getOrDefault(ghidraType, null);
				Namespace clsScope = null;
				if (ghidraClassSymbol != null) {

					clsScope = symbolTable.getNamespace(ghidraClassSymbol.getName(),
							ghidraClassSymbol.getParentNamespace());
				}

				if (vfunc!=null) {
					// We can have multiple labels in the symbol table
					String label = vfunc.getSymbol().getName(false);
					if (!label.startsWith("VIRT_")) {
						label = "VIRT_" + vfunc.getName();
					}
					createOrUpdateLabel(vfunc.getEntryPoint(), label, clsScope, SourceType.USER_DEFINED);
				}
				else {
					Msg.warn(this, "Could not create label for function: " + vfEntry.getName());
				}
			});
		}
	}

	/**
	 * Add functions to the virtual function table as members. Create a new type
	 * containing the proper function pointers for virtual functions.
	 * 
	 * @param vftableTypeName the virtual table structure to populate
	 * @param vfuncs          the list of functions to add
	 * @return
	 */
	private void populateVftable(Structure vftableStruct, List<Function> vfuncs) {

		Integer pointerSize = null;
		if (dataTypeMgr != null) {
			pointerSize = dataTypeMgr.getDataOrganization().getPointerSize();
		} else {
			pointerSize = DataOrganizationImpl.getDefaultOrganization().getPointerSize();
		}

		int offset = 0;
		for (Function vf : vfuncs) {
			if (vf != null) { 
				FunctionDefinitionDataType vfDef = new FunctionDefinitionDataType(ooanalyzerVirtualFunctionsCategory,
						vf.getName(), vf.getSignature());
				Pointer pvfDt = PointerDataType.getPointer(vfDef, dataTypeMgr);
	
				vftableStruct.insertAtOffset(offset, pvfDt, pvfDt.getLength(), vf.getName() + "_" + String.valueOf(offset),
						"virtual function table entry.");
			} 
			offset += pointerSize;
		}
	}

	/**
	 * Utility function to find the offset of a vfptr install instruction.
	 * Currently, this method is unused
	 */
	@SuppressWarnings("unused")
//	private Optional<Long> findVptrOffset(Symbol vft) {
//		if (vft.hasReferences()) {
//			for (Reference r : flatApi.getReferencesTo(vft.getAddress())) {
//				Address from = r.getFromAddress();
//				Instruction insn = flatApi.getInstructionAt(from);
//
//				if (insn != null && insn.getNumOperands() == 2) {
//
//					Object op0[] = insn.getOpObjects(0);
//					// [REG + NNN], VFT
//					if (op0.length == 2) {
//						if (op0[0] instanceof Register && op0[1] instanceof Scalar) {
//							return Optional.of(((Scalar) op0[1]).getUnsignedValue());
//
//						}
//					} else if (op0.length == 1) {
//						// [REG], VFT
//						return Optional.of(Long.valueOf(0));
//					}
//				}
//			}
//		}
//		return Optional.empty();
//	}

	/**
	 * Use the OOAnalayzer information to select the correct arraytype for the
	 * vftable.
	 * 
	 * @param ooaType    The OOAnalyzer data structure
	 * @param ghidraType The Ghidra data structure
	 * @param vfptr      the virtual function pointer to analyze
	 * @return the data type for the vfptr or an empty value
	 */
	private Optional<DataType> analyzeVfptrType(OOAnalyzerType ooaType, Structure ghidraType, Member vfptr) {

		if (ooaType.getVftables().isPresent()) {
			List<Vftable> vftables = ooaType.getVftables().get();

			Optional<Vftable> vtabOpt = vftables.stream()
					// Get this vftable
					.filter(vft -> vft.getVfptr() == vfptr.getOffset())
					// short circuit search
					.findFirst();

			if (vtabOpt.isPresent()) {
				Vftable vtable = vtabOpt.get();

				String vftableName = ghidraType.getName() + "::vftable_"
						+ Long.toHexString(vtable.getEa()).toLowerCase();

				if (ooaType.getMembers().isPresent()) {
					List<Member> members = ooaType.getMembers().get();
					Optional<Member> pOpt = members.stream()
							// Get this vftable
							.filter(mbr -> mbr.getOffset() == vfptr.getOffset() && mbr.getStruc().isPresent())
							// short circuit search
							.findFirst();
					
					if (pOpt.isPresent()) {
						Member p = pOpt.get();
						vftableName = ghidraType.getName() + "::" + p.getName() + "::vftable_"
								+ Long.toHexString(vtable.getEa()).toLowerCase();
						// We have a parent meaning this table will be overwritten
					}
				}

				Structure vftableStruct = new StructureDataType(ooanalyzerCategory,
						ghidraType.getName() + "::vftable_" + Long.toHexString(vtable.getEa()).toLowerCase(), 0);

				vftableMap.put(flatApi.toAddr(vtable.getEa()), vftableStruct);

				// actually need to return a pointer to the data type (which is likely an array)

				return Optional.of(PointerDataType.getPointer(vftableStruct, dataTypeMgr));
			}
		}

		// Go to the default type, which is LPVOID
		return findDataType(MemberType.VFPTR.ghidraTypeName());
	}

	/**
	 * Analyze class members.
	 * 
	 * @param ooaType    The type found by OOAnalyzer
	 * @param ghidraType The associated ghidra types
	 */
	private void analyzeMembers(OOAnalyzerType ooaType, Structure ghidraType) {

		if (!ooaType.getMembers().isPresent() || !classSymbolMap.containsKey(ghidraType)) {
			return;
		}

		// If there are members for this type, process them
		List<Member> members = ooaType.getMembers().get();
		for (Member mbr : members) {

			if (mbr.getOffset() == Member.INVALID_OFFSET) {
				Msg.error(this, "Cannot add member " + mbr.getName() + " due to invalid offset");
				continue;
			}

			DataType mbrType = null;

			if (MemberType.ASCII.jsonTypeName().equals(mbr.getType())) {

				// Strings are represented as "ascii" in the JSON
				// and
				// translated acc
				mbrType = findDataType(MemberType.ASCII.ghidraTypeName()).orElseGet(null);

			} else if (MemberType.STRUC.jsonTypeName().equals(mbr.getType())) {

				String strucName = mbr.getStruc().get();

				// If this type was already compared to the Ghidra
				// type and considered better, then use it

				for (Entry<OOAnalyzerType, Structure> e : classTypeMap.entrySet()) {
					OOAnalyzerType jsonType = e.getKey();

					String jsonDemangledTypeName = jsonType.getDemangledName().orElse("");
					String jsonTypeName = jsonType.getName();
					if (jsonTypeName.equals(strucName) || jsonDemangledTypeName.equals(strucName)) {
						mbrType = e.getValue();
						break;
					}
				}

				if (mbrType == null) {

					// Otherwise use the Ghidra type (if it exists)
					mbrType = findStructure(strucName).orElse(null);
				}

				// Still not found so create a 0-sized dummy
				// structure
				if (mbrType == null) {

					mbrType = new StructureDataType(strucName, 0);
				}

				if (mbr.isParent()) {
					mbrType.setDescription("Parent class.");
				} else {
					mbrType.setDescription("Component (member) class.");
				}

			} else if (mbr.getName().indexOf(MemberType.VFPTR.jsonTypeName()) != -1) {

				// vfptrs are a little different in terms of type.
				// Also "vfptr_" will appear in the name

				mbrType = analyzeVfptrType(ooaType, ghidraType, mbr).orElseGet(null);

			} else {

				// qword/dword/word/byte are directly translated as
				// builtin types

				mbrType = findDataType(mbr.getType()).orElseGet(null);
			}
			if (mbrType == null) {

				// If the member is *still* null just make it an
				// undefined
				// 0-sized type
				mbrType = Undefined.getUndefinedDataType(0);
			}

			// There is a chance that the json member type (found by
			// OO Analyzer) has a different size/definition than
			// the Ghidra standard type. In this case we will grow
			// the standard type.

			if (ghidraType.getLength() < (mbr.getOffset() + mbrType.getLength())) {
				int amount = (mbr.getOffset() + mbrType.getLength()) - ghidraType.getLength();
				ghidraType.growStructure(amount);
			}

			try {

				String typeName = mbr.getName();

				// If the member type is a structure, then typename reported by OOA may be
				// mangled, so favor the ghidra name. Parents are even really variables anyways.
				if (mbr.getType().equals(MemberType.STRUC.jsonTypeName())) {
					typeName = mbrType.getName();
				}

				// There may be cases where we need to make room for class members by clearing
				// space
				int endOffset = mbr.getOffset() + mbrType.getLength();
				for (int i = 0; i < ghidraType.getNumComponents(); i++) {
					var comp = ghidraType.getComponent(i);
					if (comp.getOffset() >= mbr.getOffset() && comp.getOffset() <= endOffset) {
						ghidraType.clearComponent(i);
					}
				}

				ghidraType.replaceAtOffset(mbr.getOffset(), mbrType, mbrType.getLength(), typeName,
						mbrType.getDescription());

			} catch (IllegalArgumentException iae) {
				Msg.error(this, "Could not add class member " + mbr + " to class " + ghidraType.getDisplayName());
			}
		}
	}

	/**
	 * Update the this pointer type
	 * 
	 * @param ghidraMethod
	 * @param dt
	 * @param parameter
	 * @return
	 */
	private Parameter updateThisPtr(Function ghidraMethod, DataType dt, Parameter parameter) {

		// Non-auto parameters can just be updated
		if (!parameter.isAutoParameter()) {
			try {
				parameter.setDataType(dt, SourceType.USER_DEFINED);
			} catch (InvalidInputException e) {
				Msg.error(this, "Unexpected error setting this pointer type at " + ghidraMethod.getEntryPoint(), e);
			}
			return parameter;
		}

		// Auto generated this pointers require a little more work.
		VariableStorage variableStorage = parameter.getVariableStorage();
		if (variableStorage.getAutoParameterType() == AutoParameterType.THIS) {
			if (dt == null) {
				dt = VariableUtilities.getAutoDataType(ghidraMethod, null, variableStorage);
			}
			try {
				return new AutoParameterImpl(dt, parameter.getOrdinal(), variableStorage, ghidraMethod);
			} catch (InvalidInputException e) {
				Msg.error(this, "Unexpected error during dynamic storage assignment for function at "
						+ ghidraMethod.getEntryPoint(), e);
			}
		}
		return parameter;
	}

	/**
	 * Fix up the prototype to be more OO-ish. This means making the method thiscall
	 * and updating it to return the this pointer if it is a constructor/destructor
	 * 
	 * @param ooClass      the data structure containing the method
	 * @param ghidraMethod the method to apply
	 * @param mType        the method type
	 * 
	 * @throws Exception
	 */
	private void applyClassToMethod(Structure ooClass, Function ghidraMethod, MethodType mType) throws Exception {

		if (ghidraMethod == null || ooClass == null) {
			Msg.warn(this, "Could not update method");
			return;
		}

		Variable returnVar = ghidraMethod.getReturn();
		List<Parameter> newParams = new ArrayList<>(Arrays.asList(ghidraMethod.getParameters()));

		// Constructors/destructors always return themselves, so type
		// everything correctly

		Parameter thisPtr = null;
		DataType thisPtrType = PointerDataType.getPointer(ooClass, dataTypeMgr);
		updateTypeManager(thisPtrType, true);

		// if a this pointer already exists in the form of a 0th param, then update it
		if (newParams.size() > 0) {
			thisPtr = updateThisPtr(ghidraMethod, thisPtrType, newParams.get(0));
			newParams.set(0, thisPtr);
		}

		if (mType == MethodType.CTOR || (mType == MethodType.DTOR || mType == MethodType.VIRTUAL_DTOR)) {

			// Thiscall functions pass the this pointer first. The this
			// pointer will be a pointer to the Ghidra class type

			ghidraMethod.setReturnType(thisPtrType, SourceType.USER_DEFINED);
			returnVar = thisPtr;
		}

		// commit the changes to the method
		ghidraMethod.updateFunction(GenericCallingConvention.thiscall.toString(), returnVar, newParams,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

	}

	/**
	 * Transactionally add a data type.
	 * 
	 * @param dt                the data type to commit.
	 * @param useOOAnalyzerPath Flag for where to add the type
	 */
	private void updateTypeManager(final DataType dt, boolean useOOAnalyzerPath) {
		if (!dataTypeMgr.contains(dt)) {
			if (useOOAnalyzerPath) {
				try {
					if (dt.getCategoryPath().compareTo(ooanalyzerCategory) != 0) {
						dt.setCategoryPath(ooanalyzerCategory);
					}
				} catch (DuplicateNameException e) {
				}
			}
			int tid = dataTypeMgr.startTransaction("T");
			dataTypeMgr.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
			dataTypeMgr.flushEvents();
			dataTypeMgr.endTransaction(tid, true);
		}
	}

	/**
	 * /** Transactionally add an array of data types.
	 *
	 * @param dTypes            The list of data types to commit.
	 * @param useOOAnalyzerPath Flag for where to add the type
	 */
	private void updateTypeManager(final DataType[] dTypes, boolean useOOAnalyzerPath) {

		int tid = dataTypeMgr.startTransaction("T");
		for (var dt : dTypes) {
			if (useOOAnalyzerPath) {
				try {
					if (dt.getCategoryPath().compareTo(ooanalyzerCategory) != 0) {
						dt.setCategoryPath(ooanalyzerCategory);
					}
				} catch (DuplicateNameException e) {
				}
			}
			dataTypeMgr.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		dataTypeMgr.flushEvents();
		dataTypeMgr.endTransaction(tid, true);
	}

	/**
	 * Analyze the methods associated with this type.
	 * 
	 * @param ghidraType The data structure containing methods
	 * @param methods    The list of methods to analyze
	 */
	private void analyzeMethods(Structure ghidraType, List<Method> methods) {

		if (null == methods || !classSymbolMap.containsKey(ghidraType)) {
			return;
		}

		Symbol ghidraTypeSym = classSymbolMap.get(ghidraType);

		for (Method ooaMethod : methods) {

			try {
				Address addr = flatApi.toAddr(Integer.parseInt(ooaMethod.getEa(), 16));

				Function ghidraMethod = flatApi.getFunctionAt(addr);
				if (ghidraMethod == null) {
					Msg.error(this, "Cannot find function at " + addr + " - skipping");
					continue;
				}

				String methodName = ooaMethod.getName();

				// if the ghidra name is not the default auto name, then use it
				if (!ghidraMethod.getName().startsWith(autoFuncNamePrefix)) {
					methodName = ghidraMethod.getName();
				}

				MethodType mType = MethodType.METHOD;

				// Constructors/Destructors have slightly different names
				if (ooaMethod.getType().equals("ctor")) {

					methodName = ghidraType.getName();
					mType = MethodType.CTOR;

				} else if (ooaMethod.getType().equals("dtor")) {

					// Proper C++ means destructors start with '~'
					methodName = "~" + ghidraType.getName();
				}

				Namespace clsNamespace = symbolTable.getNamespace(ghidraTypeSym.getName(),
						ghidraTypeSym.getParentNamespace());

				// Create a new method for this class symbol
				createNewLabel(ghidraMethod.getEntryPoint(), methodName, clsNamespace, SourceType.USER_DEFINED);

				applyClassToMethod(ghidraType, ghidraMethod, mType);

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * Creates a new label, assuming the existing label is the default
	 * 
	 * @param address    The address of the label
	 * @param name       the name to use for the label
	 * @param scope      the namespace for the label
	 * @param sourceType the type of label
	 * 
	 * @return the new symbol for the label or empty if there is an error
	 */
	private Optional<Symbol> createNewLabel(Address address, String name, Namespace scope, SourceType sourceType) {

		if (flatApi.getSymbolAt(address).getSource().equals(SourceType.DEFAULT)) {
			try {
				return Optional.of(symbolTable.createLabel(address, name, scope, sourceType));
			} catch (InvalidInputException e) {
				Msg.info(this, "Invalid input to create label.");
			}
		}
		return Optional.empty();
	}

	/**
	 * Creates a new label regardless of whether the label has been updated. If the
	 * symbol exists, then secondary labels will be added
	 * 
	 * @param address    The address of the label
	 * @param name       the name to use for the label
	 * @param scope      the namespace for the label
	 * @param sourceType the type of label
	 * 
	 * @return the new symbol for the label or empty if there is an error
	 */
	private Optional<Symbol> createOrUpdateLabel(Address address, String name, Namespace scope, SourceType sourceType) {

		try {
			return Optional.of(symbolTable.createLabel(address, name, scope, sourceType));
		} catch (InvalidInputException e) {
			Msg.info(this, "Invalid input to create label.");
		}

		return Optional.empty();
	}

	/**
	 * Sanity check to make sure the right JSON is run. If the user opens a JSON
	 * file that doesn't match the program name they are warned.
	 * 
	 * @param jsonName The json file name
	 * @param progName The program name
	 * @return true if the script can continue, false to cancel
	 */
	public static boolean doNamesMatch(String jsonName, String progName) {
		try {
			String baseJsonName = jsonName.split("\\.(?=[^\\.]+$)")[0];
			String baseProgName = progName.split("\\.(?=[^\\.]+$)")[0];
			if (baseJsonName.equalsIgnoreCase(baseProgName) == false) {

				var contDialog = new OptionDialog("Careful",
						"The JSON file name does not match the program name, continue?", "Continue",
						OptionDialog.WARNING_MESSAGE, null);

				contDialog.show();

				return (contDialog.getResult() != OptionDialog.CANCEL_OPTION);

			}
		} catch (Exception x) {
			// Nothing to do ...
		}

		// Assume the user knows what they are doing and allow the script to continue
		return true;
	}

	/**
	 * Load Pharos JSON file.
	 * 
	 * @param jsonFile The JSON file
	 * @return a list of parsed types
	 * @throws FileNotFoundException
	 */
	// public static Optional<OOAnalyzerClassList> parseJsonFile(File jsonFile) {
	public static Optional<List<OOAnalyzerType>> parseJsonFile(File jsonFile) {

		final String nameJSONString = "Name";
		final String sizeJSONString = "Size";
		final String demangledNameJSONString = "DemangledName";
		final String membersJSONString = "Members";
		final String methodsJSONString = "Methods";
		final String vftablesJSONString = "Vftables";

		if (jsonFile != null) {

			JsonReader reader = null;

			try {

				reader = new JsonReader(new FileReader(jsonFile));

				// This is a custom serializer to populate the namespace from the demangled name
				// (if possible)

				JsonDeserializer<OOAnalyzerType> deserializer = new JsonDeserializer<OOAnalyzerType>() {

					@Override
					public OOAnalyzerType deserialize(JsonElement json, Type typeOfT,
							JsonDeserializationContext context) throws JsonParseException {
						
						JsonObject jsonObject = json.getAsJsonObject();

						String namespace = "";
						String demangledName = "";
						String name = jsonObject.get(nameJSONString).getAsString();
						List<Member> mbrList = null;
						List<Method> mthList = null;
						List<Vftable> vftList = null;

						Integer size = null;
						try {
							size = Integer.parseInt(jsonObject.get(sizeJSONString).getAsString());
						} catch (NumberFormatException nfx) {

						}

						DemangledObject demangledObj;
						try {
							Demangler demangler = new MicrosoftDemangler();

							// Attempt to demangle the name and namespace first using Ghidra's approach
							demangledObj = demangler.demangle(name, true);
							if (demangledObj != null) {
								demangledName = demangledObj.toString().replace("\n", "\\n");
								namespace = demangledObj.getNamespace().toNamespace();
							} else {
								JsonElement jElm = jsonObject.get(demangledNameJSONString);
								if (jElm != null) {
									demangledName = jElm.getAsString();
									namespace = OOAnalyzer.getNamespace(demangledName);
								}
							}

						} catch (Exception e) {
							e.printStackTrace();
						}

						Gson g = new Gson();

						Type mbrListType = new TypeToken<List<Member>>() {
						}.getType();
						try {
							mbrList = g.fromJson(jsonObject.get(membersJSONString), mbrListType);
						} catch (JsonSyntaxException | IllegalStateException mbrx) {
							mbrList = null;
						}

						Type mthListType = new TypeToken<List<Method>>() {
						}.getType();
						try {
							mthList = g.fromJson(jsonObject.get(methodsJSONString), mthListType);
						} catch (JsonSyntaxException | IllegalStateException mthx) {
							mthList = null;
						}

						Type vftListType = new TypeToken<List<Vftable>>() {
						}.getType();
						try {
							vftList = g.fromJson(jsonObject.get(vftablesJSONString), vftListType);
						} catch (JsonSyntaxException | IllegalStateException vftx) {
							vftList = null;
						}

						return new OOAnalyzerType(name, demangledName, namespace, size, mbrList, mthList, vftList);
					}
				};

				GsonBuilder gsonBuilder = new GsonBuilder();
				gsonBuilder.registerTypeAdapter(OOAnalyzerType.class, deserializer);
				Gson gson = gsonBuilder.excludeFieldsWithoutExposeAnnotation().create();
				OOAnalyzerClassList types = gson.fromJson(reader, OOAnalyzerClassList.class);

				return Optional.of(types.getOOAnalyzerClassTypes());

			} catch (Exception x) {
				Msg.warn(OOAnalyzer.class, "There was a problem loading " + jsonFile);

			} finally {
				try {
					if (reader != null) {
						reader.close();
					}
				} catch (IOException iox) {

				}
			}
		}
		return Optional.empty();
	}

	/**
	 * Parse the namespace from the type name
	 * 
	 * @param name to lookup
	 * @return the namespace of the empty string if namespace cannot be found
	 */
	private static String getNamespace(String name) {

		int level = 0;
		StringCharacterIterator i = new StringCharacterIterator(name);
		char ch = i.last();
		while (ch != CharacterIterator.DONE) {
			switch (ch) {
			case '>':
				level++;
				break;
			case '<':
				level--;
				break;
			case ':':
				if (level == 0) {
					ch = i.previous();
					if (ch == ':') {
						return name.substring(0, i.getIndex());
					}
					ch = i.next();
				}
			}
			ch = i.previous();
		}
		return "";
	}
}
