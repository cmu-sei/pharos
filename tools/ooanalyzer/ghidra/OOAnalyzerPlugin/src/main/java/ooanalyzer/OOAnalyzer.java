/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/

package ooanalyzer;

import java.io.PrintWriter;
import java.io.StringWriter;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.text.StringCharacterIterator;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.function.Supplier;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.IntStream;
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
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;

import ghidra.app.util.demangler.CharacterIterator;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemangledType;
import ghidra.app.util.demangler.Demangler;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;
import ghidra.app.util.NamespaceUtils;
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
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ooanalyzer.jsontypes.Member;
import ooanalyzer.jsontypes.Method;
import ooanalyzer.jsontypes.OOAnalyzerJsonRoot;
import ooanalyzer.jsontypes.OOAnalyzerClassType;
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
  public static final String ooanalyzerCategoryString = "/OOAnalyzer";
  public static final CategoryPath ooanalyzerCategory = new CategoryPath(ooanalyzerCategoryString);
  public static final String ooanalyzerVirtualFunctionCategoryString = ooanalyzerCategoryString + "/VirtualFunctions";
  private final CategoryPath ooanalyzerVirtualFunctionsCategory = new CategoryPath(ooanalyzerVirtualFunctionCategoryString);

  // by default organize new data types / symbols in the OOAnalyzer namespace for
  // clarity on what changed.
  private Boolean useOOAnalyzerNamespace = true;
  private Namespace ooanalyzerNamespace = null;

  private final String autoFuncNamePrefix = "FUN_";

  // keep track of virtual function tables
  private HashMap<Address, Structure> vftableMap = new HashMap<>();

  // This is a mapping of the JSON OOAnalyzer type to the selected Ghidra type
  private HashMap<OOAnalyzerClassType, Structure> classTypeMap = new HashMap<>();

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
    VFTPTR {
      @Override
        public String jsonTypeName() {
        return "vftptr";
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
   * Wrapper to call allowSwingToProcessEvents, which moved
   * after 9.0.4
   */
  public void allowSwingToProcessEvents() {
    Class c = null;
    try {
      c = Class.forName("ghidra.util.Swing");
    } catch (ClassNotFoundException e) {
      try {
        c = Class.forName("ghidra.util.SystemUtilities");
      } catch (ClassNotFoundException e2) {}
    }

    try
    {
      c.getDeclaredMethod("allowSwingToProcessEvents").invoke(this);
    } catch (Exception e) {
      Msg.warn(this, "Unable to locate allowSwingToProcessEvents. The GUI may be irresponsive.");
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
  public static int execute(Collection<OOAnalyzerClassType> ooaClassList, final Program prog, Boolean useOOAnalyzerNamespace) {

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

  private String normalizeName(String name) {
    return name.replaceAll("::", "/");
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
      String normalizedGhidraName = normalizeName (struct.getPathName());

      // Sometimes the ghidra path name starts with '/'
      if (normalizedGhidraName.equalsIgnoreCase(normalizedName)
          || normalizedGhidraName.equalsIgnoreCase("/" + normalizedName)) {

        return Optional.of(struct);
      }
    }

    return Optional.empty();
  }

  /**
   * Find a data type by size
   *
   * @param size the size to the type to find
   * @return the found data type or empty
   */
  private Optional<DataType> findDataType(int size) {

    String t = null;
    switch (size) {
        case 1: t = "/byte"; break;
        case 2: t = "/word"; break;
        case 4: t = "/dword"; break;
    }

    if (t == null) {
      return Optional.empty();
    } else {
      return Optional.ofNullable (dataTypeMgr.getDataType(t));
    }
  }

  /**
   * Parse and apply the OOAnanlyzer recoverd JSON classes to Ghidra.
   *
   * @param structs The list of structures parsed from the JSON file
   * @return true on success, false otherwise
   */
  public int analyzeClasses(Collection<OOAnalyzerClassType> typeList) {

    if (typeList == null) {
      return 0;
    }

    if (!dataTypeMgr.isUpdatable()) {
      return 0;
    }

    // List<OOAnalyzerClassType> typeList = structs.getOOAnalyzerClassTypes();

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
        Msg.warn (this, "Unable to create namespace: " + e.toString ());
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

    monitor.setMessage("Type selection");
    monitor.initialize(typeList.size ());

    // Pass 1:
    // Decide which name and type to use

    typeList
      .stream ()
      .takeWhile (type -> !monitor.isCancelled ())
      .forEach(ooaType -> {
          monitor.incrementProgress(1);
          allowSwingToProcessEvents();

          // There was class name information in the ghidra-defined methods, try to
          // use it
          Optional<DataType> optType = scanMethodsForType(ooaType);

          optType.ifPresent(t -> ooaType.setName(t.getName()));

          // Attempt to use the ghidra-defined structure name. If there is no structure
          // name then we'll go with the OOAnalyzer type

          String ooaTypeName = ooaType.getDemangledName().orElse(ooaType.getName());

          Structure ghidraType = findStructure(ooaTypeName).orElse(null);

          Msg.trace (this, "found ghidra type " + ooaTypeName + ": " + ghidraType);

          Structure selectedType = selectType(ooaType, ghidraType);

          Msg.trace (this, "Selected " + selectedType.toString () + " for type " + ooaTypeName);
          classTypeMap.put(ooaType, selectedType);
        });

    if (monitor.isCancelled ()) return 0;
    Msg.info(this, classTypeMap.size() + " types selected out of " + typeList.size()
             + " defined in OOAnalyzer JSON file.");
    monitor.initialize(classTypeMap.size ());
    monitor.setMessage("Associating symbols with classes");

    // Pass 2:
    // Associate symbols with the classes

    classTypeMap
      .entrySet ()
      .stream ()
      .takeWhile (entry -> !monitor.isCancelled ())
      .forEach(entry -> {
          var ooaType = entry.getKey ();
          var ghidraType = entry.getValue ();
          monitor.incrementProgress(1);
          allowSwingToProcessEvents();

          if (ghidraType != null) {
            selectClassSymbol(ooaType, ghidraType);
          } else {
            Msg.warn(this, "There is no type defined for " + ooaType.getDemangledName().orElse(ooaType.getName()));
          }
        });

    if (monitor.isCancelled ()) return 0;
    Msg.info(this, "Symbol table updated.");
    monitor.initialize(classTypeMap.size ());
    monitor.setMessage("Updating symbol table");

    // Pass 3:
    // Fill in the members. This will update the types, but not commit to
    // the type manager. The reason the types are created in a separate pass
    // is because some members themselves may be class types

    classTypeMap
      .entrySet ()
      .stream ()
      .takeWhile (entry -> !monitor.isCancelled ())
      .forEach(entry -> {
          var ooaType = entry.getKey ();
          var ghidraType = entry.getValue ();
          monitor.incrementProgress(1);
          allowSwingToProcessEvents();
          ghidraType.setDescription("C++ Class updated via OOAanalyzer.");
          analyzeMembers(ooaType, ghidraType);
        });
    if (monitor.isCancelled ()) return 0;
    Msg.info(this, "Type definition complete.");
    monitor.initialize(classTypeMap.size ());
    monitor.setMessage("Updating datatype manager");

    // Pass 4:
    // The types are now complete (including members). Update the datatype
    // manager.

    var ghidraTypeArray = classTypeMap
      .values ()
      .stream ()
      .takeWhile (entry -> !monitor.isCancelled ())
      .toArray(DataType[]::new);
    if (monitor.isCancelled ()) return 0;
    allowSwingToProcessEvents();
    updateTypeManager(ghidraTypeArray, useOOAnalyzerNamespace);
    if (monitor.isCancelled ()) return 0;
    Msg.info(this, "Type manager updated.");
    monitor.initialize(classTypeMap.size ());
    monitor.setMessage("Updating methods and vftables");

    // Pass 5:
    // Update methods/vftables

    classTypeMap
      .entrySet ()
      .stream ()
      .takeWhile (entry -> !monitor.isCancelled ())
      .forEach(entry -> {
          var ooaType = entry.getKey ();
          var ghidraType = entry.getValue ();
          monitor.incrementProgress(1);
          allowSwingToProcessEvents();
          analyzeMethods(ghidraType, ooaType.getMethods());
          analyzeVftables(ghidraType, ooaType.getVftables());
        });
    if (monitor.isCancelled ()) return 0;
    Msg.info(this, "Methods and virtual functions analyzed.");

    return classTypeMap.size();
  }

  private CategoryPath getCategoryPathFromClass (OOAnalyzerClassType ooaType) {

    String n = useOOAnalyzerNamespace ? ooanalyzerCategoryString : "";

    Optional<String> ns = ooaType.getNamespace ();
    if (ns.isPresent ()) {
      n = n + "/" + normalizeName (ns.get ());
    }

    Msg.debug (this, "Final category path name: " + n);

    return new CategoryPath (n);
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
  private Structure selectType(OOAnalyzerClassType ooaType, Structure ghidraType) {

    // Decide whether to organize the type in the OOAnalyzer category. If the ghidra
    // type is not found, then always use OOAnalyzer category

    if (ooaType != null && ghidraType != null) {

      Msg.trace (this, "Both ooa and ghidra types defined");

      if (ghidraType.getLength() == ooaType.getSize()) {

        // Favor the OOA class if it has more elements
        Collection<Member> members = ooaType.getMembers();
        if (members.size() >= ghidraType.getNumComponents()) {
          Msg.trace (this, "OOA has more members");
          return new StructureDataType(getCategoryPathFromClass (ooaType),
                                       ooaType.getNameWithoutNamespace(),
                                       ooaType.getSize());

        }
        // Ghidra type better defined
        Msg.trace (this, "Ghidra has more members");
        return ghidraType;
      }

      // Otherwise the larger type wins. The assumption is that that bigger types
      // are generally better than smaller ones
      var ghidraBigger = ghidraType.getLength() >= ooaType.getSize();
      Msg.trace (this, "Ghidra size: " + ghidraType.getLength () + " OOA size: " + ooaType.getSize ());
      return ghidraBigger
        ? ghidraType
        : new StructureDataType(getCategoryPathFromClass (ooaType),
                                ooaType.getNameWithoutNamespace(),
                                ooaType.getSize());

    } else if (ooaType != null) {
      // Only found OOA type
      return new StructureDataType(getCategoryPathFromClass (ooaType),
                                   ooaType.getNameWithoutNamespace(),
                                   ooaType.getSize());

    } else if (ghidraType != null) {
      // Only found Ghidra type
      return ghidraType;
    }

    Msg.error(this, "Could not compare two null types");

    // both submitted types are null. This should not happen
    throw new IllegalArgumentException ("Could not compare two null types");
  }

  // Get (or create if needed) a function at at address.
  private Function getOrCreateFunction(Address addr, String name)  {

    // It's unclear what might throw here, but Cory didn't want to removed the try catch
    // without undeerstanding more about what motivated its inclusion in the first place.
    try {
      Function ghidraMethod = flatApi.getFunctionAt(addr);
      if (ghidraMethod != null) {
        return ghidraMethod;
      }

      // See if this address is a function pointer.
      Data data = program.getListing().getDataAt(addr);
      if (data != null && data.isPointer()) {
        // If it is, what does it point to?
        Address pointed_to = (Address) data.getValue();
        // Msg.info(this, "data points to " + pointed_to.toString("0x"));

        // If it points to something external, then it's basically an import, and we don't need
        // to create a function for this address.
        if (program.getExternalManager().getExternalLocations(pointed_to).hasNext()) {
          return null;
        }
      }

      ghidraMethod = flatApi.createFunction(addr, name);
      if (ghidraMethod == null) {
        Msg.error(this, "Unable to create function at " + addr.toString("0x") + " - skipping");
      }

      return ghidraMethod;
    }
    catch (Exception e) {
      Msg.error (this, "Exception occurred while creating function: " + e.toString());
      return null;
    }
  }

  /**
   * There are cases where Ghidra infers a typename from a method somehow. This
   * method attempts to use that information.
   *
   * @param ooaType the data structure information to scan for a better name
   * @return The data type found, or empty
   */
  private Optional<DataType> scanMethodsForType(OOAnalyzerClassType ooaType) {

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
      Collection<Method> methods = ooaType.getMethods();
      for (Method m : methods) {

        Address mAddr = flatApi.toAddr(m.getEa ());
        Function f = getOrCreateFunction(mAddr, m.getName());
        if (f != null) {
          methodSet.add(f);
        }
        else {
          // Errors should have been generated by getOrCreateFunction.
        }
      }

      // Scan vftables for class names
      // Collection<Vftable> vftables = ooaType.getVftables ();
      // for (Vftable vtab : vftables) {
      //   if (vtab != null) {
      //     Collection<Vfentry> vftEntries = vtab.getEntries();
      //     for (Vfentry vf : vftEntries) {
      //       try {
      //         Function f = flatApi
      //           .getFunctionAt(flatApi.toAddr(Integer.parseInt(vf.getEa(), 16)));
      //         if (f != null) {
      //           methodSet.add(f);
      //         } else {
      //           Msg.error(this, "No function at " + vf.getEaStr());
      //         }
      //       } catch (Exception e) {
      //       }
      //     }
      //   }
      // }

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
      Msg.warn (this, "Something bad happened with types: " + e.toString ());
      // So much can go wrong, just give up
    }

    return Optional.empty();
  }

  /**
   * analyze virtual function tables reported by both Ghidra and OOAnalyzer
   *
   * @param ooaType    the OOAnalyzer type
   * @param ghidraClassType The Ghidra type
   */
  private void analyzeVftables(final Structure ghidraClassType, final Collection<Vftable> vftables) {

    // These are the accumulated virtual function tables.
    Map<Address, List<Optional<Function>>> ooaVirtualFunctionTables = new ConcurrentHashMap<>();
    Map<Address, List<Optional<Function>>> ghdVirtualFunctionTables = new ConcurrentHashMap<>();

    // First, consider what OOAnalyzer says about vftables

    if (vftables != null) {

      for (Vftable ooaVftable : vftables) {

        // Make sure that vftableMap is populated, which we use below
        getOrMakeVftableType(ooaVftable, ghidraClassType);

        Address ooaVftAddr = null;

        List<Optional<Function>> vftableEntries = new ArrayList<Optional<Function>> ();

        try {
          // Convert the vftable from a list of VfEntry classes to a list of Ghidra Functions.

          ooaVftAddr = flatApi.toAddr(ooaVftable.getEa());

          // The entry list may be null
          vftableEntries = IntStream.range(0, ooaVftable.getLength())
            .map(n -> 4*n)
            // Compute address of vftable entry
            .mapToLong(n -> n + ooaVftable.getEa ())
            .boxed ()
            // Read pointer from entry
            .map (addr -> {
                try {
                  return Optional.of (flatApi.getInt (flatApi.toAddr (addr)));
                } catch (ghidra.program.model.mem.MemoryAccessException e) {
                  Msg.warn (this, "Unable to read vftable entry at " + addr);
                  return Optional.empty ();
                }
              })
            // What if there is no function?
            .map (addropt -> addropt.map(addr -> flatApi.getFunctionAt(flatApi.toAddr ((Integer) addr))))
            .collect(Collectors.toList ());
        } catch (Exception e) {
          // Just move on to the next entry
          Msg.warn (this, "Something bad happened when processing vftable entries: " + e.toString ());
        }

        if (ooaVftAddr != null && !vftableEntries.isEmpty()) {
          ooaVirtualFunctionTables.put(ooaVftAddr,
                                       vftableEntries);
        }

      }
    }

    Symbol ghidraClsSymbol = classSymbolMap.getOrDefault(ghidraClassType, null);

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
            } catch (Exception e) {
              Msg.warn (this, "Something bad happened when trying to set the name at " + child.getAddress () + ": " + e.toString ());
            }
            return child;
          })
        // Make it a list
        .collect(Collectors.toList());

      // If virtual function tables found, accumulate the methods therein
      // XXX: Rewrite me.  Do we need to know anything other than the size of the vftable?
      if (vftableSymbols != null && !vftableSymbols.isEmpty()) {
        for (Symbol vft : vftableSymbols) {

          Data ghidraVft = flatApi.getDataAt(vft.getAddress());

          if (ghidraVft == null) {
            Msg.warn(this, "Could not analyze virtual functions at " + vft.getAddress());
            continue;
          }

          List<Optional<Function>> ghidraVfList = new ArrayList<>(ghidraVft.getNumComponents());

          for (int offset = 0; offset < ghidraVft.getNumComponents(); offset++) {
            Data vfuncPtr = ghidraVft.getComponent(offset);

            if (vfuncPtr != null && vfuncPtr.isPointer()) {

              Address addr = flatApi.toAddr(vfuncPtr.getDefaultValueRepresentation());
              if (addr != null) {
                Function vf = flatApi.getFunctionAt(addr);
                if (vf != null) {
                  ghidraVfList.add(Optional.of(vf));
                }
              }
            }
          }

          ghdVirtualFunctionTables.put(vft.getAddress(), ghidraVfList);
        }
      }

      // The followin code merges the vftable information that comes from OOAnalyzer and
      // Ghidra.

      ghdVirtualFunctionTables.entrySet().parallelStream()
        .forEach(e -> ooaVirtualFunctionTables.merge(e.getKey(), e.getValue(), (ooaEntries, ghdEntries) -> {
              // If we got here, there are vftable entries from both OOAnalyzer and Ghidra.  I
              // don't think these should differ in any way except size, so we simply choose
              // the longest list here.

              if (ooaEntries.size () != ghdEntries.size ()) {
                Msg.debug (this, "Merge for vftable " + e.getKey ());

                for (Optional<Function> ent : ooaEntries) {
                  Msg.debug (this, "OOA Entry: " + ent.toString ());
                }

                for (Optional<Function> ent : ghdEntries) {
                  Msg.debug (this, "GHD Entry: " + ent.toString ());
                }
              }

              return ooaEntries.size() >= ghdEntries.size() ? ooaEntries : ghdEntries;
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

      ooaVirtualFunctionTables.forEach((vtableAddr, vfuncList) -> {

          String vftHexAddr = vtableAddr.toString("0x");
          // Note: We call getOrMakeVftableType above, so there should really be an entry!
          if (vftableMap.containsKey(vtableAddr)) {

            Structure vftableStruct = vftableMap.get(vtableAddr);
            populateVftable(vftableStruct, vfuncList);
            updateTypeManager(vftableStruct, useOOAnalyzerNamespace);

            try {
              // Try to remove any data inside the vtable
              IntStream.range(0, vftableStruct.getLength ()).forEach(offset -> {
                  Address addr = vtableAddr.add (offset);
                  Data data = flatApi.getDataAt (addr);
                  if (data != null)
                    try {
                      flatApi.removeData(data);
                    } catch (Exception e) {
                      Msg.warn(this, "Error removing data inside virtual function table at " + vftHexAddr + " (offset " + offset + "): " + e.toString ());
                    }
                });
              flatApi.createData(vtableAddr, vftableStruct);
            } catch (Exception e) {
              Msg.warn(this, "Could not create virtual function table at " + vftHexAddr + ": " + e.toString ());
            }
          } else {
            Msg.error(this, "There is no virtual function table at address " + vftHexAddr);
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
  private void selectClassSymbol(OOAnalyzerClassType ooaType, Structure ghidraClassType) {

    Msg.debug (this, "Looking for a class symbol named " + ooaType.getBestName ());

    Supplier<Stream<Symbol>> getSymbolStream = () -> StreamSupport.stream (
      Spliterators.spliteratorUnknownSize(
        symbolTable.getDefinedSymbols (),
        Spliterator.ORDERED),
      false);

    // First, try to match the symbol name exactly
    var symbol = getSymbolStream.get ()
      .filter (sym -> sym.getSymbolType () == SymbolType.CLASS)
      .filter (sym -> sym.getName (true).equalsIgnoreCase (ooaType.getBestName ()))
      .findAny ();

    // If that doesn't work, we'll try to find the class in either the OOAnalyzer namespace or
    // in an imported DLL.

    if (!symbol.isPresent ()) {
      Msg.debug (this, "Couldn't find exact match for " + ooaType.getBestName () + ", so looking in OOAnalyzer and imported DLL namespaces.");
      symbol = getSymbolStream.get ()
        .filter (sym -> sym.getSymbolType () == SymbolType.CLASS)
        // Check the class name without the namespace as a precondition
        .filter (sym -> sym.toString ().equalsIgnoreCase (ghidraClassType.getName ()))
        // Now check the namespace
        .filter (sym -> {

            var path = sym.getPath ();

            var name_without_first_ns = Arrays.stream (path)
            .skip (1) // Skip the initial namespace
            .collect (Collectors.joining ("::"));

            if (!name_without_first_ns.equals(ooaType.getBestName ()))
              return false;

            var first_ns_opt = Stream.iterate (sym.getParentNamespace (),
                                           ns -> ns != null && ns.getParentNamespace () != null,
                                           ns -> ns.getParentNamespace ())
            .findAny ();

            // If there is no parent namespace, we should have matched exactly
            if (!first_ns_opt.isPresent ())
              return false;

            var first_ns = first_ns_opt.get ();
            if (first_ns == null)
              return false;

            if (first_ns.equals(ooanalyzerNamespace))
              return true;

            if (first_ns.isExternal ())
              return true;

            // Default: fail
            return false;

          })
        .findAny ();
    }

    // Yay, we found a symbol.
    if (symbol.isPresent ()) {
      var sym = symbol.get ();

      Msg.debug(this, "Symbol for class " + ghidraClassType.getName () + ": " + sym.getName (true));
      classSymbolMap.put(ghidraClassType, sym);

      if (!useOOAnalyzerNamespace) {
        Msg.debug (this, "Not moving " + sym.getName (true) + " to the OOAnalyzer namespace because the option is disabled");
        return;
      } else {

        // Move it if necessary
        try {
          Namespace parentNs = sym.getParentNamespace();

          // Look through each parent namespace until we get to the end or find OOanalyzer
          boolean inOOAnalyzerNamespace =
            Stream.iterate (parentNs,
                            ns -> ns != null,
                            ns -> ns.getParentNamespace ())
            .filter (ns -> ns.equals (ooanalyzerNamespace))
            .findAny ()
            .isPresent ();

          if (inOOAnalyzerNamespace) {
            Msg.debug (this, "Not moving " + sym.getName (true) + " since it is already in the OOAnalyzer namespace");
          } else {
            Namespace ns = null;

            // If ns is an imported namespace, don't attempt to move it
            boolean isExternal =
              Stream.iterate (parentNs,
                              nst -> nst != null,
                              nst -> nst.getParentNamespace ())
              .filter (nst -> nst.isExternal ())
              .findAny ()
              .isPresent ();

            if (parentNs.isGlobal ()) {
              // If there is no parent namespace, ns becomes Global instead of
              // ooanalyzerNamespace.  Seems like a bug to me.
              ns = this.ooanalyzerNamespace;
            } else if (!isExternal) {
              ns = NamespaceUtils.createNamespaceHierarchy (parentNs.getName (true), this.ooanalyzerNamespace, program, SourceType.ANALYSIS);
            }

            if (ns == null) {
              Msg.debug (this, "Not moving " + sym.getName (true) + " to the OOAnalyzer namespace because it is imported and Ghidra will not allow it to be moved.");
            } else {
              Msg.debug (this, "Moving " + sym.getName (true) + " to the OOAnalyzer namespace " + ns.getName (true));
              sym.setNamespace(ns);
            }
          }
        } catch (NullPointerException | DuplicateNameException | InvalidInputException
                 | CircularDependencyException e) {
          Msg.error(this, "Could not create symbol for class: " + ghidraClassType.getName()
                    + ". This can be caused by embedded or imported classes.\n" + e.toString ());
        }
      }
    } else {
      // We did not find a symbol.  We need to create one.

      try {
        Msg.debug(this, "Symbol for class " + ghidraClassType.getName () + " not found.  Creating new one.");

        // Recreate namespace hierarchy
        Optional<String> optNamespace = ooaType.getNamespace ();

        String className = SymbolUtilities.replaceInvalidChars (ooaType.getNameWithoutNamespace (), true);

        // Msg.debug (this, "D1 " + optNamespace + " " + className + " " + ooaType.getNamespace () + " " + ooaType.getDemangledName ());

        Namespace ns = NamespaceUtils.createNamespaceHierarchy (optNamespace.orElse (null), this.ooanalyzerNamespace, program, SourceType.ANALYSIS);

        // Msg.debug (this, "D2 Namespace " + ns + " Class name " + className);

        GhidraClass newSymCls = symbolTable.createClass(ns,
                                                        className,
                                                        SourceType.USER_DEFINED);

        classSymbolMap.put(ghidraClassType, newSymCls.getSymbol());
        Msg.debug(this, "Symbol for class " + ghidraClassType.getName () + ": " + newSymCls);

      } catch (DuplicateNameException | InvalidInputException e) {
        Msg.warn (this, "Unable to create class: " + e.toString ());
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
  private void applyVirtualFunctions(Structure ghidraType, Map<Function, Vfentry> ghidraVirtualMethodInfo) {

    // This is entirely about adding things to the symbol table.

    if (ghidraType != null) {
      ghidraVirtualMethodInfo.forEach((vfunc, vfEntry) -> {

          // Assume a normal method until proven
          // otherwise
          MethodType mType = MethodType.METHOD;

          if (vfEntry != null && (vfEntry.getType().equals("dtor") || vfEntry.getType().equals("deldtor"))) {
            mType = MethodType.VIRTUAL_DTOR;
          }

          try {
            applyClassToMethod(ghidraType, vfunc, mType);
          } catch (Exception e) {
            Msg.warn (this, "Something went wrong when applying " + ghidraType + " to " + vfunc + ": " + e.toString ());
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

          if (vfunc != null) {
            // We can have multiple labels in the symbol table
            String label = vfunc.getSymbol().getName(false);
            if (!label.startsWith("VIRT_")) {
              label = "VIRT_" + vfunc.getName();
            }

            createOrUpdateLabel(vfunc.getEntryPoint(), label, clsScope, SourceType.USER_DEFINED);
          } else {
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
  private void populateVftable(Structure vftableStruct, List<Optional<Function>> vfuncs) {

    Integer pointerSize = null;
    if (dataTypeMgr != null) {
      pointerSize = dataTypeMgr.getDataOrganization().getPointerSize();
    } else {
      pointerSize = DataOrganizationImpl.getDefaultOrganization().getPointerSize();
    }

    int offset = 0;

    for (Optional<Function> vfo : vfuncs) {

      if (vfo.isEmpty ()) {
        // If we can't find the exact function, just use a pointer data type
        PointerDataType pdt = new PointerDataType ();
        vftableStruct.insertAtOffset(offset, pdt, pdt.getLength(),
                                     String.valueOf(offset), "virtual function table entry.");
      } else {
        Function vf = vfo.get ();
        FunctionDefinitionDataType vfDef = new FunctionDefinitionDataType(ooanalyzerVirtualFunctionsCategory,
                                                                          vf.getName(), vf.getSignature());
        Pointer pvfDt = PointerDataType.getPointer(vfDef, dataTypeMgr);

        vftableStruct.insertAtOffset(offset, pvfDt, pvfDt.getLength(),
                                     vf.getName() + "_" + String.valueOf(offset), "virtual function table entry.");
      }
      offset += pointerSize;
    }
  }

  /**
   * Utility function to find the offset of a vftptr install instruction.
   * Currently, this method is unused
   */
  @SuppressWarnings("unused")
  //    private Optional<Long> findVptrOffset(Symbol vft) {
  //            if (vft.hasReferences()) {
  //                    for (Reference r : flatApi.getReferencesTo(vft.getAddress())) {
  //                            Address from = r.getFromAddress();
  //                            Instruction insn = flatApi.getInstructionAt(from);
  //
  //                            if (insn != null && insn.getNumOperands() == 2) {
  //
  //                                    Object op0[] = insn.getOpObjects(0);
  //                                    // [REG + NNN], VFT
  //                                    if (op0.length == 2) {
  //                                            if (op0[0] instanceof Register && op0[1] instanceof Scalar) {
  //                                                    return Optional.of(((Scalar) op0[1]).getUnsignedValue());
  //
  //                                            }
  //                                    } else if (op0.length == 1) {
  //                                            // [REG], VFT
  //                                            return Optional.of(Long.valueOf(0));
  //                                    }
  //                            }
  //                    }
  //            }
  //            return Optional.empty();
  //    }

  private DataType getOrMakeVftableType(Vftable vftable, Structure ghidraClassType) {

    var ea = flatApi.toAddr (vftable.getEa ());
    if (!vftableMap.containsKey (ea)) {
      Structure vftableStruct = new StructureDataType(ghidraClassType.getCategoryPath (),
                                                      ghidraClassType.getName() + "::vftable_" + Long.toHexString(vftable.getEa()).toLowerCase(), 0);

      vftableMap.put(ea, vftableStruct);
    }

    var struct = vftableMap.get (ea);
    return struct;

  }

  /**
   * Use the OOAnalayzer information to select the correct arraytype for the
   * vftable.
   *
   * @param ooaType    The OOAnalyzer data structure
   * @param ghidraType The Ghidra data structure for the class
   * @param vftptr      the virtual function pointer to analyze
   * @return the data type for the vftptr or an empty value
   */
  private Optional<DataType> analyzeVftptrType(OOAnalyzerClassType ooaType, Structure ghidraClassType, Member vftptr) {

    Collection<Vftable> vftables = ooaType.getVftables();
    Optional<Vftable> vtabOpt = vftables.stream()
      // Get this vftable
      .filter(vft -> vft.getVftptr() == vftptr.getOffset())
      // short circuit search
      .findFirst();

    if (vtabOpt.isPresent()) {
      Vftable vftable = vtabOpt.get();
      return Optional.of (PointerDataType.getPointer (getOrMakeVftableType (vftable, ghidraClassType), dataTypeMgr));
    } else {
      Msg.error(this, "Unable to find the vftable corresponding to " + vftptr.getOffset () + " in " + ooaType);
      return Optional.empty ();
    }
  }

  /**
   * Analyze class members.
   *
   * @param ooaType    The type found by OOAnalyzer
   * @param ghidraType The associated ghidra types
   */
  private void analyzeMembers(OOAnalyzerClassType ooaType, Structure ghidraType) {

    if (!classSymbolMap.containsKey(ghidraType)) {
      Msg.warn(this, "Skipping " + ooaType.getName() + " because there is no associated symbol.");
      Msg.warn(this, "The Ghidra type was " + ghidraType.getName());
      return;
    }

    // If there are members for this type, process them
    Collection<Member> members = ooaType.getMembers();
    for (Member mbr : members) {

      if (mbr.getBase()) {
        Msg.trace (this, "Skipping member " + mbr.getName() + " because it was defined on the base class.");
        continue;
      }

      if (mbr.getOffset() == Member.INVALID_OFFSET) {
        Msg.error(this, "Cannot add member " + mbr.getName() + " due to invalid offset");
        continue;
      }

      DataType mbrType = null;

      if (MemberType.STRUC.jsonTypeName().equals(mbr.getType())) {

        String strucName = mbr.getStruc().get();

        // If this type was already compared to the Ghidra
        // type and considered better, then use it

        for (Entry<OOAnalyzerClassType, Structure> e : classTypeMap.entrySet()) {
          OOAnalyzerClassType jsonType = e.getKey();

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

      } else if (mbr.getType().equals(MemberType.VFTPTR.jsonTypeName())) {

        // vftptrs are a little different in terms of type.
        // Also "vftptr_" will appear in the name

        mbrType = analyzeVftptrType(ooaType, ghidraType, mbr).orElse(null);

      } else {

        // qword/dword/word/byte are directly translated as
        // builtin types

        mbrType = findDataType(mbr.getSize()).orElse(null);
      }

      if (mbrType == null) {

        // If the member is *still* null just make it an undefined type
        Msg.warn (this, String.format ("Creating undefined type for type %s, member %s on class %s", mbr.getType(), mbr.getName(), ooaType.getName()));
        mbrType = Undefined.getUndefinedDataType(ooaType.getSize());
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

      } catch (IllegalArgumentException | NullPointerException x) {
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
    // XXX: Set category path of the pointer type
    DataType thisPtrType = PointerDataType.getPointer(ooClass, dataTypeMgr);
    thisPtrType.setCategoryPath (ooClass.getCategoryPath ());
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
   * Add a data type.
   *
   * @param dt                the data type to commit.
   * @param useOOAnalyzerPath Flag for where to add the type
   */
  private void updateTypeManager(final DataType dt, boolean useOOAnalyzerPath) {
    if (!dataTypeMgr.contains(dt)) {
      if (useOOAnalyzerPath) {
        try {
          if (!dt.getCategoryPath().isAncestorOrSelf(ooanalyzerCategory)) {
            CategoryPath cp = new CategoryPath(ooanalyzerCategory, dt.getCategoryPath().getPath ());
            dt.setCategoryPath(cp);
          }
        } catch (DuplicateNameException e) {
        }
      }

      try {
        dataTypeMgr.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
        dataTypeMgr.flushEvents();
      } catch (Exception e) {
        Msg.warn(this, "Unable to add data type " + dt.toString() + ": " + e.toString ());
      }
    }
  }

  /**
   * /** Add an array of data types.
   *
   * @param dTypes            The list of data types to commit.
   * @param useOOAnalyzerPath Flag for where to add the type
   */
  private void updateTypeManager(final DataType[] dTypes, boolean useOOAnalyzerPath) {

    for (var dt : dTypes) {
      allowSwingToProcessEvents ();
      if (monitor.isCancelled ()) {
        return;
      }
      updateTypeManager(dt, useOOAnalyzerPath);
    }
    dataTypeMgr.flushEvents();
  }

  /**
   * Analyze the methods associated with this type.
   *
   * @param ghidraType The data structure containing methods
   * @param methods    The list of methods to analyze
   */
  private void analyzeMethods(Structure ghidraType, Collection<Method> methods) {

    if (null == methods || !classSymbolMap.containsKey(ghidraType)) {
      return;
    }

    Symbol ghidraTypeSym = classSymbolMap.get(ghidraType);

    for (Method ooaMethod : methods) {

      try {
        Address addr = flatApi.toAddr(ooaMethod.getEa());

        String methodName = ooaMethod.getName();

        // XXX: Don't we need to set mType to VIRTUAL?
        MethodType mType = MethodType.METHOD;

        // Constructors/Destructors have slightly different names
        if (ooaMethod.getType().equals("ctor")) {

          methodName = ghidraType.getName();
          mType = MethodType.CTOR;

        } else if (ooaMethod.getType().equals("dtor") || ooaMethod.getType().equals("deldtor")) {

          // Proper C++ means destructors start with '~'
          methodName = "~" + ghidraType.getName();
          mType = MethodType.DTOR;
        }

        Function ghidraMethod = getOrCreateFunction(addr, methodName);
        if (ghidraMethod == null) {
          // Errors should have been generated by getOrCreateFunction.
          continue;
        }

        // if the ghidra name is not the default auto name, then use it
        if (!ghidraMethod.getName().startsWith(autoFuncNamePrefix)) {
          methodName = ghidraMethod.getName();
        }

        Namespace clsNamespace = symbolTable.getNamespace(ghidraTypeSym.getName(),
                                                          ghidraTypeSym.getParentNamespace());

        // Create a new method for this class symbol
        createNewLabel(ghidraMethod.getEntryPoint(), methodName, clsNamespace, SourceType.USER_DEFINED);

        applyClassToMethod(ghidraType, ghidraMethod, mType);

      } catch (Exception e) {
        Msg.warn (this, "An error occurred in analyzeMethods: " + e.toString ());
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

    if (flatApi.getSymbolAt(address).getSource().equals(SourceType.DEFAULT))
      return createOrUpdateLabel (address, name, scope, sourceType);
    else
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
      // Remove bad characters
      name = SymbolUtilities.replaceInvalidChars (name, true);

      return Optional.of(symbolTable.createLabel(address, name, scope, sourceType));
    } catch (InvalidInputException e) {
      Msg.warn (this, "Unable to create label: " + e.toString ());
    }

    return Optional.empty();
  }

  private static Optional<Map<String, String>> tryToDemangleUsingGhidra (String mangledName, Boolean isMethodName) {
    try {
      Demangler demangler = new MicrosoftDemangler();

      Msg.debug (OOAnalyzer.class, "Trying to demangle " + mangledName + " using Ghidra");
      DemangledObject demangledObj = demangler.demangle(mangledName, true);

      if (demangledObj != null) {

        String demangledName, namespace;

        // For imports, we used a method name
        if (isMethodName) {
          demangledName = demangledObj.getNamespace ().toString().replace("\n", "\\n").replace(" ", "_");
          // This will leave a :: at the end that we need to remove
          demangledName = demangledName.substring (0, demangledName.length () - "::".length ());
        } else {
          Msg.warn(OOAnalyzer.class, "Ghidra suceeded on a non-imported class name.  This is unexpected.");
          demangledName = demangledObj.toString().replace("\n", "\\n").replace(" ", "_");
        }
        Msg.debug (OOAnalyzer.class, "Ghidra demangled " + mangledName + " to " + demangledName);

        // Now get the namespace
        String namespaceType = null;
        if (isMethodName) {
          // method -> class -> namespace
          var tmpNamespace = demangledObj.getNamespace ().getNamespace ();
          if (tmpNamespace != null)
            namespaceType = demangledObj.getNamespace ().getNamespace ().toString ();
        } else {
          var tmpNamespace = demangledObj.getNamespace ();
          if (tmpNamespace != null)
            namespaceType = demangledObj.getNamespace ().toString ();
        }
        if (namespaceType != null) {
          namespace = namespaceType;
          // This will leave a :: at the end that we need to remove
          namespace = namespace.substring (0, namespace.length () - "::".length ());

        } else {
          namespace = "";
        }
        // Ghidra demangler leaves :: at the end, which we don't want.
        Msg.debug(OOAnalyzer.class, "Got namespace from Ghidra demangler: " + namespace);
        return Optional.of (Map.of("demangledName", demangledName, "namespace", namespace));
      } else {
        Msg.debug (OOAnalyzer.class, "Ghidra did not know how to demangle " + mangledName);
      }

    } catch (Exception e) {
      Msg.warn(OOAnalyzer.class, "Demangling failed with exception: " + e.toString ());
    }

    return Optional.empty ();
  }

  /**
   * Load Pharos JSON file.
   *
   * @param jsonFile The JSON file
   * @return a list of parsed types
   * @throws FileNotFoundException
   */
  public static Optional<OOAnalyzerJsonRoot> parseJsonFile(File jsonFile) {

    final String mangledNameJSONString = "name";
    final String sizeJSONString = "size";
    final String demangledNameJSONString = "demangled_name";
    final String membersJSONString = "members";
    final String methodsJSONString = "methods";
    final String vftablesJSONString = "vftables";

    if (jsonFile != null) {

      JsonReader reader = null;

      try {

        reader = new JsonReader(new FileReader(jsonFile));

        // This is a custom serializer to populate the namespace from the demangled name
        // (if possible)

        JsonDeserializer<OOAnalyzerClassType> deserializer = new JsonDeserializer<OOAnalyzerClassType>() {

            @Override
            public OOAnalyzerClassType deserialize(JsonElement json, Type typeOfT,
                                              JsonDeserializationContext context) throws JsonParseException {

              JsonObject jsonObject = json.getAsJsonObject();

              String namespace = "";
              String demangledName = "";
              String mangledName = jsonObject.get(mangledNameJSONString).getAsString();

              Integer size = null;
              size = Integer.parseInt(jsonObject.get(sizeJSONString).getAsString());

              Gson g = new Gson();

              Type mbrListType = new TypeToken<Map<String, Member>>() {
                }.getType();
              Map<String, Member> mbrMap = g.fromJson(jsonObject.get(membersJSONString), mbrListType);

              Type mthListType = new TypeToken<Map<String, Method>>() {
                }.getType();
              Map<String, Method> mthMap = g.fromJson(jsonObject.get(methodsJSONString), mthListType);

              Type vftListType = new TypeToken<Map<String, Vftable>>() {
                }.getType();
              Map<String, Vftable> vftMap = g.fromJson(jsonObject.get(vftablesJSONString), vftListType);

              // Determine the name of the class

              var ghidraDemanglerOutput =
              // We first try to demangle mangledName using Ghidra.  Sometimes this is set from
              // RTTI, but other times it is made up (e.g., cls_1234)
              tryToDemangleUsingGhidra (mangledName, false)
              // If that fails, maybe we can find an imported method name and demangle that
              // using Ghidra
              .or (() ->
                   // Try to find an imported method name
                   mthMap
                   .values ()
                   .stream ()
                   .parallel ()
                   .filter (m -> m.getImported ())
                   .findAny () // optional
                   .map (m -> m.getName ()) // optional
                   // And then try to demangle it
                   .map (m -> tryToDemangleUsingGhidra (m, true)) // optional optional
                   // If not null, get the value
                   // How do we convert optional optional to optional?
                   .orElse (Optional.empty ()));

              if (ghidraDemanglerOutput.isPresent ()) {
                // We were able to demangle something using Ghidra
                demangledName = ghidraDemanglerOutput.get ().get ("demangledName");
                namespace = ghidraDemanglerOutput.get ().get ("namespace");
              } else {
                // Ghidra failed, so use the demangled name from OOAnalyzer
                Msg.debug(this, "Demangling " + mangledName + " using Ghidra failed");
                JsonElement jElm = jsonObject.get(demangledNameJSONString);
                demangledName = jElm.getAsString();
                Msg.debug(this, "Using demangled name in JSON instead: " + demangledName);
                namespace = OOAnalyzer.getNamespace(demangledName);
                Msg.debug(this, "Got namespace from OOanalyzer: " + namespace);
              }

              return new OOAnalyzerClassType(mangledName, demangledName, namespace, size, mbrMap.values (), mthMap.values (), vftMap.values ());
            }
          };

        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(OOAnalyzerClassType.class, deserializer);
        Gson gson = gsonBuilder.excludeFieldsWithoutExposeAnnotation().create();
        OOAnalyzerJsonRoot types = gson.fromJson(reader, OOAnalyzerJsonRoot.class);

        return Optional.of(types);

      } catch (Exception e) {
        Msg.warn(OOAnalyzer.class, "There was a problem loading " + jsonFile);
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        Msg.warn(OOAnalyzer.class, "Exception: " + sw.toString ());
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
