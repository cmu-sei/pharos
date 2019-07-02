/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/
/**
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 */
 
package ooanalyzer;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;

/*** 
 * Utility class to identify the class names that Ghidra assigns by default.
 * Currently this is a separate class with a single method. It is designed this
 * way in case the definition of valid evolves over time.
 */

public class ClassTypeChecker {
    
    // These are the names that Ghidra attempts to give
    private final CategoryPath defaultStructCategory = new CategoryPath("/auto_structs");
    private final String defaultClassName = "AutoClass";

    /**
     * Evaluate whether a selected type name is OK
     * 
     * @param dt the data type yo evaluate
     * @return true if valid, false otherwise
     */
	public boolean isValid(final DataType dt) {
		// The built-in types seem to tbe the primative types. We will avoid
		// these

		if (dt.getSourceArchive().getArchiveType().isBuiltIn()) {
			return false;
		}
		// Check for the dummy structure name / category
		else if (dt.getCategoryPath().equals(defaultStructCategory)) {
			return false;
		}
		// Check for the dummy base class name
		else if (dt.getName().indexOf(defaultClassName) != -1) {
			return false;
		}
		// The name is OK
		return true;
	}
}
