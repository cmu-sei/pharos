/*******************************************************************************
 * Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.
 ******************************************************************************/
package ooanalyzer.jsontypes;

import java.util.Optional;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * JSON class to represent a member
 */
public class Member {
    
    public static final Integer INVALID_OFFSET = -1;
    
    @Expose
    @SerializedName("name")
    private String name;
    
    @Expose
    @SerializedName("type")
    private String type;
    
    @Expose
    @SerializedName("struc")
    private String struc;
    
    @Expose
    @SerializedName("parent")
    private String parent;
    
    @Expose
    @SerializedName("offset")
    private String offset;
    
    @Expose
    @SerializedName("count")
    private String count;

    public Optional<String> getStruc() {
    	if (struc == null) return Optional.empty();
        return Optional.of(struc);
    }

    public boolean isParent() {
        if (parent == null) {
            return false;
        }
        return parent.equalsIgnoreCase("yes");
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public Integer getOffset() {
        try {
            return Integer.parseInt(offset, 16);
        } catch (NumberFormatException nfx) {
            
        }
        return -1;
    }

    public Integer getCount() {
        return Integer.parseInt(count);
    }

    @Override
    public String toString() {
        return "[name=" + name + ", type=" + type + ", struc=" + struc
                + ", parent=" + parent + ", offset=" + offset + ", count="
                + count + "]";
    }
}
