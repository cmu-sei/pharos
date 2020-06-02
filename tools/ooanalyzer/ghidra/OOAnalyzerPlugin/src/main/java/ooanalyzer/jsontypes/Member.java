/*******************************************************************************
 * Copyright 2015-2020 Carnegie Mellon University.  See LICENSE file for terms.
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
  @SerializedName("base")
  private Boolean base;

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

  public Boolean getBase() {
    return base;
  }

  public Integer getOffset() {
    return Integer.decode (offset);
  }

  public Integer getCount() {
    return Integer.decode (count);
  }

  @Override
  public String toString() {
    return "[name=" + name + ", type=" + type + ", struc=" + struc
      + ", parent=" + parent + ", offset=" + offset + ", count="
      + count + "]";
  }
}
