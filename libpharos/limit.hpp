// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Limit_H
#define Pharos_Limit_H

// This header is intended to provide a generic and graceful
// mechanisms for implementing a wide variety of resource limits
// without burdening the calling algorithm with the details.  Simply
// construct a resource limit object, set some limits, periodically
// increment the counter and/or check the limits, and exit when the
// check does not return LimitSuccess.  It can also be used to time
// algorithms and report resource consumption.

// Cory's intention for implementing both relative and absolute limits
// was that we could have a period of gracefully exiting, even when
// things were beginning to go very wrong. For example, we might cap
// absolute memory consumption at 40GB using this system, and at 44GB
// using some kind of harsher signal based system, and hopefully
// ObjDigger would be able to complete object analysis with whatever
// functions had already been analyzed without triggering the second
// limit.

#include <sys/time.h> // For definition of timespec
#include <sys/resource.h> // For definition of rusage

#include <string>
#include "options.hpp"

// This is a global value for when we first started execution.
extern bool first_ts_set;
extern timespec first_ts;

enum LimitCode {
  LimitSuccess,
  LimitCounter,
  LimitRelativeCPU,
  LimitAbsoluteCPU,
  LimitRelativeMemory,
  LimitAbsoluteMemory,
  LimitRelativeClock,
  LimitAbsoluteClock,
};

class ResourceLimit {

private:

  size_t counter;
  rusage start_ru;
  timespec start_ts;

  size_t counter_limit;
  double relative_cpu_limit;
  double absolute_cpu_limit;
  double relative_memory_limit;
  double absolute_memory_limit;
  double relative_clock_limit;
  double absolute_clock_limit;

  std::string msg;

public:

  ResourceLimit();

  void reset_counter() { counter = 0; }
  void increment_counter() { counter++; }
  size_t get_counter() { return counter; }

  void set_counter_limit(size_t limit) {
    counter_limit = limit;
  }

  void set_cpu_limits(double relative, double absolute) {
    relative_cpu_limit = relative;
    absolute_cpu_limit = absolute;
  }

  void set_memory_limits(double relative, double absolute) {
    relative_memory_limit = relative;
    absolute_memory_limit = absolute;
  }

  void set_clock_limits(double relative, double absolute) {
    relative_clock_limit = relative;
    absolute_clock_limit = absolute;
  }

  LimitCode check();

  std::string get_message() { return msg; }

  double get_relative_clock();
  double get_relative_cpu();
  double get_relative_memory();

  double get_absolute_clock();
  double get_absolute_cpu();
  double get_absolute_memory();

  std::string get_relative_usage();
  std::string get_absolute_usage();

};

struct PharosLimits {
  enum class limit_type { BASE, PARTITIONER };

  PharosLimits(const ProgOptVarMap &vm);

  void set_clock_limits(ResourceLimit &limit, limit_type ltype) const;
  void set_cpu_limits(ResourceLimit &limit, limit_type ltype) const;

  void set_memory_limits(ResourceLimit &limit) const {
    if (maxmem && relative_maxmem) {
      limit.set_memory_limits(*relative_maxmem, *maxmem);
    }
  }


  void set_counter_limit(ResourceLimit &limit) const {
    if (counter_limit) {
      limit.set_counter_limit(*counter_limit);
    }
  }

  void set_limits(ResourceLimit &limit, limit_type ltype) const {
    set_counter_limit(limit);
    set_clock_limits(limit, ltype);
    set_cpu_limits(limit, ltype);
    set_memory_limits(limit);
  }

  boost::optional<double> timeout;
  boost::optional<double> relative_timeout;

  boost::optional<double> partitioner_timeout;
  boost::optional<double> relative_partitioner_timeout;

  boost::optional<double> maxmem;
  boost::optional<double> relative_maxmem;

  boost::optional<int> counter_limit;
};

const PharosLimits &get_global_limits();

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
