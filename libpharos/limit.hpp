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

#include <sys/resource.h> // For definition of rusage

#include <string>
#include <chrono>
#include "options.hpp"

namespace pharos {

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
 public:
  using clock = std::chrono::steady_clock;
  using time_point = std::chrono::time_point<clock>;
  using duration = std::chrono::duration<double>;

 private:

  size_t counter;
  rusage start_ru;
  time_point start_ts;

  size_t counter_limit;
  double relative_cpu_limit;
  double absolute_cpu_limit;
  double relative_memory_limit;
  double absolute_memory_limit;
  duration relative_clock_limit;
  duration absolute_clock_limit;

  std::string msg;

 public:

  ResourceLimit();

  void reset_counter() { counter = 0; }
  void increment_counter() { counter++; }
  size_t get_counter() const { return counter; }

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
    set_clock_limits(duration(relative), duration(absolute));
  }
  void set_clock_limits(duration relative, duration absolute) {
    relative_clock_limit = relative;
    absolute_clock_limit = absolute;
  }

  LimitCode check();

  std::string get_message() { return msg; }

  duration get_relative_clock() const;
  double get_relative_cpu() const;
  double get_relative_memory() const;

  duration get_absolute_clock() const;
  double get_absolute_cpu() const;
  double get_absolute_memory() const;

  std::string get_relative_usage() const;
  std::string get_absolute_usage() const;

};

struct PharosLimits {
  enum class limit_type { BASE, FUNC, PARTITIONER };

  PharosLimits(const ProgOptVarMap &vm);

  void set_clock_limits(ResourceLimit &limit, limit_type ltype) const;
  void set_cpu_limits(ResourceLimit &limit, limit_type ltype) const;
  void set_counter_limit(ResourceLimit &limit, limit_type ltype) const;

  void set_memory_limits(ResourceLimit &limit) const {
    if (maxmem && relative_maxmem) {
      limit.set_memory_limits(*relative_maxmem, *maxmem);
    }
  }


  void set_limits(ResourceLimit &limit, limit_type ltype) const {
    set_counter_limit(limit, ltype);
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

  boost::optional<int> block_counter_limit;
  boost::optional<int> func_counter_limit;
};

const PharosLimits &get_global_limits();

} // namespace pharos

#endif
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
