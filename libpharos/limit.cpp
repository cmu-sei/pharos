// Copyright 2015-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>

#include "limit.hpp"
#include "misc.hpp"
#include "descriptors.hpp"

namespace pharos {

namespace {

#if __linux__
#  define MEM_FACTOR (1024.0)
#else
#  if __APPLE__ && __MACH__
#    define MEM_FACTOR (1024.0 * 1024.0)
#  else
#    define MEM_FACTOR (1024.0 * 1024.0)
#    warning "Unrecognized platform! Memory limit options may not work correctly."
#  endif
#endif

// A couple of global variables.  It's unclear that there's a better way to do this...
bool first_ts_set = false;
ResourceLimit::time_point first_ts;

// A few private helper routines.

inline double total_cpu_time(const rusage& ru) {
  double secs = ru.ru_utime.tv_sec + ru.ru_stime.tv_sec;
  double usecs = ru.ru_utime.tv_usec + ru.ru_stime.tv_usec;
  return (secs + (usecs / 1000000.0));
}

inline void get_resource_usage(rusage& ru) {
  if (getrusage(RUSAGE_SELF, &ru) != 0) {
    assert(false);
    abort();
  }
}

} // unnamed namespace

// ResourceLimit class methods

ResourceLimit::ResourceLimit() {
  counter = 0;
  counter_limit = 0;
  set_cpu_limits(0.0, 0.0);
  set_memory_limits(0.0, 0.0);
  set_clock_limits(duration(), duration());
  get_resource_usage(start_ru);
  start_ts = clock::now();
  if (!first_ts_set) {
    first_ts_set = true;
    first_ts = start_ts;
  }
}

LimitCode ResourceLimit::check() {
  // Counters are the easiest, check them first.
  if (counter_limit > 0) {
    if (counter >= counter_limit) {
      msg = "count limit exceeded";
      return LimitCounter;
    }
  }
  // Then relative and absolute wall clock limits.
  if (relative_clock_limit > duration() || absolute_clock_limit > duration()) {
    time_point now_ts = clock::now();

    // Check the relative wall clock limit if there is one.
    if (relative_clock_limit > duration()) {
      duration relative_clock_delta = now_ts - start_ts;
      if (relative_clock_delta >= relative_clock_limit) {
        msg = "relative wall clock exceeded";
        return LimitRelativeClock;
      }
    }

    // Check the absolute wall clock limit if there is one.
    if (absolute_clock_limit > duration()) {
      duration absolute_clock_delta = now_ts - first_ts;
      if (absolute_clock_delta >= absolute_clock_limit) {
        msg = "absolute wall clock exceeded; adjust with --timeout";
        return LimitAbsoluteClock;
      }
    }
  }

  // Check limits that require calling getrusage()...
  if (relative_cpu_limit > 0 || absolute_cpu_limit > 0 ||
      relative_memory_limit > 0 || absolute_memory_limit > 0) {
    rusage now_ru;
    get_resource_usage(now_ru);

    // Check the relative memory limit if there is one.
    if (relative_memory_limit > 0) {
      long relative_memory_long = now_ru.ru_maxrss - start_ru.ru_maxrss;
      // Convert from architecture dependent memory units to our API of mibibytes.
      double relative_memory_delta = relative_memory_long / MEM_FACTOR;
      if (relative_memory_delta >= relative_memory_limit) {
        msg = "relative memory exceeded";
        return LimitRelativeMemory;
      }
    }

    // Check the absolute memory limit if there is one.
    if (absolute_memory_limit > 0) {
      // Convert from architecture dependent memory units to our API of mibibytes.
      double absolute_memory_delta = now_ru.ru_maxrss / MEM_FACTOR;
      if (absolute_memory_delta >= absolute_memory_limit) {
        msg = "absolute memory exceeded";
        return LimitAbsoluteMemory;
      }
    }

    // Check the relative CPU limit if there is one.
    if (relative_cpu_limit > 0) {
      double total_now_cpu = total_cpu_time(now_ru);
      double total_start_cpu = total_cpu_time(start_ru);
      double relative_cpu_delta = total_now_cpu - total_start_cpu;
      if (relative_cpu_delta >= relative_cpu_limit) {
        msg = "relative CPU time exceeded; adjust with --per-function-timeout";
        return LimitRelativeCPU;
      }
    }

    // Check the absolute CPU limit if there is one.
    if (absolute_cpu_limit > 0) {
      double total_now_cpu = total_cpu_time(now_ru);
      if (total_now_cpu >= absolute_cpu_limit) {
        msg = "absolute CPU time exceeded";
        return LimitAbsoluteCPU;
      }
    }
  }

  // Either there were no limits, or we haven't reached any of them.
  return LimitSuccess;
}

ResourceLimit::duration ResourceLimit::get_relative_clock() const {
  time_point now_ts = clock::now();
  return now_ts - start_ts;
}

double ResourceLimit::get_relative_cpu() const {
  rusage now_ru;
  get_resource_usage(now_ru);
  double total_now_cpu = total_cpu_time(now_ru);
  double total_start_cpu = total_cpu_time(now_ru);
  return (total_start_cpu - total_now_cpu);
}

double ResourceLimit::get_relative_memory() const {
  rusage now_ru;
  get_resource_usage(now_ru);
  long relative_memory_long = now_ru.ru_maxrss - start_ru.ru_maxrss;
  // Convert from architecture dependent memory units to our API of mibibytes.
  return (relative_memory_long / MEM_FACTOR);
}

ResourceLimit::duration ResourceLimit::get_absolute_clock() const {
  time_point now_ts = clock::now();
  return now_ts - first_ts;
}

double ResourceLimit::get_absolute_cpu() const {
  rusage now_ru;
  get_resource_usage(now_ru);
  return total_cpu_time(now_ru);
}

double ResourceLimit::get_absolute_memory() const {
  rusage now_ru;
  get_resource_usage(now_ru);
  // Convert from architecture dependent memory units to our API of mibibytes.
  return (now_ru.ru_maxrss / MEM_FACTOR);
}

std::string ResourceLimit::get_relative_usage() const {
  time_point now_ts = clock::now();
  rusage now_ru;
  get_resource_usage(now_ru);

  duration relative_clock_delta = now_ts - start_ts;
  double total_now_cpu = total_cpu_time(now_ru);
  double total_start_cpu = total_cpu_time(start_ru);
  double relative_cpu_delta = total_start_cpu - total_now_cpu;
  long relative_memory_long = now_ru.ru_maxrss - start_ru.ru_maxrss;
  // Convert from architecture dependent memory units to our API of mibibytes.
  double relative_memory_delta = relative_memory_long / MEM_FACTOR;

  return boost::str(boost::format("%.2f secs CPU, %.2f MB memory, %.2f secs elapsed") %
                    relative_cpu_delta % relative_memory_delta % relative_clock_delta.count());
}

std::string ResourceLimit::get_absolute_usage() const {
  time_point now_ts = clock::now();
  rusage now_ru;
  get_resource_usage(now_ru);

  duration absolute_clock_delta = now_ts - first_ts;
  double absolute_cpu_delta = total_cpu_time(now_ru);
  // Convert from architecture dependent memory units to our API of mibibytes.
  double absolute_memory_delta = now_ru.ru_maxrss / MEM_FACTOR;

  return boost::str(boost::format("%.2f secs CPU, %.2f MB memory, %.2f secs elapsed") %
                    absolute_cpu_delta % absolute_memory_delta % absolute_clock_delta.count());
}

// This class contains the value provided on the command line and/or from the configuration
// file.  It facilities copying these values into a specific instance of the ResourceLimit
// object using the set_xxx_limits() functions.  Duggan suggested that there might be a better
// way to do this now with lambdas.
PharosLimits::PharosLimits(const ProgOptVarMap &vm)
{
  // On August 10 2018, we agreed that the names of these options were poorly documented and
  // named.  In particular absolute versus relative didn't really have clear meaning without
  // more context.  Cory had originally intended for this module to be re-usable in multiple
  // contexts so didn't want to tie the two kinds of measurements to specific things like
  // "per-function".  The mistake he made was that in practice that _are_ tied to specific
  // things according to where they're being called from.  Thus this routine that binds the
  // limits to configuration options should have used more specific names, even if the internal
  // variables continue to reference absolute and relative.

  // With no qualifier --timeout is the whole program timeout.
  timeout = vm.get<double>("timeout", "pharos.timeout");
  // The time spent per function before moving on to the next function.
  relative_timeout = vm.get<double>("per-function-timeout", "pharos.per_function_timeout");

  // The total time allowed to be spent in partitioning.
  partitioner_timeout = vm.get<double>("partitioner-timeout", "pharos.partitioner_timeout");
  if (timeout && partitioner_timeout && *timeout != 0.0 && *timeout < *partitioner_timeout) {
    partitioner_timeout = timeout;
    OWARN << "Reducing partitioner timeout to match timeout (" << *partitioner_timeout << " seconds)." << LEND;
  }

  // The maxmimum memory that the process is allowed to use.
  maxmem = vm.get<double>("maximum-memory", "pharos.maximum_memory");
  // The maxmimum memory allowed per function before moving on to the next function.
  relative_maxmem = vm.get<double>("per-function-maximum-memory", "pharos.per_function_maximum_memory");
  if (DescriptorSet::get_concurrency_level(vm) > 1) {
    // When running with threads, we really don't have a good way to calculate per-function
    // memory usage
    relative_maxmem = 0;
  }

  // The maximum instructions per block before aborting function analysis.
  block_counter_limit = vm.get<int>("maximum-instructions-per-block", "pharos.maximum_instructions_per_block");
  // The maximum iterations over the CFG before aborting function analysis.
  func_counter_limit = vm.get<int>("maximum-iterations-per-function", "pharos.maximum_iterations_per_function");

  // The maximum number of treenodes per ITE condition allowed before substituting a new treenode.
  node_condition_limit = vm.get<int>("maximum-nodes-per-condition", "pharos.maximum_nodes_per_condition");
}

void PharosLimits::set_clock_limits(ResourceLimit &limit, limit_type ltype) const
{
  switch (ltype) {
   case limit_type::BASE:
   case limit_type::FUNC:
    if (timeout) {
      limit.set_clock_limits(0.0, *timeout);
    }
    break;
   case limit_type::PARTITIONER:
    if (partitioner_timeout) {
      limit.set_clock_limits(0.0, *partitioner_timeout);
    }
    break;
  }
}

void PharosLimits::set_cpu_limits(ResourceLimit &limit, limit_type ltype) const
{
  switch (ltype) {
   case limit_type::BASE:
   case limit_type::FUNC:
    if (relative_timeout) {
      limit.set_cpu_limits(*relative_timeout, 0.0);
    }
    break;
   case limit_type::PARTITIONER:
    // No relative/CPU paritioner timeout.
    break;
  }
}

void PharosLimits::set_counter_limit(ResourceLimit &limit, limit_type ltype) const {
  switch (ltype) {
   case limit_type::BASE:
    if (block_counter_limit) {
      limit.set_counter_limit(*block_counter_limit);
    }
    break;
   case limit_type::FUNC:
    if (func_counter_limit) {
      limit.set_counter_limit(*func_counter_limit);
    }
    break;
   case limit_type::PARTITIONER:
    // No partitioner count limit.
    break;
  }
}

void PharosLimits::set_memory_limits(ResourceLimit &limit, limit_type ltype) const {
  switch (ltype) {
   case limit_type::BASE:
   case limit_type::FUNC:
    if (maxmem && relative_maxmem) {
      limit.set_memory_limits(*relative_maxmem, *maxmem);
    }
    break;
   case limit_type::PARTITIONER:
    // No relative memory limit for partitioning.
    if (maxmem) {
      limit.set_memory_limits(0.0, *maxmem);
    }
    break;
  }
}

namespace {
std::unique_ptr<PharosLimits> global_limits;
}

void set_global_limits(const ProgOptVarMap& vm)
{
  global_limits.reset(new PharosLimits(vm));
}

const PharosLimits& get_global_limits()
{
  assert(global_limits);
  return *global_limits;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
