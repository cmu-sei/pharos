// Copyright 2015, 2016 Carnegie Mellon University.  See LICENSE file for terms.

#include <boost/format.hpp>

#include "limit.hpp"
#include "misc.hpp"

namespace pharos {

namespace {
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
        msg = "absolute wall clock exceeded";
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
      // Convert from internal "memory units" (KB) to our API of mibibytes
      double relative_memory_delta = relative_memory_long / 1024.0;
      if (relative_memory_delta >= relative_memory_limit) {
        msg = "relative memory exceeded";
        return LimitRelativeMemory;
      }
    }

    // Check the absolute memory limit if there is one.
    if (absolute_memory_limit > 0) {
      // Convert from internal "memory units" (KB) to our API of mibibytes
      double absolute_memory_delta = now_ru.ru_maxrss / 1024.0;
      if (absolute_memory_delta >= absolute_memory_limit) {
        msg = "absolute memory exceeded";
        return LimitAbsoluteMemory;
      }
    }

    // Check the relative CPU limit if there is one.
    if (relative_cpu_limit > 0) {
      double total_now_cpu = total_cpu_time(now_ru);
      double total_start_cpu = total_cpu_time(start_ru);
      double relative_cpu_delta = total_start_cpu - total_now_cpu;
      if (relative_cpu_delta >= relative_cpu_limit) {
        msg = "relative CPU time exceeded";
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
  // Convert from internal "memory units" (KB) to our API of mibibytes
  return (relative_memory_long / 1024.0);
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
  // Convert from internal "memory units" (KB) to our API of mibibytes
  return (now_ru.ru_maxrss / 1024.0);
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
  // Convert from internal "memory units" (KB) to our API of mibibytes
  double relative_memory_delta = relative_memory_long / 1024.0;

  return boost::str(boost::format("%.2f secs CPU, %.2f MB memory, %.2f secs elapsed") %
                    relative_cpu_delta % relative_memory_delta % relative_clock_delta.count());
}

std::string ResourceLimit::get_absolute_usage() const {
  time_point now_ts = clock::now();
  rusage now_ru;
  get_resource_usage(now_ru);

  duration absolute_clock_delta = now_ts - first_ts;
  double absolute_cpu_delta = total_cpu_time(now_ru);
  // Convert from internal "memory units" (KB) to our API of mibibytes
  double absolute_memory_delta = now_ru.ru_maxrss / 1024.0;

  return boost::str(boost::format("%.2f secs CPU, %.2f MB memory, %.2f secs elapsed") %
                    absolute_cpu_delta % absolute_memory_delta % absolute_clock_delta.count());
}

PharosLimits::PharosLimits(const ProgOptVarMap &vm)
{
  timeout = vm.get<double>("timeout", "pharos.timeout");
  relative_timeout = vm.get<double>("reltimeout", "pharos.relative_timeout");

  partitioner_timeout = vm.get<double>("ptimeout", "pharos.partitioner_timeout");
  relative_partitioner_timeout = vm.get<double>("preltimeout", "pharos.relative_partitioner_timeout");

  maxmem = vm.get<double>("maxmem", "pharos.maxmem");
  relative_maxmem = vm.get<double>("relmaxmem", "pharos.relative_maxmem");

  block_counter_limit = vm.get<int>("blockcounterlimit", "pharos.block_counter_limit");
  func_counter_limit = vm.get<int>("funccounterlimit", "pharos.func_counter_limit");
}

void PharosLimits::set_clock_limits(ResourceLimit &limit, limit_type ltype) const
{
  switch (ltype) {
   case limit_type::BASE:
   case limit_type::FUNC:
    if (timeout && relative_timeout) {
      limit.set_clock_limits(*relative_timeout, *timeout);
    }
    break;
   case limit_type::PARTITIONER:
    if (partitioner_timeout && relative_partitioner_timeout) {
      limit.set_clock_limits(*relative_partitioner_timeout, *partitioner_timeout);
    }
    break;
  }
}

void PharosLimits::set_cpu_limits(ResourceLimit &limit, limit_type ltype) const
{
  switch (ltype) {
   case limit_type::BASE:
   case limit_type::FUNC:
    if (timeout && relative_timeout) {
      limit.set_cpu_limits(*relative_timeout, *timeout);
    }
    break;
   case limit_type::PARTITIONER:
    if (partitioner_timeout && relative_partitioner_timeout) {
      limit.set_cpu_limits(*relative_partitioner_timeout, *partitioner_timeout);
    }
    break;
  }
}

void PharosLimits::set_counter_limit(ResourceLimit &limit, limit_type ltype) const {
  switch (ltype) {
   case limit_type::BASE:
   case limit_type::PARTITIONER:
    if (block_counter_limit) {
      limit.set_counter_limit(*block_counter_limit);
    }
    break;
   case limit_type::FUNC:
    if (func_counter_limit) {
      limit.set_counter_limit(*func_counter_limit);
    }
    break;
  }
}

const PharosLimits &get_global_limits()
{
  static PharosLimits limits(get_global_options_vm());
  return limits;
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
