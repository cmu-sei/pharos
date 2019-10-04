// Copyright 2018-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "threads.hpp"
#include <limits>
#include <cassert>

namespace pharos {

#if !defined(PHAROS_BROKEN_THREADS) && !defined(__cpp_lib_shared_mutex) && !defined(__cpp_lib_shared_timed_mutex)

namespace detail {

void shared_mutex::lock() noexcept
{
  std::unique_lock<std::mutex> lk(mutex);
  cond.wait(lk, [this]{ return count == 0; });
  count = -1;
  lk.unlock();
}

bool shared_mutex::try_lock() noexcept
{
  std::lock_guard<std::mutex> guard(mutex);
  if (count == 0) {
    count = -1;
    return true;
  }
  return false;
}

void shared_mutex::unlock() noexcept
{
  {
    std::lock_guard<std::mutex> guard(mutex);
    assert(count == -1);
    count = 0;
  }
  cond.notify_one();
}

void shared_mutex::lock_shared() noexcept
{
  std::unique_lock<std::mutex> lk(mutex);
  cond.wait(lk, [this]{
    return (count >= 0 && count != std::numeric_limits<decltype(count)>::max());});
  ++count;
  lk.unlock();
}

void shared_mutex::unlock_shared() noexcept
{
  decltype(count) count_copy;
  {
    std::lock_guard<std::mutex> guard(mutex);
    assert(count > 0);
    count_copy = count;
    --count;
  }
  if (count_copy == 1) {
    cond.notify_one();
  } else if (count_copy == std::numeric_limits<decltype(count)>::max()) {
    cond.notify_all();
  }
}

bool shared_mutex::try_lock_shared() noexcept
{
  std::lock_guard<std::mutex> guard(mutex);
  if (count < 0 || count == std::numeric_limits<decltype(count)>::max()) {
    return false;
  }
  ++count;
  return true;
}

} // namespace detail

#endif // !defined(__cpp_lib_shared_mutex)

bool ThreadPool::add_task(task_t && task)
{
  std::unique_lock<std::mutex> lk(mutex);
  if (shutdown) {
    return false;
  }
  if (tasks.empty() && num_threads < max_threads) {
    threads.emplace_back(&ThreadPool::thread_function, this);
  }
  tasks.push_back(std::move(task));
  cond.notify_one();
  return true;
}

void ThreadPool::thread_function() {
  while (true) {
    std::unique_lock<std::mutex> lk(mutex);
    while (true)
      cond.wait(lk, [this](){ return shutdown || !tasks.empty(); });
    if (shutdown) {
      return;
    }
    task_t task = std::move(tasks.back());
    tasks.pop_back();
    lk.unlock();
    task(shutdown);
  }
}

ThreadPool::~ThreadPool()
{
  cond.notify_one();
  for (auto & thread : threads) {
    thread.join();
  }
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
