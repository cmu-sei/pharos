// Copyright 2018-2019 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Threads_H
#define Pharos_Threads_H

#include <mutex>
#include <condition_variable>
#include <thread>
#include <utility>
#include <list>
#include <functional>
#include <type_traits>

#if __cplusplus >= 201402L
# include <shared_mutex>
#endif

#include <boost/range/iterator_range_core.hpp>

namespace pharos {

namespace detail {

class dummy_mutex
{
 public:
  void lock() noexcept {}
  bool try_lock() noexcept {return true;}
  void unlock() noexcept {}
  void lock_shared() noexcept {}
  void unlock_shared() noexcept {}
  bool try_lock_shared() noexcept {return true;}
};

#ifdef PHAROS_BROKEN_THREADS
using shared_mutex = dummy_mutex;
#elif defined(__cpp_lib_shared_mutex)
using std::shared_mutex;
#elif defined(__cpp_lib_shared_timed_mutex)
using shared_mutex = std::shared_timed_mutex;
#else
class shared_mutex
{
 private:
  std::mutex mutex;
  std::condition_variable cond;
  int count = 0;

 public:
  void lock() noexcept;
  bool try_lock() noexcept;
  void unlock() noexcept;
  void lock_shared() noexcept;
  void unlock_shared() noexcept;
  bool try_lock_shared() noexcept;
};
#endif  // shared_mutex

#ifdef PHAROS_BROKEN_THREADS
using std_mutex = dummy_mutex;
#else
using std_mutex = std::mutex;
#endif

#if defined(__cpp_lib_shared_mutex) || defined(__cpp_lib_shared_timed_mutex)
template <typename Mutex>
struct shared_lock : std::shared_lock<Mutex> {
  using std::shared_lock<Mutex>::shared_lock;
};
#else
template <typename Mutex>
class shared_lock {
  Mutex * mutex;
 public:
  shared_lock(Mutex & m) noexcept(noexcept(m.lock_shared())) : mutex(&m) {
    mutex->lock_shared();
  }
  shared_lock(Mutex & m, std::adopt_lock_t) : mutex(&m) {}
  shared_lock(shared_lock && other) noexcept {
    std::swap(mutex, other.mutex);
  }
  ~shared_lock() {
    if (mutex) {
      mutex->unlock_shared();
    }
  }
  shared_lock & operator=(shared_lock & other) noexcept {
    std::swap(mutex, other.mutex);
    return *this;
  }
  shared_lock(shared_lock const &) = delete;
  shared_lock & operator=(shared_lock const &) = delete;
};
#endif  // shared_lock

template <>
struct shared_lock<std::mutex> : std::lock_guard<std::mutex> {
  using std::lock_guard<std::mutex>::lock_guard;
};

struct WriteLock {
  template <typename T>
  static void lock(T & t) { t.lock(); }
  template <typename T>
  static void unlock(T & t) { t.unlock(); }
};

struct ReadLock {
  template <typename T>
  static void lock(T & t) { t.lock_shared(); }
  template <typename T>
  static void unlock(T & t) { t.unlock_shared(); }
};


template <typename... Ts> struct make_void { using type = void; };
template <typename... Ts> using void_t = typename make_void<Ts...>::type;

template <typename, typename = void_t<>>
struct has_size : std::false_type {};

template <typename T>
struct has_size<T, void_t<decltype(std::declval<T&>().size())>> : std::true_type {};

template <typename T, std::enable_if_t<has_size<T>::value>* = nullptr>
auto range_size(T & r) {
  return r.size();
}

template <typename T, std::enable_if_t<(!has_size<T>::value)>* = nullptr>
auto range_size(T & r) {
  return std::distance(r.begin(), r.end());
}

template <typename T, typename = void_t<>, typename = void_t<>>
struct has_begin_end : std::false_type {};
template <typename T>
struct has_begin_end<T, void_t<decltype(std::declval<T&>().begin())>,
                     void_t<decltype(std::declval<T&>().end())>> : std::true_type {};

template <typename, typename = void_t<>>
struct is_lockable : std::false_type {};
template <typename T>
struct is_lockable<T, void_t<decltype(std::declval<T&>().lock())>> : std::true_type {};
template <typename, typename = void_t<>>
struct is_unlockable : std::false_type {};
template <typename T>
struct is_unlockable<T, void_t<decltype(std::declval<T&>().unlock())>> : std::true_type {};
template <typename, typename = void_t<>>
struct is_shared_lockable : std::false_type {};
template <typename T>
struct is_shared_lockable<T, void_t<decltype(std::declval<T&>().shared_lock())>>
  : std::true_type {};
template <typename, typename = void_t<>>
struct is_shared_unlockable : std::false_type {};
template <typename T>
struct is_shared_unlockable<T, void_t<decltype(std::declval<T&>().shared_unlock())>>
  : std::true_type {};

template <typename T>
constexpr bool is_mutex() {
  return is_lockable<T>::value && is_unlockable<T>::value;
}

template <typename T>
constexpr bool is_shared_mutex() {
  return is_mutex<T>() && is_shared_lockable<T>::value && is_shared_unlockable<T>::value;
}

template <typename M>
struct shadow_mutex_base
{
 private:
  M mutex;
 public:
  shadow_mutex_base() = default;
  shadow_mutex_base(shadow_mutex_base const &) {};
  shadow_mutex_base(shadow_mutex_base &&) {}
  shadow_mutex_base & operator=(shadow_mutex_base &&) { return *this; }
  shadow_mutex_base & operator=(shadow_mutex_base const &) { return *this; }
  void lock() { mutex.lock(); }
  void unlock() { mutex.unlock(); }
  M & actual() { return mutex; }
};

template <typename M, typename = void>
struct shadow_mutex : shadow_mutex_base<M> {
  using shadow_mutex_base<M>::shadow_mutex_base;
 private:
  using shadow_mutex_base<M>::mutex;
};

template <typename M>
struct shadow_mutex<M, std::enable_if_t<is_shared_mutex<M>()>> : shadow_mutex_base<M>
{
  using shadow_mutex_base<M>::shadow_mutex_base;
  void lock_shared() { this->actual().lock_shared(); }
  void unlock_shared() { this->actual().unlock_shared(); }
};

} // namespace detail

using detail::std_mutex;

template <typename M>
using read_guard = detail::shared_lock<M>;

template <typename M>
using write_guard = std::lock_guard<M>;

// Although the non-specialized version, this is the locked_range that is suitable for Sawyer
// containers that don't have begin and end methods
template <typename T, typename M, typename L, typename = void>
class locked_range
{
  using range_t = decltype(std::declval<T>().values());
  T const & collection;
  range_t range;
  M & mutex;
 public:
  using iterator = typename range_t::iterator;
  using const_iterator = typename range_t::const_iterator;

  locked_range(T const & t, M & m) : collection{t}, range{t.values()}, mutex{m} {
    L::lock(mutex);
  }
  ~locked_range() {
    L::unlock(mutex);
  }
  auto begin() const { return range.begin(); }
  auto end() const { return range.end(); }
  bool empty() const { return collection.isEmpty(); }
  auto size() const { return collection.size(); }
};

// The specialized version works for standard containers that have a begin/end
template <typename T, typename M, typename L>
class locked_range<T, M, L, std::enable_if_t<detail::has_begin_end<T>::value>>
{
  T const & collection;
  M & mutex;
 public:
  using iterator = decltype(std::declval<T>().begin());
  using const_iterator = decltype(std::declval<const T>().begin());

  locked_range(T const & t, M & m) : collection(t), mutex(m) {
    L::lock(mutex);
  }
  ~locked_range() {
    L::unlock(mutex);
  }
  auto begin() const { return const_cast<T const &>(collection).begin(); }
  auto end() const { return const_cast<T const &>(collection).end(); }
  bool empty() const { return begin() == end(); }
  auto size() const { return detail::range_size(collection); }
};


template <typename T, typename M>
auto make_write_locked_range(T && t, M & m) {
  return locked_range<T, M, detail::WriteLock>(std::forward<T>(t), m);
}

template <typename T, typename M>
auto make_read_locked_range(T && t, M & m) {
  return locked_range<T, M, detail::ReadLock>(std::forward<T>(t), m);
}

using detail::shared_mutex;

template <typename M>
using shadow_mutex = detail::shadow_mutex<M>;

class ThreadPool {
 public:
  using task_t = std::function<void(bool const &)>;

  ThreadPool(int max_threads_) : max_threads(max_threads_) {}
  ~ThreadPool();

  bool add_task(task_t && task);
  bool add_task(task_t const & task) {
    return add_task(task_t(task));
  }

 private:

  void thread_function();

  std::mutex mutex;
  std::condition_variable cond;
  std::list<task_t> tasks;
  std::list<std::thread> threads;
  int num_threads = 0;
  int max_threads;
  bool shutdown = false;
};

} // namespace pharos

#endif // Pharos_Threads_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
