// Copyright 2018 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Memory_H
#define Pharos_Memory_H

#include <cstddef>
#include "semantics.hpp"

namespace pharos {

namespace detail {
template <typename SizeType>
class SizedType {
 public:
  using size_type = SizeType;
  explicit constexpr SizedType(size_type v = size_type()) noexcept : val(v) {}
  constexpr size_type operator()() const noexcept { return val; }
  constexpr operator size_type() const noexcept { return val; }
 private:
  size_type val;
};
}

class Bits;
class Bytes;

class Bytes : public detail::SizedType<std::size_t> {
 public:
  using detail::SizedType<std::size_t>::SizedType;
  constexpr Bytes(Bits const & bits) noexcept;
};

class Bits : public detail::SizedType<std::size_t> {
 public:
  using detail::SizedType<std::size_t>::SizedType;
  constexpr Bits(Bytes const & bytes) noexcept;
};

constexpr Bytes::Bytes(Bits const & bits) noexcept : Bytes((bits >> 3) + bool(bits & 7)) {}
constexpr Bits::Bits(Bytes const & bytes) noexcept : Bits(bytes << 3) {}

class Memory
{
 public:
  using MapPtr = Sawyer::SharedPointer<MemoryMap>;
  using MapConstPtr = Sawyer::SharedPointer<const MemoryMap>;

 private:
  MapPtr memmap;

 public:
  Memory() = default;
  Memory(MapPtr const & ptr) : memmap(ptr) {}

  void set_memmap(MapPtr const & map) {
    memmap = map;
  }

  MapPtr get_memmap() {
    return memmap;
  }

  MapConstPtr get_memmap() const {
    return memmap;
  }

  explicit operator bool() const {
    return memmap;
  }


  std::size_t read_bytes(rose_addr_t addr, void *buf, Bytes bytes) const;
  void read_bytes_strict(rose_addr_t addr, void *buf, Bytes bytes) const;

  std::string read_string(rose_addr_t addr, Bytes bytes) const;
  std::string read_hex_string(rose_addr_t addr, Bytes bytes) const;

  std::pair<std::size_t, std::unique_ptr<Sawyer::Container::BitVector> >
  read_bits(rose_addr_t addr, Bits bits) const;

  SymbolicValuePtr read_value(rose_addr_t addr, Bits nbits) const;

  SymbolicValuePtr read_value(
    SymbolicState const & state,
    SymbolicValuePtr const & addr,
    Bits bits) const;

  rose_addr_t read_address(rose_addr_t addr, Bytes arch_bytes) const;
  rose_addr_t read_address(rose_addr_t addr) const;

  bool is_mapped(rose_addr_t addr) const;
};

} // namespace pharos

#endif // Pharos_Memory_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
