// Copyright 2018-2019 Carnegie Mellon University.  See LICENSE file for terms.

#include "memory.hpp"
#include "state.hpp"
#include "descriptors.hpp"
#include <sstream>

namespace pharos {

std::size_t Memory::read_bytes(rose_addr_t addr, void *buf, Bytes bytes) const {
  return memmap->at(addr).limit(bytes).read((uint8_t *)buf).size();
}

void Memory::read_bytes_strict(rose_addr_t addr, void *buf, Bytes bytes) const {
  auto size = read_bytes(addr, buf, bytes);
  if (size != bytes) {
    std::stringstream ss;
    ss << "read_bytes_script: request to read " << bytes << " bytes at " << addr_str(addr) << " failed because only " << size << " bytes were read from the image";
    throw std::runtime_error(ss.str());
  }
}

std::string Memory::read_string(rose_addr_t addr, Bytes bytes) const
{
  std::string retval(bytes, char());
  std::size_t nread = read_bytes(addr, &retval.front(), bytes);
  retval.resize(nread);
  return retval;
}

std::string Memory::read_hex_string(rose_addr_t addr, Bytes bytes) const
{
  std::ostringstream result;
  result << std::hex << std::uppercase << std::setfill('0');
  // ReadVector takes a third argument for required permissions, and by default it requires
  // that the bytes be readable.  I'm not convinced we actually want that but it shouldn't be a
  // huge problem either.  If bytes go missing, check whether they're readable.
  for (auto byte : memmap->readVector(addr, bytes)) {
    result << std::setw(2) << (int)byte;
  }
  return result.str();
}

std::pair<std::size_t, std::unique_ptr<Sawyer::Container::BitVector> >
Memory::read_bits(rose_addr_t addr, Bits bits) const
{
  auto bv = make_unique<Sawyer::Container::BitVector>(bits);
  std::size_t nread = read_bytes(addr, bv->data(), bits);
  std::size_t read_bits = nread << 3;
  read_bits = std::min(bits(), read_bits);

  return std::make_pair(read_bits, std::move(bv));
}

SymbolicValuePtr Memory::read_value(rose_addr_t addr, Bits nbits) const
{
  auto bv = read_bits(addr, nbits);
  if (tget<std::size_t>(bv) == nbits) {
    return SymbolicValue::treenode_instance(
      SymbolicExpr::makeIntegerConstant(
        *tget<std::unique_ptr<Sawyer::Container::BitVector>>(bv)));
  }
  return SymbolicValuePtr();
}

SymbolicValuePtr Memory::read_value(
  SymbolicState const & state, SymbolicValuePtr const & addr, Bits bits) const
{
  auto val = state.read_memory(addr, bits);
  if (val) {
    return val;
  }
  const auto & exp = addr->get_expression();
  if (exp && exp->isIntegerConstant()) {
    return read_value(*exp->toUnsigned(), bits);
  }
  return SymbolicValuePtr{};
}

rose_addr_t Memory::read_address(rose_addr_t addr) const {
  return read_address(addr, Bytes(global_arch_bytes));
}

rose_addr_t Memory::read_address(rose_addr_t addr, Bytes arch_bytes) const
{
  rose_addr_t naddr = 0;
  if (arch_bytes == 4) {
    int32_t buff;
    std::size_t nread = read_bytes(addr, &buff, Bytes(sizeof(buff)));
    if (nread == sizeof(buff)) naddr = buff;
  }
  else if (arch_bytes == 8) {
    int64_t buff;
    std::size_t nread = read_bytes(addr, &buff, Bytes(sizeof(buff)));
    if (nread == sizeof(buff)) naddr = buff;
  }
  return naddr;
}

bool Memory::is_mapped(rose_addr_t addr) const {
  // The zero is a mask meaning we don't care what the protection bits are?
  return memmap->at(addr).exists(0);
}

} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
