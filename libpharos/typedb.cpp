// Copyright 2016, 2017 Carnegie Mellon University.  See LICENSE file for terms.

#include "typedb.hpp"
#include "descriptors.hpp"
#include <stdexcept>
#include <cassert>
#include <locale>
#include <boost/locale/encoding_utf.hpp>
#include <boost/range/adaptor/reversed.hpp>

namespace pharos {

template<> char const* EnumStrings<types::Signedness>::data[] = {
  "Top",
  "Signed",
  "Unsigned",
  "Bottom"
};

template<> char const* EnumStrings<types::Pointerness>::data[] = {
  "Top",
  "Pointer",
  "NotPointer",
  "Bottom"
};

namespace typedb {

using boost::locale::conv::utf_to_utf;

using ParseError = std::runtime_error;

size_t Type::arch_bytes() const {
  return global_descriptor_set->get_arch_bytes();
}

static SymbolicValuePtr program_bits(rose_addr_t addr, size_t nbits)
{
  auto bv = global_descriptor_set->read_addr_bits(addr, nbits);
  if (tget<size_t>(bv) == nbits) {
    return SymbolicValue::treenode_instance(
      LeafNode::createConstant(*tget<std::unique_ptr<Sawyer::Container::BitVector>>(bv)));
  }
  return SymbolicValuePtr();
}

static SymbolicValuePtr memory_value(
  const SymbolicState & memory,
  const SymbolicValuePtr & addr,
  size_t bits)
{
  auto val = memory.read_memory(addr, bits);
  if (val) {
    return val;
  }
  const auto & exp = addr->get_expression();
  if (exp && exp->isNumber()) {
    return program_bits(exp->toInt(), bits);
  }
  return SymbolicValuePtr();
}

Value Type::get_value(
    const SymbolicValuePtr & value,
    const SymbolicState * memory) const
{
  return Value(ptr(), value, memory);
}

void Pointer::update(const DB & db) {
  if (pointed_to->is_unknown()) {
    pointed_to = db.lookup(pointed_to->get_name());
  }
}

void Struct::update(const DB & db) {
  for (auto & value : members) {
    if (value.type->is_unknown()) {
      value.type = db.lookup(value.type->get_name());
    }
  }
}

std::string Pointer::generate_name(const TypeRef & t)
{
  return t->get_name() + "*";
}

void Struct::init()
{
  align = 0;
  size = 0;
  for (auto & param : members) {
    size_t t_size = param.type->get_size();
    size_t t_align = param.type->get_align();
    if (size & (t_align - 1)) {
      size = (size & ~(t_align - 1)) + t_align;
    }
    param.offset = size;
    size += t_size;
    align = std::max(align, t_align);
  }
}

bool handle_node(DB & db, const YAML::Node & node, DB::handle_error_t handle)
{
  switch (node.Type()) {
   case YAML::NodeType::Scalar:
    {
      auto path = Path(node.Scalar());
      if (!path.has_root_directory()) {
        path = get_default_libdir() / path;
      }
      if (is_directory(path)) {
        // Assume the directory contains per-DLL json files
        // Currently these are ignored
        return true;
      }
      try {
        // Determine whether this is a sqlite file or a json file
        std::ifstream file(path.native());
        if (!file) {
          throw std::runtime_error("Could not open for read");
        }

        // Read the first few bytes to see of the file match the SQLite magic prologue
        static constexpr char sqlite_magic[] = "SQLite";
        constexpr auto len = sizeof(sqlite_magic) - 1;
        char prologue[len];
        file.read(prologue, len);
        bool correct_size = file.gcount() == len;
        file.close();
        if (correct_size && std::equal(prologue, prologue + len, sqlite_magic)) {
          // Ignore this file, as the sqlite apidb does't yet have type information
          return true;
        } else {
          // Assume a json file
          db.load_json(path);
          return true;
        }
      } catch (const std::runtime_error & e) {

        std::ostringstream os;
        os << "Unable to load type database: " << path << '\n'
           << "Reason: " << e.what();
        switch (handle) {
         case DB::IGNORE:
          break;
         case DB::LOG_WARN:
          GWARN << os.str() << LEND;
          break;
         case DB::LOG_ERROR:
          GERROR << os.str() << LEND;
          break;
         case DB::THROW:
          throw std::runtime_error(os.str());
        }
        return false;
      }
    }
   case YAML::NodeType::Sequence:
    {
      std::vector<YAML::Node> nodes;
      std::copy(node.begin(), node.end(), std::back_inserter(nodes));
      bool all_success = true;
      for (auto item : boost::adaptors::reverse(nodes)) {
        all_success &= handle_node(db, item, handle);
      }
      return all_success;
    }
   case YAML::NodeType::Map:
    try {
      db.load_json(node, "<internal>");
      return true;
    } catch (const std::runtime_error & e) {
      switch (handle) {
       case DB::IGNORE:
        break;
       case DB::LOG_WARN:
       case DB::LOG_ERROR:
        {
          auto & err = glog[(handle == DB::LOG_WARN)
                            ? Sawyer::Message::WARN : Sawyer::Message::ERROR];
          err && err << "Error in type database\n"
                     << "Reason: " << e.what() << LEND;
        }
        break;
       case DB::THROW:
        throw;
      }
      return false;
    }
   default:
    throw ParseError("Illegal type of node in pharos.typedb parsing");
  }
}

DB DB::create_standard(const ProgOptVarMap &vm, handle_error_t handle)
{
  auto db = DB();

  if (vm.count("apidb")) {
    // If it's listed on the command line, use that.
    for (auto & filename : vm["apidb"].as<std::vector<std::string>>()) {
      handle_node(db, YAML::Node(filename), THROW);
    }
  }

  auto typedb = vm.config().path_get("pharos.typedb");
  if (typedb) {
    handle_node(db, typedb.as_node(), handle);
  }

  return db;
}

TypeRef DB::lookup(const std::string & name) const {
  DB * mdb = const_cast<DB *>(this);
  return mdb->internal_lookup(name);
}

const std::shared_ptr<Type> & DB::internal_lookup(const std::string & name) {
  auto found = db.find(name);
  if (found != db.end()) {
    return found->second;
  }
  DB * mdb = const_cast<DB *>(this);
  auto result = mdb->db.emplace(name, std::make_shared<UnknownType>(name));
  return result.first->second;
}

void DB::load_json(const Path & path)
{
  auto filename = path.native();
  const auto filenode = YAML::LoadFile(filename);
  if (!filenode.IsMap()) {
    throw ParseError("File is not a map: " + filename);
  }
  auto types = filenode["config"]["types"];
  if (types) {
    load_json(types, filename);
  }
}

struct CouldNotFind : public std::runtime_error
{
  CouldNotFind(const std::string & n, const std::string & v)
    : std::runtime_error(generate(n, v)), name(n), value(v)
  {}

  static std::string generate(const std::string & n, const std::string & v) {
    std::ostringstream os;
    os << "Could not find definition of " << v << " when defining " << n;
    return os.str();
  }

  std::string name;
  std::string value;
};

void DB::load_json(const YAML::Node & typemap, const std::string & filename)
{
  if (!typemap.IsMap()) {
    throw ParseError("\"types\" is not a map or doesn't exist: " + filename);
  }
  std::list<CouldNotFind> failed;
  for (auto value : typemap) {
    auto nname = value.first;
    if (!nname.IsScalar()) {
      throw ParseError("non-string type-name: " + filename);
    }
    try {
      add_type(nname.Scalar(), value.second);
    } catch (const CouldNotFind & cnf) {
      failed.push_back(cnf);
    }
  }

  // Re-lookup failed lookups
  bool modified = true;
  while (modified && !failed.empty()) {
    modified = false;
    auto cur = failed.begin();
    while (cur != failed.end()) {
      auto found = db.find(cur->value);
      if (found == db.end()) {
        ++cur;
      } else {
        db[cur->name] = found->second;
        auto del = cur;
        ++cur;
        failed.erase(del);
        modified = true;
      }
    }
  }

  if (!failed.empty()) {
    throw(failed.front());
  }

  update();
}

void DB::add_type(const std::string & name, const YAML::Node & node)
{
  try {
    std::shared_ptr<Type> type;
    if (node.IsScalar()) {
      const std::string & nname = node.Scalar();
      if (nname == "string") {
        // Ascii string
        type = std::make_shared<String>(name, String::CHAR);
      } else if (nname == "wstring") {
        // Wide String
        type = std::make_shared<String>(name, String::WCHAR);
      } else if (nname == "tstring") {
        // Variable string
        type = std::make_shared<String>(name, String::TCHAR);
      } else if (nname == "void*") {
        // Void *
        type = std::make_shared<Pointer>(name, lookup("void"));
      } else if (nname == "bool") {
        // Bool
        type = std::make_shared<Bool>(name);
      } else {
        auto found = db.find(nname);
        if (found != db.end()) {
          type = found->second;
        } else {
          throw CouldNotFind(name, nname);
        }
      }
    } else if (node.IsMap()) {
      auto ftype = node["type"];
      if (!ftype.IsScalar()) {
        throw ParseError("Non-string or no \"type\" field parsing " + name);
      }
      const std::string & ftname = ftype.Scalar();

      if (ftname == "unsigned" || ftname == "signed" || ftname == "float") {
        // Unsigned, Signed, and Float
        auto nsize = node["size"];
        if (!nsize.IsScalar()) {
          throw ParseError("Non-integer or no \"size\" field parsing " + name);
        }
        size_t size;
        if (nsize.Scalar() == "arch") {
          size = global_descriptor_set->get_arch_bytes();
        } else {
          size = nsize.as<size_t>();
        }
        if (ftname == "unsigned") {
          type = std::make_shared<Unsigned>(name, size);
        } else if (ftname == "signed") {
          type = std::make_shared<Signed>(name, size);
        } else if (ftname == "float") {
          type = std::make_shared<Float>(name, size);
        } else {
          assert(false);
        }
      } else if (ftname == "pointer") {
        // Pointer
        auto vnode = node["value"];
        if (!vnode.IsScalar()) {
          throw ParseError("Non-string or no \"value\" field parsing " + name);
        }
        const std::string & value = vnode.Scalar();
        type = std::make_shared<Pointer>(name, lookup(value));
      } else if (ftname == "struct") {
        auto vnode = node["value"];
        if (!vnode.IsSequence()) {
          throw ParseError("Non-array or no \"value\" field parsing " + name);
        }
        ParamList params;
        for (auto pnode : vnode) {
          if (!pnode.IsMap()) {
            throw ParseError("Non-map element in \"value\" field parsing " + name);
          }
          auto pnnode = pnode["name"];
          if (!pnnode.IsScalar()) {
            throw ParseError("Non-string element name in \"value\" field parsing " + name);
          }
          auto ptnode = pnode["type"];
          if (!ptnode.IsScalar()) {
            throw ParseError("Non-string element type in \"value\" field parsing " + name);
          }
          params.emplace_back(lookup(ptnode.Scalar()), pnnode.Scalar());
        }
        type = std::make_shared<Struct>(name, std::move(params));
      } else if (ftname == "unknown") {
        auto nsize = node["size"];
        size_t size = 1;
        if (nsize) {
          if (!nsize.IsScalar()) {
            throw ParseError("Non-integer \"size\" field parsing " + name);
          }
          size = nsize.as<size_t>();
          type = std::make_shared<UnknownType>(name, size);
        }
      } else {
        throw ParseError("Unknown type: " + ftname + " parsing " + name);
      }
    } else {
      throw ParseError("Non-string, non-map type node parsing " + name);
    }

    db[name] = type;

  } catch (const YAML::BadConversion & b) {
    throw ParseError("Bad conversion parsing " + name + ": " + b.what());
  }
}

void DB::update()
{
  for (auto & data : db) {
    data.second->update(*this);
  }
}

bool Value::is_pointer() const {
  return dynamic_cast<const Pointer *>(type.get());
}

bool Value::is_string() const {
  return dynamic_cast<const String *>(type.get());
}

bool Value::is_unsigned() const {
  return dynamic_cast<const Unsigned *>(type.get());
}

bool Value::is_signed() const {
  return dynamic_cast<const Signed *>(type.get());
}

bool Value::is_bool() const {
  return dynamic_cast<const Bool *>(type.get());
}

bool Value::is_struct() const {
  return dynamic_cast<const Struct *>(type.get());
}

template <typename T>
boost::optional<T> interpret(const TreeNodePtr & tn);

template <>
boost::optional<uint64_t> interpret<uint64_t>(const TreeNodePtr & tn)
{
  if (tn && tn->isNumber()) {
    return tn->toInt();
  }
  return boost::none;
}

template <>
boost::optional<int64_t> interpret<int64_t>(const TreeNodePtr & tn)
{
  auto x = interpret<uint64_t>(tn);
  if (x) {
    return int64_t(*x);
  }
  return boost::none;
}

template <>
boost::optional<bool> interpret<bool>(const TreeNodePtr & tn)
{
  auto x = interpret<uint64_t>(tn);
  if (x) {
    return bool(*x);
  }
  return boost::none;
}

boost::optional<uint64_t> Value::as_unsigned() const
{
  if (!is_unsigned()) {
    throw IllegalConversion("Cannot call as_unsigned on non-Unsigned");
  }
  if (node) {
    return interpret<uint64_t>(node->get_expression());
  }
  return boost::none;
}

boost::optional<int64_t> Value::as_signed() const
{
  if (!is_signed()) {
    throw IllegalConversion("Cannot call as_signed on non-Signed");
  }
  if (node) {
    return interpret<int64_t>(node->get_expression());
  }
  return boost::none;
}

boost::optional<bool> Value::as_bool() const
{
  if (!is_bool()) {
    throw IllegalConversion("Cannot call as_bool on non-Bool");
  }
  if (node) {
    return interpret<bool>(node->get_expression());
  }
  return boost::none;
}

template <typename Char>
boost::optional<std::basic_string<Char>> parse_string_value(
  const SymbolicState & memory,
  const TreeNodePtr & base)
{
  std::basic_string<Char> result;
  for (size_t i = 0; true; i += sizeof(Char)) {
    auto addr = base + i;
    auto sym = SymbolicValue::treenode_instance(addr);
    auto c = memory_value(memory, sym, sizeof(Char) * CHAR_BIT);
    if (c) {
      auto & cexp = c->get_expression();
      if (cexp && cexp->isNumber()) {
        Char n = std::char_traits<Char>::to_char_type(
          (typename std::char_traits<Char>::int_type)(cexp->toInt()));
        if (n) {
          result.push_back(n);
          continue;
        } else {
          return result;
        }
      }
    }
    break;
  }
  return boost::none;
}

boost::optional<std::string> Value::as_string(bool wide) const
{
  if (!node) {
    return boost::none;
  }
  const String * s = dynamic_cast<const String *>(type.get());
  auto & exp = node->get_expression();
  if (exp && exp->isNumber() && exp->toInt() == 0) {
    return boost::none;
  } else if (memory) {
    if (s->get_string_type() == String::WCHAR ||
        (s->get_string_type() == String::TCHAR && wide))
    {
      auto result = parse_string_value<char16_t>(*memory, exp);
      if (result) {
        return utf_to_utf<char>(*result);
      }
    } else {
      return parse_string_value<char>(*memory, exp);
    }
  }
  return boost::none;
}

Value Value::val_from_param(const Param & param) const
{
  auto ptr = std::make_shared<Pointer>(param.type);
  auto val = ptr->get_value(node + param.offset, memory).dereference();
  return val;
}

Value::type_range Value::member_types() const
{
  const Struct * s = dynamic_cast<const Struct *>(type.get());
  if (!s) {
    throw IllegalConversion("Illegal call on non-Struct");
  }
  return boost::make_iterator_range(s->begin(), s->end());
}

Value::value_range Value::member_values() const
{
  return (member_types() | boost::adaptors::transformed(
            val_from_param_wrapper(this)));
}

Value::vpair_range Value::members() const
{
  return (member_types() | boost::adaptors::transformed(
            vpair_from_param_wrapper(this)));
}

bool Value::is_nullptr() const
{
  if (node && (is_pointer() || is_string())) {
    auto & exp = node->get_expression();
    return exp && exp->isNumber() && exp->toInt() == 0;
  }
  return false;
}

Value Value::dereference() const
{
  auto p = dynamic_cast<const Pointer *>(type.get());
  if (!p) {
    throw IllegalConversion("Cannot dereference non-pointer");
  }
  auto & t = p->get_contained();
  if (!node) {
    return t->get_value(node, memory);
  }
  auto & exp = node->get_expression();
  if (exp && exp->isNumber() && exp->toInt() == 0) {
    throw IllegalConversion("Cannot dereference NULL");
  }
  if (!memory) {
    return Value(t);
  }
  if (dynamic_cast<const Struct *>(t.get())) {
    return Value(t, node, memory);
  }
  auto v = memory_value(*memory, node, t->get_size() * CHAR_BIT);
  return Value(t, v, memory);
}

} // namespace typedb
} // namespace pharos

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
