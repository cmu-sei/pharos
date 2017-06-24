// Copyright 2017 Carnegie Mellon University.  See LICENSE file for terms.

#ifndef Pharos_Md5_H
#define Pharos_Md5_H


#include <cstdint>
#include <string>
#include <vector>

#ifdef HAVE_OPENSSL
extern "C" {
#include <openssl/md5.h>
}
#else

/* Any 32-bit or wider unsigned integer data type will do */
typedef std::uint32_t MD5_u32plus;

typedef struct {
  MD5_u32plus lo, hi;
  MD5_u32plus a, b, c, d;
  unsigned char buffer[64];
  MD5_u32plus block[16];
} MD5_CTX;
#endif

namespace pharos {

class MD5;

class MD5Result {
 public:
  std::string str() const;
  unsigned char const * value() const {
    return _value;
  }
  std::vector<uint8_t> bytes() const;

  MD5Result(const MD5Result &) = default;

 private:
  MD5Result() = default;
  unsigned char _value[16];
  friend class MD5;
};


class MD5 : public MD5_CTX {
 public:
  MD5();
  MD5(void const *data, size_t size) : MD5() {
    update(data, size);
  }
  MD5(std::string const & str) : MD5(str.data(), str.size()) {}
  void update(void const * data, size_t size);
  MD5Result finalize();

  static MD5Result from_file(std::string const & filename);
};

} // namespace pharos

#endif // Pharos_Md5_H

/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
