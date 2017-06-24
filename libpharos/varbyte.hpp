// Copyright 2015 Carnegie Mellon University.  See LICENSE file for terms.

// a class to handle a Variable Byte encoding scheme for various UInt types (uint32_t or uint64_t)
// simple variable byte encoding, high bit set == more bytes follow, so:
//   0 - 127 => 1 byte
//   128 - 16.383 => 2 bytes
//   16.384 - 2.097.151 => 3 bytes
//   2.097.152 - 268.435.455 => 4 bytes
//   268.435.456 - UINT32_MAX => 5 bytes
//   etc

#ifndef __VARBYTE_HPP_INCLUDED___
#define __VARBYTE_HPP_INCLUDED___

#define __STDC_LIMIT_MACROS // I have to define this to get UINT32_MAX because of the ISO C99 standard, apparently
#include <stdint.h>

#include <vector>


template < typename T >
class VarByteUInt
{
public:
  // constructors
  //VarByteUInt< T >::VarByteUInt(T val):
  VarByteUInt(T val):
    _val(val)
  {
  }
  //VarByteUInt< T >::VarByteUInt(std::vector< uint8_t > &enc_val):
  VarByteUInt(std::vector< uint8_t > &enc_val):
    _enc_val(enc_val)
  {
  }

  // copy constructor
  //VarByteUInt< T >::VarByteUInt (VarByteUInt< T > const & rhs)
  //VarByteUInt (VarByteUInt< T > const & rhs)
  //{
  //  this->_val = rhs._val;
  //  this->_enc_val = rhs._enc_val;
  //}
  // copy assignment operator
  //VarByteUInt< T > &VarByteUInt< T >::operator=(VarByteUInt< T > const & rhs)
  //VarByteUInt & operator=(VarByteUInt< T > const & rhs)
  //{
  //  this->_val = rhs._val;
  //  this->_enc_val = rhs._enc_val;
  //}

  std::vector< uint8_t >& encode()
  {
    if (_enc_val.size() == 0)
    {
      T tval(_val);
      do
      {
        uint8_t bval(tval & 0x7F);
        tval >>= 7;
        if (tval > 0)
        {
          bval |= 0x80;
        }
        _enc_val.push_back(bval);
      } while (tval > 0);
    }
    return _enc_val;
  }

  // so you can reuse the same object for multiple encodings (better copy the vector ref off):
  std::vector< uint8_t >& encode(T newval)
  {
    _val = newval;
    _enc_val.clear();
    return encode();
  }

  T decode()
  {
    T retval(0);
    int num(_enc_val.size());
    int i(0);
    while (i < num)
    {
      uint8_t bval(_enc_val[i]);
      retval |= (T((bval & 0x7f)) << (7*i++));
      // for stream processing, would check this:
      // if (bval & 0x80 != 0) break;
      // but since we have a vector, we know how many to process...
    }
    _val = retval;
    return retval;
  }

  // for "stream" decoding of a pointer to an array of uint8_t or char:
  T decode(uint8_t *dp,uint8_t*count = NULL)
  {
    T retval(0);
    bool done(dp==NULL);
    uint8_t i(0);
    while (!done)
    {
      uint8_t bval(dp[i]);
      if ((bval & 0x80) == 0)
      {
        done = true;
      }
      retval |= (T((bval & 0x7f)) << (7*i++));
      // probably should look for i to be above 9 too and bail if that happens?
    }
    if (count != NULL)
    {
      (*count) = i;
    }
    _val = retval;
    return retval;
  }

private:
  T _val;
  std::vector< uint8_t > _enc_val;
};


#endif // __VARBYTE_HPP_INCLUDED___

