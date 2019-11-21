#pragma once
#include <array>
#include <cstdarg>
#include <random>

#define MMIX(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }
#define DEBUG_PRINT(m,...) //printf(m,__VA_ARGS__)
#define BLOCK_SIZE 16

#define HIDE_STR(hide, s) auto hide = HideString<sizeof(s) - 1, __COUNTER__ >(s, std::make_index_sequence<sizeof(s) - 1>())
#define PRINT_HIDE_STR(s) (HideString<sizeof(s) - 1, __COUNTER__ >(s, std::make_index_sequence<sizeof(s) - 1>()).decrypt())

inline uint32_t Murmur3(const void *key, int len, unsigned int seed)
{
  const unsigned int m = 0x5bd1e995;
  const int r = 24;
  unsigned int l = len;
  const unsigned char *data = (const unsigned char *)key;
  unsigned int h = seed;
  unsigned int k;
  while (len >= 4)
  {
    k = *(unsigned int *)data;
    MMIX(h, k);
    data += 4;
    len -= 4;
  }
  unsigned int t = 0;
  switch (len)
  {
    case 3: t ^= data[2] << 16;
    case 2: t ^= data[1] << 8;
    case 1: t ^= data[0];
  };
  MMIX(h, t);
  MMIX(h, l);
  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;
  return h;
}

constexpr auto time = __TIME__;

constexpr auto seed =
  static_cast<int>(time[7]) + static_cast<int>(time[6]) * 10
  + static_cast<int>(time[4]) * 60 + static_cast<int>(time[3]) * 600
  + static_cast<int>(time[1]) * 3600 + static_cast<int>(time[0]) * 36000;

template <int N>
struct RandomGeneratorString
{
 private:
  static constexpr unsigned a = 16807;
  static constexpr unsigned m = 2147483647;
  static constexpr unsigned s = RandomGeneratorString < N - 1 >::value;
  static constexpr unsigned lo = a * (s & 0xFFFF);
  static constexpr unsigned hi = a * (s >> 16);
  static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16);
  static constexpr unsigned hi2 = hi >> 16;
  static constexpr unsigned lo3 = lo2 + hi;

 public:
  static constexpr unsigned max = m;
  static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
};

template <>
struct RandomGeneratorString< 0 >
{
  static constexpr unsigned value = seed;
};

template < int N, int M >
struct RandomInt
{
  static constexpr auto value = RandomGeneratorString < N + 1 >::value % M;
};

template < int N >
struct RandomChar
{
  static const char value = static_cast<char>(1 + RandomInt < N, 0x7F - 1 >::value);
};

class XTEA3
{
 public:
  uint8_t *data_ptr = nullptr;
  uint32_t size_crypt = 0;
  uint32_t size_decrypt_data = 0;

 protected:
  uint32_t rol(uint32_t base, uint32_t shift)
  {
    uint32_t res;
    /* only 5 bits of shift are significant*/
    shift &= 0x1F;
    res = (base << shift) | (base >> (32 - shift));
    return res;
  };

  void xtea3_encipher(unsigned int num_rounds, uint32_t *v, const uint32_t *k)
  {
    unsigned int i;
    uint32_t a, b, c, d, sum = 0, t, delta = 0x9E3779B9;
    sum = 0;
    a = v[0] + k[0];
    b = v[1] + k[1];
    c = v[2] + k[2];
    d = v[3] + k[3];
    for (i = 0; i < num_rounds; i++) {
      a += (((b << 4) + rol(k[(sum % 4) + 4], b)) ^
            (d + sum) ^ ((b >> 5) + rol(k[sum % 4], b >> 27)));
      sum += delta;
      c += (((d << 4) + rol(k[((sum >> 11) % 4) + 4], d)) ^
            (b + sum) ^ ((d >> 5) + rol(k[(sum >> 11) % 4], d >> 27)));
      t = a; a = b; b = c; c = d; d = t;
    }
    v[0] = a ^ k[4];
    v[1] = b ^ k[5];
    v[2] = c ^ k[6];
    v[3] = d ^ k[7];
  };

  void xtea3_decipher(unsigned int num_rounds, uint32_t *v, const uint32_t *k)
  {
    unsigned int i;
    uint32_t a, b, c, d, t, delta = 0x9E3779B9, sum = delta * num_rounds;
    d = v[3] ^ k[7];
    c = v[2] ^ k[6];
    b = v[1] ^ k[5];
    a = v[0] ^ k[4];
    for (i = 0; i < num_rounds; i++) {
      t = d; d = c; c = b; b = a; a = t;
      c -= (((d << 4) + rol(k[((sum >> 11) % 4) + 4], d)) ^
            (b + sum) ^ ((d >> 5) + rol(k[(sum >> 11) % 4], d >> 27)));
      sum -= delta;
      a -= (((b << 4) + rol(k[(sum % 4) + 4], b)) ^
            (d + sum) ^ ((b >> 5) + rol(k[sum % 4], b >> 27)));
    }
    v[3] = d - k[3];
    v[2] = c - k[2];
    v[1] = b - k[1];
    v[0] = a - k[0];
  };

  void xtea3_data_crypt(uint8_t *inout, uint32_t len, bool encrypt, const uint32_t *key)
  {
    static unsigned char dataArray[BLOCK_SIZE];
    for (int i = 0; i < len / BLOCK_SIZE; i++)
    {
      memcpy(dataArray, inout, BLOCK_SIZE);
      if (encrypt)
        xtea3_encipher(48, (uint32_t *)dataArray, key);
      else
        xtea3_decipher(48, (uint32_t *)dataArray, key);
      memcpy(inout, dataArray, BLOCK_SIZE);
      inout = inout + BLOCK_SIZE;
    }
    if (len % BLOCK_SIZE != 0)
    {
      int mod = len % BLOCK_SIZE;
      int offset = (len / BLOCK_SIZE) * BLOCK_SIZE;
      uint32_t data[BLOCK_SIZE];
      memcpy(data, inout + offset, mod);
      if (encrypt)
        xtea3_encipher(32, (uint32_t *)data, key);
      else
        xtea3_decipher(32, (uint32_t *)data, key);
      memcpy(inout + offset, data, mod);
    }
  }

 public:
  XTEA3()
  {
  }

  ~XTEA3()
  {
  }

  uint8_t *data_crypt(const uint8_t *data, const uint32_t key[8], uint32_t size)
  {
    uint32_t size_crypt_tmp = size;
    DEBUG_PRINT("CRYPT: \n");
    DEBUG_PRINT("SIZE = %d \n", size);
    // align to 16
    while ((size_crypt_tmp % 16) != 0)
    {
      size_crypt_tmp++;
    }
    // Allocate memory for aligned buffer
    // Plus eight bytes, so that there is the size of the encrypted data and the size of the original data, all this will be stored in the encrypted data
    data_ptr = NULL;
    data_ptr = (uint8_t *)malloc(size_crypt_tmp + 8);
    if (data_ptr == NULL)
    {
      DEBUG_PRINT("NO FREE MEM \n");
      return NULL;
    }
    // Put the size of the crypted data and the size of the original in the resulting buffer
    size_crypt = size_crypt_tmp + 8;
    size_decrypt_data = size;
    memcpy(data_ptr, (char *)&size_crypt, 4);
    memcpy(data_ptr + 4, (char *)&size_decrypt_data, 4);
    memcpy(data_ptr + 8, data, size);
    // Encrypt data
    xtea3_data_crypt(data_ptr + 8, size_crypt - 8, true, key);
    return data_ptr;
  }

  uint8_t *data_decrypt(const uint8_t *data, const uint32_t key[8], uint32_t size)
  {
    // Get the size of the crypted data and the size of the original
    memcpy((char *)&size_crypt, data, 4);
    memcpy((char *)&size_decrypt_data, data + 4, 4);
    DEBUG_PRINT("DECRYPT: \n");
    DEBUG_PRINT("SIZE = %d \n", size);
    DEBUG_PRINT("size_crypt = %d \n", size_crypt);
    DEBUG_PRINT("size_decrypt_data = %d \n", size_decrypt_data);
    if (size_crypt <= size)
    {
      // Allocate memory for decrypted data
      data_ptr = NULL;
      data_ptr = (uint8_t *)malloc(size_crypt);
      if (data_ptr == NULL)
      {
        DEBUG_PRINT("NO FREE MEM \n");
        return NULL;
      }
      memcpy(data_ptr, data + 8, size_crypt - 8);
      // Decrypt data
      xtea3_data_crypt(data_ptr, size_crypt - 8, false, key);
    }
    else
    {
      DEBUG_PRINT("size_crypt > size \n");
      return NULL;
    }
    return data_ptr;
  }

  uint32_t get_decrypt_size(void)
  {
    return size_decrypt_data;
  }

  uint32_t get_crypt_size(void)
  {
    return size_crypt;
  }

  void free_ptr(uint8_t *ptr)
  {
    free(ptr);
  }
};

template <size_t N, int K>
class HideString : protected XTEA3
{
 private:
  const char _key;
  uint32_t key_for_xtea3[8];
  uint8_t *crypted_str;
  std::array < char, N + 1 > _encrypted;

  constexpr char enc(char c) const
  {
    return c ^ _key;
  }

  char dec(char c) const
  {
    return c ^ _key;
  }

 public:
  // Constructor
  template < size_t... Is >
  constexpr __forceinline HideString(const char *str, std::index_sequence< Is... >)
    : _key(RandomChar< K >::value), _encrypted
  {
    enc(str[Is])...

  }
  {
    // key for xtea3
    uint32_t value_for_gen_key = seed;
    // gen pass for XTEA3
    for (int i = 0; i < 8; i++)
    {
      key_for_xtea3[i] = Murmur3(&value_for_gen_key, sizeof(value_for_gen_key), i);
    }
    // crypt
    crypted_str = data_crypt((const uint8_t *)_encrypted.data(), key_for_xtea3, N);
  }

  __forceinline uint8_t *decrypt(void)
  {
    // key for xtea3
    uint32_t value_for_gen_key = seed;
    // gen pass for XTEA3
    for (int i = 0; i < 8; i++)
    {
      key_for_xtea3[i] = Murmur3(&value_for_gen_key, sizeof(value_for_gen_key), i);
    }
    // decrypt
    uint8_t *decrypted_str = data_decrypt(crypted_str, key_for_xtea3, this->get_crypt_size());
    if (decrypted_str == NULL) return NULL;
    for (size_t i = 0; i < N; ++i)
    {
      decrypted_str[i] = dec(decrypted_str[i]);
    }
    decrypted_str[N] = '\0';
    return decrypted_str; // pointer for decrypted string
  }

  __forceinline uint8_t *crypt(void)
  {
    return crypted_str; // pointer for encrypted string
  }

  __forceinline void str_free(uint8_t *ptr)
  {
    free(ptr); // free memory
  }
};
