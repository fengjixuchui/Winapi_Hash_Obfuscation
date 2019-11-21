#include <windows.h>
#include <iostream>

#include "api_obf/api_obfuscation.hpp"

int main()
{
  // example
  FILETIME fileTime;
  hash_GetSystemTimeAsFileTime(&fileTime);
  // ------------------------------------
  std::cout << "Check code!\r\n";
}
