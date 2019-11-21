#include <windows.h>
#include <iostream>

#include "t1ha/t1ha.h"
#include "api_obf/api_obfuscation.hpp"

int main()
{
  // example
  FILETIME fileTime;
  hash_GetSystemTimeAsFileTime(&fileTime);
  // ------------------------------------
  std::cout << "Check code!\r\n";
}
