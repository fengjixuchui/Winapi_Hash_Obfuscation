#include <iostream>

#include "t1ha/t1ha.h"
#include <windows.h>
#include <sysinfoapi.h>
#include "api_obf/hash_work.hpp"

int main()
{
  FILETIME fileTime;
  hash_GetSystemTimeAsFileTime(&fileTime);
  std::cout << "Hello World!\n";
}
