#pragma once

#include <string>
#include <fstream>

class ExeParser
{
public:
  ExeParser(std::ifstream& stream);
  ExeParser() = delete;

  std::string GetSHA256();
  std::string GetSHA512();
  std::string GetMD5();
private:
  std::ifstream& file;
};