#pragma once

#include <string>
#include <fstream>
#include <vector>

class ExeParser
{
public:
  ExeParser(std::vector<unsigned char>& inputFile);
  ExeParser() = delete;

  std::string GetSHA256();
  std::string GetSHA512();
  std::string GetMD5();
private:
  std::vector<unsigned char>& binaryData;
};