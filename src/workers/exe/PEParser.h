#pragma once
#include "ExeParser.hpp"
#include <string>

class PE32 : public ExeParser
{
public:
  PE32(std::string inputFile) : ExeParser(inputFile) {};
  std::string getCompilationTime();
  std::string getDigitalSignature();
  std::string getAlternateData();
  std::string getBitness();
  std::string getFileType();

};
