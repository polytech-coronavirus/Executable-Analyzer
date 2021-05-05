#pragma once
#include "ExeParser.hpp"

class UnknownFile : public ExeParser
{
public:
  UnknownFile(std::string inputFile) : ExeParser(inputFile) {};

  std::string getCompilationTime();
  std::string getDigitalSignature();
  std::string getAlternateData();
  std::string getBitness();
  std::string getFileType();

};
