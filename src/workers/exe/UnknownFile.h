#ifndef UNKNOWNFILE_H
#define UNKNOWNFILE_H

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
  std::string isUsingGPU();
  std::string getCompiler();

};
#endif
