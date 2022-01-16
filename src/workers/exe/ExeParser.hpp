#ifndef EXEPARSER_H
#define EXEPARSER_H

#include <string>
#include <fstream>
#include <vector>
#include <iostream>
#include "../../foxui.h"

class ExeParser
{
public:
  
  ExeParser(std::string inputFile);
  ExeParser() = delete;
  virtual ~ExeParser() = default;
  
  std::string getCreationTime();
  std::string getLastChangeTime();
  virtual std::string getCompilationTime() = 0;
  virtual std::string getCompiler() = 0;
  std::string getFileSize();
  virtual std::string getDigitalSignature() = 0;
  virtual std::string getBitness() = 0;
  virtual std::string getFileType() = 0;
  virtual std::string isUsingGPU() = 0;

  std::vector<alternateDataStreams_t> GetADS();
  std::string GetSHA256();
  std::string GetSHA512();
  std::string GetMD5();
  
protected:
  std::string inputFile;
};

ExeParser* getParser(const std::string& filename);
#endif
