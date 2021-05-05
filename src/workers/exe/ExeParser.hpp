#pragma once

#include <string>
#include <fstream>
#include <vector>

class ExeParser
{
public:
  
  ExeParser(std::string inputFile);
  ExeParser() = delete;
  virtual ~ExeParser() = default;
  
  virtual std::string getCreationTime() = 0;
  virtual std::string getLastChangeTime() = 0;
  virtual std::string getCompilationTime() = 0;
  virtual std::string getFileSize() = 0;
  virtual std::string getDigitalSignature() = 0;
  virtual std::string getAlternateData() = 0;
  virtual std::string getBitness() = 0;
  virtual std::string getFileType() = 0;
  
  std::string GetSHA256();
  std::string GetSHA512();
  std::string GetMD5();
  
private:
  std::string inputFile;
};
