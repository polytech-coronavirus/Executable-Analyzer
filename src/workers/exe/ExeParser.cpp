#include "ExeParser.hpp"

#include <stdexcept>
#include "digestpp.hpp"

ExeParser::ExeParser(std::vector<unsigned char>& inputFile):
  binaryData(inputFile)
{
  
}

std::string ExeParser::GetSHA256()
{
  return "0x" + digestpp::sha256().absorb(binaryData.begin(), binaryData.end()).hexdigest();
}

std::string ExeParser::GetSHA512()
{
  return "0x" + digestpp::sha512().absorb(binaryData.begin(), binaryData.end()).hexdigest();
}

std::string ExeParser::GetMD5()
{
  return "0x" + digestpp::md5().absorb(binaryData.begin(), binaryData.end()).hexdigest();
}
