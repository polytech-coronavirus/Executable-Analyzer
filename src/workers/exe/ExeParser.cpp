#include "ExeParser.hpp"

#include <stdexcept>
#include "digestpp.hpp"

ExeParser::ExeParser(std::ifstream& stream) :
  file(stream)
{
  if (!file.is_open())
  {
    std::runtime_error("[ExeParser()] File is not opened");
  }
}

std::string ExeParser::GetSHA256()
{
  this->file.seekg(0, std::ios::beg);
  return "0x" + digestpp::sha256().absorb(this->file).hexdigest();
}

std::string ExeParser::GetSHA512()
{
  this->file.seekg(0, std::ios::beg);
  return "0x" + digestpp::sha512().absorb(this->file).hexdigest();
}

std::string ExeParser::GetMD5()
{
  this->file.seekg(0, std::ios::beg);
  return "0x" + digestpp::md5().absorb(this->file).hexdigest();
}
