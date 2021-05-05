#include "ElfParser.hpp"

#include <stdexcept>
#include <fstream>

Elf32Parser::Elf32Parser(std::string inputFile):
  ExeParser(inputFile)
{
  std::ifstream file(inputFile, std::ios::in | std::ios::binary);
  if (!file.is_open())
  {
    throw std::invalid_argument("ELF_PARSER_ERROR: couldn't open file." + inputFile);
  }
  uint32_t offset;
  if (!file.read((char*)&elf_header, sizeof(elf_header)))
  {
    throw std::runtime_error("ELF_PARSER_ERROR: error during file reading");
  }
  if (elf_header.e_ident[0] != 0x7F
      || elf_header.e_ident[1] != 'E'
      || elf_header.e_ident[2] != 'L'
      || elf_header.e_ident[3] != 'F'
      || elf_header.e_ident[4] != 0x01
      || elf_header.e_ident[5] != 0x01
      || elf_header.e_ident[6] != 0x01
      || elf_header.e_type != 2
      || elf_header.e_version != 1)
  {
    throw std::runtime_error("ELF_PARSER_ERROR: file isn't ELF32 executable");
  }
  
}

std::string Elf32Parser::getCreationTime()
{
  return "";
}

std::string Elf32Parser::getLastChangeTime()
{
  return "";
}

std::string Elf32Parser::getCompilationTime()
{
  return "";
}

std::string Elf32Parser::getFileSize()
{
  return "";
}

std::string Elf32Parser::getDigitalSignature()
{
  return "";
}

std::string Elf32Parser::getAlternateData()
{
  return "";
}

std::string Elf32Parser::getBitness()
{
  return "";
}

std::string Elf32Parser::getFileType()
{
  return "";
}
