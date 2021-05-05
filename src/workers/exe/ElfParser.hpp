#pragma once

#include <string>
#include <fstream>
#include <vector>
#include <cstdint>

#include "ExeParser.hpp"

struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  uint16_t      e_type;
  uint16_t      e_machine;
  uint32_t      e_version;
  uint32_t    e_entry;
  uint32_t     e_phoff;
  uint32_t     e_shoff;
  unsigned char e_offset[4];
  uint32_t      e_flags;
  uint16_t      e_ehsize;
  uint16_t      e_phentsize;
  uint16_t      e_phnum;
  uint16_t      e_shentsize;
  uint16_t      e_shnum;
  uint16_t      e_shstrndx;
};

struct Elf32_Phdr
{
  
};

class Elf32Parser: public ExeParser
{
public:
  
  Elf32Parser(std::string inputFile);
  
  std::string getCreationTime();
  std::string getLastChangeTime();
  std::string getCompilationTime();
  std::string getFileSize();
  std::string getDigitalSignature();
  std::string getAlternateData();
  std::string getBitness();
  std::string getFileType();
  
private:
  Elf32_Ehdr elf_header;
  Elf32_Phdr elf_phdr;
};

class Elf64Parser : public ExeParser
{
public:

  Elf64Parser(std::string inputFile);

  std::string getCreationTime();
  std::string getLastChangeTime();
  std::string getCompilationTime();
  std::string getFileSize();
  std::string getDigitalSignature();
  std::string getAlternateData();
  std::string getBitness();
  std::string getFileType();

private:
  Elf32_Ehdr elf_header;
  Elf32_Phdr elf_phdr;
};

