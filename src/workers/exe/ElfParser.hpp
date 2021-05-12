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
  uint32_t      e_entry;
  uint32_t      e_phoff;
  uint32_t      e_shoff;
  uint32_t      e_flags;
  uint16_t      e_ehsize;
  uint16_t      e_phentsize;
  uint16_t      e_phnum;
  uint16_t      e_shentsize;
  uint16_t      e_shnum;
  uint16_t      e_shstrndx;
};

struct Elf64_Ehdr
{
  unsigned char e_ident[16];
  uint16_t      e_type;
  uint16_t      e_machine;
  uint32_t      e_version;
  uint64_t      e_entry;
  uint64_t      e_phoff;
  uint64_t      e_shoff;
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
  uint32_t   p_type;
  uint32_t   p_offset;
  uint32_t   p_vaddr;
  uint32_t   p_paddr;
  uint32_t   p_filesz;
  uint32_t   p_memsz;
  uint32_t   p_flags;
  uint32_t   p_align;
};

struct Elf64_Phdr
{
  uint32_t   p_type;
  uint32_t   p_flags;
  uint64_t   p_offset;
  uint64_t   p_vaddr;
  uint64_t   p_paddr;
  uint64_t   p_filesz;
  uint64_t   p_memsz;
  uint64_t   p_align;
};

struct Elf32_Shdr
{
  uint32_t   sh_name;
  uint32_t   sh_type;
  uint32_t   sh_flags;
  uint32_t   sh_addr;
  uint32_t   sh_offset;
  uint32_t   sh_size;
  uint32_t   sh_link;
  uint32_t   sh_info;
  uint32_t   sh_addralign;
  uint32_t   sh_entsize;
};

struct Elf64_Shdr
{
  uint32_t   sh_name;
  uint32_t   sh_type;
  uint64_t   sh_flags;
  uint64_t   sh_addr;
  uint64_t   sh_offset;
  uint64_t   sh_size;
  uint32_t   sh_link;
  uint32_t   sh_info;
  uint64_t   sh_addralign;
  uint64_t   sh_entsize;
};

class ElfParser: public ExeParser
{
public:
  
  ElfParser(std::string inputFile);
  std::string getCompilationTime();
  std::string getDigitalSignature();
  std::string getBitness();
  std::string getFileType();
  std::string isUsingGPU();
  
  std::string getCompiler();
private:
  union
  {
    Elf32_Ehdr elf32;
    Elf64_Ehdr elf64;
  }
  elf_header;
  
  enum
  {
    ELF32 = 32,
    ELF64 = 64
  }
  elf_bitness;
  
  enum
  {
    LITTLE,
    BIG
  }
  elf_endian;
  
  struct
  {
    std::vector<Elf32_Phdr> elf32;
    std::vector<Elf64_Phdr> elf64;
  }
  elf_phdr;
  
  struct
  {
    std::vector<Elf32_Shdr> elf32;
    std::vector<Elf64_Shdr> elf64;
  }
  elf_shdr;
  
  std::string getFromComment();
};
