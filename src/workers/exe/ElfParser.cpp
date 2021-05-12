#include "ElfParser.hpp"

#include <stdexcept>
#include <fstream>
#include <regex>
#include <algorithm>
#include <cstring>

template <typename T>
T swap_endian(T u)
{
    union
    {
        T u;
        unsigned char u8[sizeof(T)];
    } source, dest;

    source.u = u;

    for (size_t k = 0; k < sizeof(T); k++)
        dest.u8[k] = source.u8[sizeof(T) - k - 1];

    return dest.u;
}

ElfParser::ElfParser(std::string inputFile):
  ExeParser(inputFile)
{
  
  std::ifstream file(inputFile, std::ios::in | std::ios::binary);
  if (!file.is_open())
  {
    throw std::runtime_error("ELF_PARSER_ERROR: couldn't open file." + inputFile);
  }
  if (!file.read((char*)&elf_header, sizeof(elf_header)))
  {
    throw std::runtime_error("ELF_PARSER_ERROR: error during file reading");
  }
  if (elf_header.elf32.e_ident[0] != 0x7F
      || elf_header.elf32.e_ident[1] != 'E'
      || elf_header.elf32.e_ident[2] != 'L'
      || elf_header.elf32.e_ident[3] != 'F'
      || elf_header.elf32.e_ident[6] != 0x01)//always 1
  {
    throw std::runtime_error("ELF_PARSER_ERROR: file isn't ELF executable");
  }
  
  if (elf_header.elf32.e_ident[4] == 0x01)
  {
    elf_bitness = ELF32;
  }
  else if (elf_header.elf32.e_ident[4] == 0x02)
  {
    elf_bitness = ELF64;
  }
  else
  {
    std::runtime_error("ELF_PARSER_ERROR: incorrect bitness. e_ident[4] must be 0x01 (32bit) or 0x02 (64bit).");
  }
  
  if (elf_header.elf32.e_ident[5] == 0x01)
  {
    elf_endian = LITTLE;
  }
  else if (elf_header.elf32.e_ident[5] == 0x02)
  {
    elf_endian = BIG;
  }
  else
  {
    std::runtime_error("ELF_PARSER_ERROR: incorrect endian. e_ident[4] must be 0x01 (little) or 0x02 (big).");
  }
  if (elf_bitness == ELF32)
  {
    if (elf_endian == BIG)
    {
      swap_endian(elf_header.elf32.e_type);
      swap_endian(elf_header.elf32.e_machine);
      swap_endian(elf_header.elf32.e_version);
      swap_endian(elf_header.elf32.e_entry);
      swap_endian(elf_header.elf32.e_phoff);
      swap_endian(elf_header.elf32.e_shoff);
      swap_endian(elf_header.elf32.e_flags);
      swap_endian(elf_header.elf32.e_ehsize);
      swap_endian(elf_header.elf32.e_phentsize);
      swap_endian(elf_header.elf32.e_phnum);
      swap_endian(elf_header.elf32.e_shentsize);
      swap_endian(elf_header.elf32.e_shnum);
      swap_endian(elf_header.elf32.e_shstrndx);
    }
    if (elf_header.elf32.e_type != 2 //executable
        || elf_header.elf32.e_version != 1) //always 1
    {
      throw std::runtime_error("ELF_PARSER_ERROR: file isn't ELF executable");
    }
    elf_phdr.elf32.resize(elf_header.elf32.e_phnum);
    file.seekg(elf_header.elf32.e_phoff);
    if (!file.read((char*)elf_phdr.elf32.data(), sizeof(Elf32_Phdr) * elf_header.elf32.e_phnum))
    {
      throw std::runtime_error("ELF_PARSER_ERROR: error during file reading");
    }
    if (elf_endian == BIG)
    {
      for (Elf32_Phdr phdr : elf_phdr.elf32)
      {
        swap_endian(phdr.p_type);
        swap_endian(phdr.p_offset);
        swap_endian(phdr.p_vaddr);
        swap_endian(phdr.p_paddr);
        swap_endian(phdr.p_filesz);
        swap_endian(phdr.p_memsz);
        swap_endian(phdr.p_flags);
        swap_endian(phdr.p_align);
      }
    }
    elf_shdr.elf32.resize(elf_header.elf32.e_shnum);
    file.seekg(elf_header.elf32.e_shoff);
    if (!file.read((char*)elf_shdr.elf32.data(), sizeof(Elf32_Shdr) * elf_header.elf32.e_shnum))
    {
      throw std::runtime_error("ELF_PARSER_ERROR: error during file reading");
    }
    if (elf_endian == BIG)
    {
      for (Elf32_Shdr shdr : elf_shdr.elf32)
      {
        swap_endian(shdr.sh_name);
        swap_endian(shdr.sh_type);
        swap_endian(shdr.sh_flags);
        swap_endian(shdr.sh_addr);
        swap_endian(shdr.sh_offset);
        swap_endian(shdr.sh_size);
        swap_endian(shdr.sh_link);
        swap_endian(shdr.sh_info);
        swap_endian(shdr.sh_addralign);
        swap_endian(shdr.sh_entsize);
      }
    }
  }
  else
  {
    if (elf_endian == BIG)
    {
      swap_endian(elf_header.elf64.e_type);
      swap_endian(elf_header.elf64.e_machine);
      swap_endian(elf_header.elf64.e_version);
      swap_endian(elf_header.elf64.e_entry);
      swap_endian(elf_header.elf64.e_phoff);
      swap_endian(elf_header.elf64.e_shoff);
      swap_endian(elf_header.elf64.e_flags);
      swap_endian(elf_header.elf64.e_ehsize);
      swap_endian(elf_header.elf64.e_phentsize);
      swap_endian(elf_header.elf64.e_phnum);
      swap_endian(elf_header.elf64.e_shentsize);
      swap_endian(elf_header.elf64.e_shnum);
      swap_endian(elf_header.elf64.e_shstrndx);
    }
    if (elf_header.elf64.e_type != 2 //executable
        || elf_header.elf64.e_version != 1) //always 1
    {
      throw std::runtime_error("ELF_PARSER_ERROR: file isn't ELF executable");
    }
    elf_phdr.elf64.resize(elf_header.elf64.e_phnum);
    file.seekg(elf_header.elf64.e_phoff);
    if (!file.read((char*)elf_phdr.elf64.data(), sizeof(Elf64_Phdr) * elf_header.elf64.e_phnum))
    {
      throw std::runtime_error("ELF_PARSER_ERROR: error during file reading");
    }
    if (elf_endian == BIG)
    {
      for (Elf64_Phdr phdr : elf_phdr.elf64)
      {
        swap_endian(phdr.p_type);
        swap_endian(phdr.p_flags);
        swap_endian(phdr.p_offset);
        swap_endian(phdr.p_vaddr);
        swap_endian(phdr.p_paddr);
        swap_endian(phdr.p_filesz);
        swap_endian(phdr.p_memsz);
        swap_endian(phdr.p_align);
      }
    }
    elf_shdr.elf64.resize(elf_header.elf64.e_shnum);
    file.seekg(elf_header.elf64.e_shoff);
    if (!file.read((char*)elf_shdr.elf64.data(), sizeof(Elf64_Shdr) * elf_header.elf64.e_shnum))
    {
      throw std::runtime_error("ELF_PARSER_ERROR: error during file reading");
    }
    if (elf_endian == BIG)
    {
      for (Elf64_Shdr shdr : elf_shdr.elf64)
      {
        swap_endian(shdr.sh_name);
        swap_endian(shdr.sh_type);
        swap_endian(shdr.sh_flags);
        swap_endian(shdr.sh_addr);
        swap_endian(shdr.sh_offset);
        swap_endian(shdr.sh_size);
        swap_endian(shdr.sh_link);
        swap_endian(shdr.sh_info);
        swap_endian(shdr.sh_addralign);
        swap_endian(shdr.sh_entsize);
      }
    }
  }
  file.close();
}

std::string ElfParser::getCompilationTime()
{
  return "";
}

std::string ElfParser::getDigitalSignature()
{
  return "";
}

std::string ElfParser::getBitness()
{
  return std::to_string(elf_bitness) + "bit";
}

std::string ElfParser::getFileType()
{
  return std::string("ELF") + std::to_string(elf_bitness);
}

std::string ElfParser::isUsingGPU()
{
  return "TODO";
}

std::string ElfParser::getCompiler()
{
  std::string compiler;
  if ((compiler = getFromComment()).length() == 0)
  {}
  return compiler;
}

std::string ElfParser::getFromComment()
{
  std::string version;
  if (elf_bitness == ELF32)
  {
    std::ifstream file(inputFile, std::ios::in | std::ios::binary);
    if (!file.is_open())
    {
      throw std::invalid_argument("ELF_PARSER_ERROR: couldn't open file." + inputFile);
    }
    Elf32_Shdr sh_strtab = elf_shdr.elf32[elf_header.elf32.e_shstrndx];
    auto commentSection = std::find_if(elf_shdr.elf32.begin(), elf_shdr.elf32.end(), [&](Elf32_Shdr& shdr)
    {
      char comment[8];
      file.seekg(sh_strtab.sh_offset + shdr.sh_name);
      file.read(comment, 8);
      return strncmp(comment, ".comment", 8)==0;
    });
    if (commentSection != elf_shdr.elf32.end())
    {
      version.resize(commentSection->sh_size);
      file.seekg(commentSection->sh_offset);
      file.read(&version.front(), commentSection->sh_size);
    }
  }
  else
  {
    std::ifstream file(inputFile, std::ios::in | std::ios::binary);
    if (!file.is_open())
    {
      throw std::invalid_argument("ELF_PARSER_ERROR: couldn't open file." + inputFile);
    }
    Elf64_Shdr sh_strtab = elf_shdr.elf64[elf_header.elf64.e_shstrndx];
    auto commentSection = std::find_if(elf_shdr.elf64.begin(), elf_shdr.elf64.end(), [&](Elf64_Shdr& shdr)
    {
      char comment[8];
      file.seekg(sh_strtab.sh_offset + shdr.sh_name);
      file.read(comment, 8);
      return strncmp(comment, ".comment", 8)==0;
    });
    if (commentSection != elf_shdr.elf64.end())
    {
      version.resize(commentSection->sh_size);
      file.seekg(commentSection->sh_offset);
      file.read(&version.front(), commentSection->sh_size);
    }
  }
  return version;
}
