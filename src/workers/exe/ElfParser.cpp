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
    int index = getSectionIndex(".dynamic", file);
    if (index >= 0)
    {
      Elf32_Shdr& dynamicSection = elf_shdr.elf32[index];
      file.seekg(dynamicSection.sh_offset);
      
      Elf32_Dyn dyn;
      do
      {
        file.read((char*)(&dyn), sizeof(Elf32_Dyn));
        elf_dyn.elf32.push_back(dyn);
      }
      while (dyn.d_tag != 0);
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
    int index = getSectionIndex(".dynamic", file);
    if (index >= 0)
    {
      Elf64_Shdr& dynamicSection = elf_shdr.elf64[index];
      file.seekg(dynamicSection.sh_offset);
      
      Elf64_Dyn dyn;
      do
      {
        file.read((char*)(&dyn), sizeof(Elf64_Dyn));
        elf_dyn.elf64.push_back(dyn);
      }
      while (dyn.d_tag != 0);
    }
  }
  file.close();
}

std::string ElfParser::getCompilationTime()
{
  return "---";
}

std::string ElfParser::getDigitalSignature()
{
  return "---";
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
  const std::vector <std::string>gpuLibs =
  {
    "opengl[a-z0-9]*\\.so\\.[a-z0-9]*",
    "vulkan-[a-z0-9]*\\.so\\.[a-z0-9]*",
    "d3d[a-z0-9]*\\.so\\.[a-z0-9]*",
    "glu(32|64)\\.so\\.[a-z0-9]*",
    "dxgi\\.so\\.[a-z0-9]*",
    "unityplayer\\.so\\.[a-z0-9]*",
    "opencl\\.so\\.[a-z0-9]*",
    "gdiplus\\.so\\.[a-z0-9]*",
    "gdi32\\.so\\.[a-z0-9]*"
  };
  std::string gpuDLLs = "YES [";
  std::ifstream file(inputFile, std::ios::in | std::ios::binary);
  if (!file.is_open())
  {
    throw std::runtime_error("ELF_PARSER_ERROR: couldn't open file." + inputFile);
  }
  int64_t index = getSectionIndex(".dynstr", file);
  if (index < 0)
  {
    return "NO";
  }
  if (elf_bitness == ELF32)
  {
    Elf32_Shdr& dynstr = elf_shdr.elf32[index];
    std::string currentDLL;
    for (Elf32_Dyn& dyn: elf_dyn.elf32)
    {
      if (dyn.d_tag == 1)
      {
        file.seekg(dynstr.sh_offset + dyn.d_un.d_val);
        getline(file, currentDLL, '\0');
        std::transform(currentDLL.begin(), currentDLL.end(), currentDLL.begin(),
          [](unsigned char c) { return std::tolower(c); });
        for (auto importRegex : gpuLibs)
        {
          std::regex regex(importRegex);
          if (std::regex_match(currentDLL, regex))
          {
            gpuDLLs += currentDLL + ", ";
            break;
          }
        }
      }
    }
  }
  else
  {
    Elf64_Shdr& dynstr = elf_shdr.elf64[index];
    std::string currentDLL;
    for (Elf64_Dyn& dyn: elf_dyn.elf64)
    {
      if (dyn.d_tag == 1)
      {
        file.seekg(dynstr.sh_offset + dyn.d_un.d_val);
        getline(file, currentDLL, '\0');
        std::transform(currentDLL.begin(), currentDLL.end(), currentDLL.begin(),
          [](unsigned char c) { return std::tolower(c); });
        for (auto importRegex : gpuLibs)
        {
          std::regex regex(importRegex);
          if (std::regex_match(currentDLL, regex))
          {
            gpuDLLs += currentDLL + ", ";
            break;
          }
        }
      }
    }
  }
  if (gpuDLLs.size() == 5)
  {
    return "NO";
  }
  gpuDLLs.pop_back();
  gpuDLLs.back() = ']';
  return gpuDLLs;
}

std::string ElfParser::getCompiler()
{
  std::ifstream file(inputFile, std::ios::in | std::ios::binary);
  if (!file.is_open())
  {
    throw std::invalid_argument("ELF_PARSER_ERROR: couldn't open file." + inputFile);
  }
  std::string compiler;
  if ((compiler = getFromComment(file)).length() != 0)
  {}
  else if ((compiler = getFPC(file)).length() != 0)
  {}
  else if ((compiler = getDMD(file)).length() != 0)
  {}
  else if ((compiler = getTCC(file)).length() != 0)
  {}
  return compiler;
}

std::string ElfParser::getFromComment(std::ifstream& file)
{
  if (!file.is_open())
  {
    return "";
  }
  std::string version;
  int index = getSectionIndex(".comment", file);
  if (index < 0)
  {
    return "";
  }
  return readSection(index, file);
}

std::string ElfParser::getFPC(std::ifstream& file)
{
  if (!file.is_open())
  {
    return "";
  }
  int index = getSectionIndex(".data", file);
  if (index < 0)
  {
    return "";
  }
  std::string data = readSection(index, file);
  std::regex r(R"(FPC\ (\d+\.)?(\d+\.)?(\*|\d+))");
  std::smatch match;
  if (std::regex_search(data, match, r))
  {
    return match.str();
  }
  return "";
}

std::string ElfParser::getDMD(std::ifstream& file)
{
  if (!file.is_open())
  {
    return "";
  }
  int index = getSectionIndex(".dynstr", file);
  if (index < 0)
  {
    return "";
  }
  std::string dynstr = readSection(index, file);
    // Look for the DMD marker
  if (dynstr.find("__dmd_") != std::string::npos)
  {
    return "DMD";
  }
  return "";
}

std::string ElfParser::getTCC(std::ifstream& file)
{
  if (getSectionIndex(".note.ABI-tag", file) >= 0) {
    return "";
  }
  if (getSectionIndex(".rodata.cst4", file) < 0) {
    return "";
  }
  return "TCC";
}

int64_t ElfParser::getSectionIndex(std::string name, std::ifstream& file)
{
  if (!file.is_open())
  {
    return -2;
  }
  int64_t i = 0;
  std::string currentSection;
  int nameSize = name.size();
  currentSection.resize(nameSize);
  if (elf_bitness == ELF32)
  {
    Elf32_Shdr& sh_strtab = elf_shdr.elf32[elf_header.elf32.e_shstrndx];
    for (; i < elf_shdr.elf32.size(); ++i)
    {
      file.seekg(sh_strtab.sh_offset + elf_shdr.elf32[i].sh_name);
      file.read(&currentSection.front(), nameSize);
      if (!file.good())
      {
        return -3;
      }
      if (name == currentSection)
      {
        break;
      }
    }
    if (elf_shdr.elf32.size() == i)
    {
      return -1;
    }
  }
  else
  {
    Elf64_Shdr& sh_strtab = elf_shdr.elf64[elf_header.elf64.e_shstrndx];
    for (; i < elf_shdr.elf64.size(); ++i)
    {
      file.seekg(sh_strtab.sh_offset + elf_shdr.elf64[i].sh_name);
      file.read(&currentSection.front(), nameSize);
      if (!file.good())
      {
        return -3;
      }
      if (name == currentSection)
      {
        break;
      }
    }
    if (elf_shdr.elf64.size() == i)
    {
      return -1;
    }
  }
  return i;
}

std::string ElfParser::readSection(int index, std::ifstream& file)
{
  if (index < 0 || !file.is_open() || !file.good())
  {
    return "";
  }
  std::string data;
  if (elf_bitness == ELF32)
  {
    if (index >= elf_shdr.elf32.size())
    {
      return "";
    }
    Elf32_Shdr& section = elf_shdr.elf32[index];
    data.resize(section.sh_size);
    file.seekg(section.sh_offset);
    file.read(&data.front(), section.sh_size);
  }
  else
  {
    if (index >= elf_shdr.elf64.size())
    {
      return "";
    }
    Elf64_Shdr& section = elf_shdr.elf64[index];
    data.resize(section.sh_size);
    file.seekg(section.sh_offset);
    file.read(&data.front(), section.sh_size);
  }
  if (!file.good())
  {
    return "";
  }
  return data;
}
