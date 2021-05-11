#include "PEParser.h"
#include <fstream>
#include <algorithm>
#include <regex>
#include <stdexcept>
#include <time.h>
#include <sstream>
#include <iomanip>

//virtual address to file address
unsigned long Rva2Offset_32(unsigned long rva, PIMAGE_FOX_SECTION_HEADER psh, PIMAGE_FOX_NT_HEADERS32 pnt)
{
  size_t i = 0;
  PIMAGE_FOX_SECTION_HEADER pSeh;
  if (rva == 0)
  {
    return (rva);
  }
  pSeh = psh;
  for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
  {
    if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
      pSeh->Misc.VirtualSize)
    {
      break;
    }
    pSeh++;
  }
  return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

unsigned long Rva2Offset_64(unsigned long rva, PIMAGE_FOX_SECTION_HEADER psh, PIMAGE_FOX_NT_HEADERS64 pnt)
{
  size_t i = 0;
  PIMAGE_FOX_SECTION_HEADER pSeh;
  if (rva == 0)
  {
    return (rva);
  }
  pSeh = psh;
  for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
  {
    if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
      pSeh->Misc.VirtualSize)
    {
      break;
    }
    pSeh++;
  }
  return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

void passImportTable32(void* virtualpointer, std::vector<std::string>& importDlls)
{
  PIMAGE_FOX_NT_HEADERS32 ntheaders32 = (PIMAGE_FOX_NT_HEADERS32)((unsigned char*)(virtualpointer) + PIMAGE_FOX_DOS_HEADER(virtualpointer)->e_lfanew);
  PIMAGE_FOX_SECTION_HEADER pSech32 = IMAGE_FOX_FIRST_SECTION_32(ntheaders32);
  PIMAGE_FOX_IMPORT_DESCRIPTOR pImportDescriptor;
  if (ntheaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
  {
    pImportDescriptor = (PIMAGE_FOX_IMPORT_DESCRIPTOR)((uint64_t)virtualpointer + \
      Rva2Offset_32(ntheaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSech32, ntheaders32));

    char* libname[256];
    size_t i = 0;

    // Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
    while (pImportDescriptor->Name != NULL)
    {
      //Get the name of each DLL
      libname[i] = (char*)((uint64_t)virtualpointer + Rva2Offset_32(pImportDescriptor->Name, pSech32, ntheaders32));

      std::string libCompare(libname[i]);
      std::transform(libCompare.begin(), libCompare.end(), libCompare.begin(),
        [](unsigned char c) { return std::tolower(c); });

      importDlls.push_back(libCompare);

      pImportDescriptor++; //advance to next IMAGE_IMPORT_DESCRIPTOR
      i++;
    }
  }
}

void passImportTable64(void* virtualpointer, std::vector<std::string>& importDlls)
{
  PIMAGE_FOX_NT_HEADERS64 ntheaders64 = (PIMAGE_FOX_NT_HEADERS64)((unsigned char*)(virtualpointer) + PIMAGE_FOX_DOS_HEADER(virtualpointer)->e_lfanew);
  PIMAGE_FOX_SECTION_HEADER pSech64 = IMAGE_FOX_FIRST_SECTION_64(ntheaders64);
  PIMAGE_FOX_IMPORT_DESCRIPTOR pImportDescriptor;

  if (ntheaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
  {
    pImportDescriptor = (PIMAGE_FOX_IMPORT_DESCRIPTOR)((uint64_t)virtualpointer + \
      Rva2Offset_64(ntheaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSech64, ntheaders64));

    char* libname[256];
    size_t i = 0;
    // Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
    while (pImportDescriptor->Name != NULL)
    {
      //Get the name of each DLL
      libname[i] = (char*)((uint64_t)virtualpointer + Rva2Offset_64(pImportDescriptor->Name, pSech64, ntheaders64));

      std::string libCompare(libname[i]);
      std::transform(libCompare.begin(), libCompare.end(), libCompare.begin(),
        [](unsigned char c) { return std::tolower(c); });

      importDlls.push_back(libCompare);

      pImportDescriptor++; //advance to next IMAGE_IMPORT_DESCRIPTOR
      i++;
    }
  }
}

std::uint8_t* PatternScan(void* module, const char* signature)
{
  static auto pattern_to_byte = [](const char* pattern) { //was static
    auto bytes = std::vector<int>{};
    auto start = const_cast<char*>(pattern);
    auto end = const_cast<char*>(pattern) + strlen(pattern);

    for (auto current = start; current < end; ++current) {
      if (*current == '?') {
        ++current;
        if (*current == '?')
          ++current;
        bytes.push_back(-1);
      }
      else {
        bytes.push_back(strtoul(current, &current, 16));
      }
    }
    return bytes;
  };

  auto dosHeader = (PIMAGE_FOX_DOS_HEADER)module;
  auto ntHeaders = (PIMAGE_FOX_NT_HEADERS64)((std::uint8_t*)module + dosHeader->e_lfanew);

  auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
  auto patternBytes = pattern_to_byte(signature);
  auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

  auto s = patternBytes.size();
  auto d = patternBytes.data();

  for (auto i = 0ul; i < sizeOfImage - s; ++i) {
    bool found = true;
    for (auto j = 0ul; j < s; ++j) {
      if (scanBytes[i + j] != d[j] && d[j] != -1) {
        found = false;
        break;
      }
    }
    if (found) {
      return &scanBytes[i];
    }
  }
  return nullptr;
}


PE32::PE32(std::string inputFile) : ExeParser(inputFile), bitness(0), compileTime(0), hasImportTable(0)
{
  std::ifstream file(inputFile, std::ios::binary);

  file.seekg(0, file.end);
  int length = file.tellg();
  file.seekg(0, file.beg);

  void* virtualpointer = new unsigned char[length];
  file.read((char*)virtualpointer, length);

  auto bitraw = *(uint16_t*)((unsigned char*)virtualpointer + PIMAGE_FOX_DOS_HEADER(virtualpointer)->e_lfanew + sizeof(uint32_t) + sizeof(IMAGE_FOX_FILE_HEADER));
  if (bitraw == 0x10b)
  {
    //IMAGE_NT_OPTIONAL_HDR32_MAGIC
    this->bitness = 32;
  }
  else if (bitraw == 0x20b)
  {
    //IMAGE_NT_OPTIONAL_HDR64_MAGIC
    this->bitness = 64;
  }
  else
  {
    throw std::runtime_error("IMAGE_NT_OPTIONAL_ magic number is invalid");
  }

  PIMAGE_FOX_NT_HEADERS64 ntheaders64 = (PIMAGE_FOX_NT_HEADERS64)((unsigned char*)(virtualpointer) + PIMAGE_FOX_DOS_HEADER(virtualpointer)->e_lfanew);
  PIMAGE_FOX_NT_HEADERS32 ntheaders32 = (PIMAGE_FOX_NT_HEADERS32)((unsigned char*)(virtualpointer) + PIMAGE_FOX_DOS_HEADER(virtualpointer)->e_lfanew);

  if (this->bitness == 32)
  {
    passImportTable32(virtualpointer, this->importDlls);
    this->compileTime = ntheaders32->FileHeader.TimeDateStamp;

    /*for (unsigned int i = 0; i < ntheaders32->FileHeader.NumberOfSections - 1; i++)
    {
      PIMAGE_FOX_SECTION_HEADER pSech32 = (PIMAGE_FOX_SECTION_HEADER)((uint8_t*)ntheaders32 + sizeof(_IMAGE_FOX_NT_HEADERS32) + i * sizeof(IMAGE_FOX_SECTION_HEADER));
      std::cout << pSech32->Name << "\n";
    }*/

  }
  else
  {
    passImportTable64(virtualpointer, this->importDlls);
    this->compileTime = ntheaders64->FileHeader.TimeDateStamp;

    /*for (unsigned int i = 0; i < ntheaders64->FileHeader.NumberOfSections - 1; i++)
    {
      PIMAGE_FOX_SECTION_HEADER pSech64 = (PIMAGE_FOX_SECTION_HEADER)((uint8_t*)ntheaders64 + sizeof(_IMAGE_FOX_NT_HEADERS64) + i * sizeof(IMAGE_FOX_SECTION_HEADER));
      std::cout << pSech64->Name << "\n";
    }*/
  }

  if (!this->importDlls.empty())
  {
    this->hasImportTable = true;
  }
  
  delete[] virtualpointer;
}

std::string PE32::getCompilationTime()
{
  if (compileTime != 0)
  {
    time_t timet = (time_t)compileTime;
    tm* pGMT = gmtime(&timet);

    std::stringstream ss;
    ss << std::put_time(pGMT, "%c");
    return ss.str();
  }
  return "";
}

std::string PE32::getDigitalSignature()
{
  return "";
}

std::string PE32::getBitness()
{
  if (bitness == 32)
  {
    return "x86";
  }
  else if (bitness == 64)
  {
    return "x64";
  }
  else
  {
    return "Unknown";
  }
}

std::string PE32::getFileType()
{
  if (bitness == 32)
  {
    return "WinPE x86";
  }
  else if (bitness == 64)
  {
    return "WinPE x64";
  }
  else
  {
    return "WinPE unknown";
  }
}

std::string PE32::isUsingGPU()
{
  const std::vector <std::string>gpuLibs =
  {
    "opengl[a-z0-9]*\\.dll",
    "vulkan-[a-z0-9]*\\.dll",
    "d3d[a-z0-9]*\\.dll",
    "glu(32|64)\.dll",
    "dxgi.dll",
    "unityplayer.dll",
    "opencl.dll",
    "gdiplus.dll"
  };
  
  bool hasMatches = false;

  std::string out("Yes [");

  for (auto dll : importDlls)
  {
    for (auto importRegex : gpuLibs)
    {
      std::regex regexfox(importRegex);
      if (std::regex_match(dll, regexfox))
      {
        hasMatches = true;
        out += dll;
        out += ',';
        
        break;
      }
    }
  }
  if (out.back() == ',')
  {
    out.pop_back();
  }
  out += ']';

  if (hasMatches)
  {
    return out;
  }

  return "No";
   
}

std::string PE32::getCompiler()
{
  return "";
}
