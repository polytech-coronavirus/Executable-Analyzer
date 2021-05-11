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
    throw std::runtime_error("IMAGE_ROM_OPTIONAL_HDR_MAGIC is not supported");
  }

  PIMAGE_FOX_NT_HEADERS64 ntheaders64 = (PIMAGE_FOX_NT_HEADERS64)((unsigned char*)(virtualpointer) + PIMAGE_FOX_DOS_HEADER(virtualpointer)->e_lfanew);
  PIMAGE_FOX_NT_HEADERS32 ntheaders32 = (PIMAGE_FOX_NT_HEADERS32)((unsigned char*)(virtualpointer) + PIMAGE_FOX_DOS_HEADER(virtualpointer)->e_lfanew);

  if (this->bitness == 32)
  {
    passImportTable32(virtualpointer, this->importDlls);
    this->compileTime = ntheaders32->FileHeader.TimeDateStamp;
  }
  else
  {
    passImportTable64(virtualpointer, this->importDlls);
    this->compileTime = ntheaders64->FileHeader.TimeDateStamp;
  }

  if (!this->importDlls.empty())
  {
    this->hasImportTable = true;
  }

  delete[] virtualpointer;
}

std::string PE32::getCompilationTime()
{
  time_t TimeX = (time_t)compileTime;
  tm* pGMT = gmtime(&TimeX);

  std::stringstream ss;
  ss << std::put_time(pGMT, "%c");
  return ss.str();
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
