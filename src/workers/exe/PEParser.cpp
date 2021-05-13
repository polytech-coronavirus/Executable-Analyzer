#include "PEParser.h"
#include <fstream>
#include <algorithm>
#include <regex>
#include <stdexcept>
#include <time.h>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <tchar.h>
#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#pragma comment (lib, "wintrust")
#endif

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

std::uint8_t* PatternScan(void* module, const char* signature, uint32_t size)
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

 
  auto patternBytes = pattern_to_byte(signature);
  auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

  auto s = patternBytes.size();
  auto d = patternBytes.data();

  for (auto i = 0ul; i < size - s; ++i) {
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


std::uint8_t* PatternScan(void* module, const char* signature, uint32_t start, uint32_t end)
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

  auto patternBytes = pattern_to_byte(signature);
  auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

  auto s = patternBytes.size();
  auto d = patternBytes.data();

  for (auto i = start; i < end - s; ++i)
  {
    bool found = true;
    for (auto j = 0ul; j < s; ++j) {
      if (scanBytes[i + j] != d[j] && d[j] != -1)
      {
        found = false;
        break;
      }
    }
    if (found)
    {
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

    for (unsigned int i = 0; i < ntheaders32->FileHeader.NumberOfSections - 1; i++)
    {
      PIMAGE_FOX_SECTION_HEADER pSech32 = (PIMAGE_FOX_SECTION_HEADER)((uint8_t*)ntheaders32 + sizeof(_IMAGE_FOX_NT_HEADERS32) + i * sizeof(IMAGE_FOX_SECTION_HEADER));
      sections.push_back(pSech32);
      std::cout << pSech32->Name << "\n";
    }
    
  }
  else
  {
    passImportTable64(virtualpointer, this->importDlls);
    this->compileTime = ntheaders64->FileHeader.TimeDateStamp;

    for (unsigned int i = 0; i < ntheaders64->FileHeader.NumberOfSections - 1; i++)
    {
      PIMAGE_FOX_SECTION_HEADER pSech64 = (PIMAGE_FOX_SECTION_HEADER)((uint8_t*)ntheaders64 + sizeof(_IMAGE_FOX_NT_HEADERS64) + i * sizeof(IMAGE_FOX_SECTION_HEADER));
      sections.push_back(pSech64);
      std::cout << pSech64->Name << "\n";
    }
    
  }

  this->compilerName = parseCompiler(virtualpointer, length);
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
    std::string to_return;

#ifdef _WIN32
    LONG lStatus;
    DWORD dwLastError;
    std::wstring filename(inputFile.begin(), inputFile.end());
    

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = filename.c_str();
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = 0;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
      
        to_return += "The file is signed and the signature was verified\n";
        break;

    case TRUST_E_NOSIGNATURE:

        dwLastError = GetLastError();
        if (TRUST_E_NOSIGNATURE == dwLastError ||
            TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
            TRUST_E_PROVIDER_UNKNOWN == dwLastError)
        {
            to_return += "The file is not signed.\n";
        }
        else
        {
            to_return += "An unknown error occurred trying to verify the signature of the file.\n";
        }

        break;

    case TRUST_E_EXPLICIT_DISTRUST:

        to_return += "The signature is present, but specifically disallowed.\n";

        break;

    case TRUST_E_SUBJECT_NOT_TRUSTED:

        to_return += "The signature is present, but not trusted.\n";

        break;

    case CRYPT_E_SECURITY_SETTINGS:
   
        to_return += R"(CRYPT_E_SECURITY_SETTINGS - The hash\n 
            representing the subject or the publisher wasn't\n
            explicitly trusted by the admin and admin policy\n
            has disabled user trust. No signature, publisher\n
            or timestamp errors.\n)";

        break;

    default:
        to_return += "Unexpexted error is: 0x%x.\n";
        break;
    }
#endif
  return to_return;
}

std::string PE32::getBitness()
{
  if (bitness == 32)
  {
    return "32";
  }
  else if (bitness == 64)
  {
    return "64";
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
    "glu(32|64)\\.dll",
    "dxgi\\.dll",
    "unityplayer\\.dll",
    "opencl\\.dll",
    "gdiplus\\.dll",
    "gdi32\\.dll"
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
  return compilerName;
}

std::string getVSVersionFromLinker(unsigned char linkerMinorVer, unsigned char linkerMajorVer)
{
  switch (linkerMajorVer)
  {
  case 3:  return "MS C++ " + std::to_string(linkerMinorVer) + "." + std::to_string(linkerMajorVer);   break; // MS C++
  case 4:  return "Visual studio 4.0";  break;
  case 5:  return  "Visual studio 5.0";  break;
  case 6:  return  "Visual studio 6.0";  break;
  case 7:
    if (linkerMinorVer < 10)
    {
      return "Visual studio 2002";
    }
    else
    {
      return "Visual studio 2003";
    }
    break;
  case 8:  return "Visual studio 2005"; break;
  case 9:  return "Visual studio 2008"; break;
  case 10: return "Visual studio 2010"; break;
  case 11: return "Visual studio 2012"; break;
  case 12: return "Visual studio 2013"; break;
  case 14:
    switch (linkerMinorVer)
    {
    case 0:  return "Visual studio 2015 v.14.0"; break;
    case 10: return "Visual studio 2017 v.15.0"; break;
    case 11: return "Visual studio 2017 v.15.3"; break;
    case 12: return "Visual studio 2017 v.15.5"; break;
    case 13: return "Visual studio 2017 v.15.6"; break;
    case 14: return "Visual studio 2017 v.15.7"; break;
    case 15: return "Visual studio 2017 v.15.8"; break;
    case 16: return "Visual studio 2017 v.15.9"; break;
    case 20: return "Visual studio 2019 v.16.0"; break;
    case 27: return "Visual studio 2019 v.16.7"; break;
    }
  }
  return "Visual Studio";
}

std::string PE32::parseCompiler(void* image, unsigned int image_size)
{
  std::string compiler;
  unsigned char linkerMajorVer;
  unsigned char linkerMinorVer;

  PIMAGE_FOX_NT_HEADERS32 ntheaders32 = (PIMAGE_FOX_NT_HEADERS32)((unsigned char*)(image)+PIMAGE_FOX_DOS_HEADER(image)->e_lfanew);
  PIMAGE_FOX_NT_HEADERS64 ntheaders64 = (PIMAGE_FOX_NT_HEADERS64)((unsigned char*)(image)+PIMAGE_FOX_DOS_HEADER(image)->e_lfanew);

  if (this->bitness == 32)
  {
    linkerMajorVer = ntheaders32->OptionalHeader.MajorLinkerVersion;
    linkerMinorVer = ntheaders32->OptionalHeader.MinorLinkerVersion;
  }
  else
  {
    linkerMajorVer = ntheaders64->OptionalHeader.MajorLinkerVersion;
    linkerMinorVer = ntheaders64->OptionalHeader.MinorLinkerVersion;
  }

  //FASM
  if (PatternScan(image, "4D 5A 80 00 01 00 00 00 04 00 10 00 FF FF 00 00 40 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21", image_size))
  {
    return ("FASM" + std::string(" [") + std::to_string(linkerMajorVer) + "." + std::to_string(linkerMinorVer) + "]");
  }

  bool wasFoundVS = false;
  std::string vsTempVersion;

  uint8_t* text_addr;
  auto section_fox = getSection(".text");
  uint32_t section_size = image_size;

  if (section_fox != nullptr)
  {
    section_size = section_fox->SizeOfRawData;
  }
  else
  {
    text_addr = (uint8_t*)image;
  }

  if (bitness == 32)
  {
    if (section_fox != nullptr)
    {
      text_addr = (uint8_t*)(Rva2Offset_32(section_fox->VirtualAddress, section_fox, ntheaders32) + (uint8_t*)image);
    }
    
  }
  else
  {
    if (section_fox != nullptr)
    {
      text_addr = (uint8_t*)(Rva2Offset_64(section_fox->VirtualAddress, section_fox, ntheaders64) + (uint8_t*)image);
    }
  }

  if (text_addr == 0)
  {
    text_addr = (uint8_t*)image;
  }

  if (PatternScan(text_addr, "55 8B EC 51 C7 45 FC 01 00 00 00 83 7D 0C 00 75 10 83 3D", section_size))
  {
    vsTempVersion = "6.0";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "E8 ?? ?? ?? 00 E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? E8", section_size))
  {
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 75 09 83 3D", section_size))
  {
    vsTempVersion = "6.0";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83", section_size))
  {
    vsTempVersion = "5.0-2003";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 8B 75 0C 33 FF 3B F7 75 0C 39 3D", section_size))
  {
    vsTempVersion = "2003";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 81 3D", section_size))
  {
    vsTempVersion = "2003";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 94 00 00 00 8B C7 E8", section_size))
  {
    vsTempVersion = "2003";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "8B FF 55 8B EC 83 7D 0C 01 75 05 E8", section_size))
  {
    vsTempVersion = "2008-2010";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "8B FF 55 8B EC E8 ?? ?? ?? 00 E8 ?? ?? ?? 00 5D C3", section_size))
  {
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "64 A1 00 00 00 00 55 8B EC 6A FF 68", section_size))
  {
    
    wasFoundVS = true;

  }
  else if (PatternScan(text_addr, "64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57", section_size))
  {
    vsTempVersion = "5.0";
    wasFoundVS = true;

  }
  else if (PatternScan(text_addr, "53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75", section_size))
  {
    vsTempVersion = "2.0";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "56 E8 ?? ?? ?? ?? 8B F0 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? 56 E8", section_size))
  {
    vsTempVersion = "2.0";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "53 B8 ?? ?? ?? ?? 8B ?? ?? ?? 56 57 85 DB 55 75", section_size))
  {
    vsTempVersion = "4.2";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15", section_size))
  {
    vsTempVersion = "6.0";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A 06 3C 22", section_size))
  {
    vsTempVersion = "6.0";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84", section_size))
  {
    vsTempVersion = "6.0";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10", section_size))
  {
    vsTempVersion = "2002";
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "55 8B EC 83 EC 24 53 56 57 89 65 F8", section_size))
  {
    wasFoundVS = true;
  }
  else if (PatternScan(text_addr, "55 8B EC 83 EC 24 53 56 57 89 65 F8", section_size))
  {
    wasFoundVS = true;
  }

  if (wasFoundVS)
  {
    if (vsTempVersion.empty())
    {
      return getVSVersionFromLinker(linkerMinorVer, linkerMajorVer);
    }
    else
    {
      return "Visual Studio " + vsTempVersion;
    }
  }

  for (auto dll : this->importDlls)
  {
    std::regex msvcpRegex("msvcp[a-z0-9]*\\.dll");
    if (std::regex_match(dll, msvcpRegex))
    {
      std::string vers = getVSVersionFromLinker(linkerMinorVer, linkerMajorVer);
      if (vers.length() > 14)
      {
        return vers;
      }
      
      if (std::regex_match(dll, std::regex("msvcp100[a-z]?\\.dll")))
      {
        return "Microsoft Visual Studio 2010";
      }
      else if (std::regex_match(dll, std::regex("msvcp110[a-z]?\\.dll")))
      {
        return "Microsoft Visual Studio 2012";
      }
      else if (std::regex_match(dll, std::regex("msvcp120[a-z]?\\.dll")))
      {
        return "Microsoft Visual Studio 2013";
      }
      else if (std::regex_match(dll, std::regex("msvcp140[a-z]?\\.dll")))
      {
        return "Microsoft Visual Studio 2015-2019";
      }

    }

  }

  //MINGW
  if (linkerMajorVer == 2)
  {
    bool wasFound = false;
    //90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21
    if (PatternScan(image, "90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21", image_size))
    {
      if (!hasSection(".rsrc"))
      {
        compiler += "MinGW";
        wasFound = true;
      }
      else
      {
        PIMAGE_FOX_SECTION_HEADER sectionHeader = getSection(".rsrc");

        if (sectionHeader->SizeOfRawData > 512)
        {
          if (bitness == 32)
          {
            if (!PatternScan((void*)(Rva2Offset_32(sectionHeader->VirtualAddress, sectionHeader, ntheaders32) + (uint8_t*)image + sectionHeader->SizeOfRawData - 512) , "4D 69 63 72 6F 73 6F 66 74 20 43 6F 72 70 2E", 512))
            {
              compiler += "MinGW";
              wasFound = true;
            }
          }
          else
          {
            if (!PatternScan((void*)(Rva2Offset_64(sectionHeader->VirtualAddress, sectionHeader, ntheaders64) + (uint8_t*)image + sectionHeader->SizeOfRawData - 512), "4D 69 63 72 6F 73 6F 66 74 20 43 6F 72 70 2E", 512))
            {
              compiler += "MinGW";
              wasFound = true;
            }
          }
        }

      }
    }
    
    if (wasFound)
    {
      auto sec = getSection(".rdata");
      if (sec != nullptr)
      {
        uint8_t* foxversOffset;
        if (bitness == 32)
        {
          foxversOffset = PatternScan((void*)(Rva2Offset_32(sec->VirtualAddress, sec, ntheaders32) + (uint8_t*)image), "47 43 43 3A 20", sec->SizeOfRawData);
        }
        else
        {
          foxversOffset = PatternScan((void*)(Rva2Offset_64(sec->VirtualAddress, sec, ntheaders64) + (uint8_t*)image), "47 43 43 3A 20", sec->SizeOfRawData);
        }

        if (foxversOffset != nullptr)
        {
          char version_temp[256];
          strcpy(version_temp, (const char*)(foxversOffset));

          compiler += " [";
          compiler += version_temp;
          compiler += "]";
        }

      }
    }
  }

  if (PatternScan(image, "55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? 55", image_size))
  {
    return "MinGW GCC 3.x";
  }
  else if (PatternScan(image, "55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9", image_size))
  {
    return "MinGW GCC 2.x";
  }
  else if (PatternScan(image, "55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45", image_size))
  {
    return "MinGW GCC 2.x";
  }
  //A1........C1E002A3
  //
  if (image_size > 310)
  {
    if (PatternScan(image, "4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 BA 10 00 0E 1F B4 09 CD 21 B8 01 4C CD 21 90 90 54 68 69 73 20 70 72 6F 67 72 61 6D 20 6D 75 73 74 20 62 65 20 72 75 6E 20 75 6E 64 65 72 20 57 69 6E 33 32 0D 0A 24 37 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 50 45 00 00", image_size))
    {
      return "Borland C/C++";
    }
  }
  if (PatternScan(image, "A1 ?? ?? ?? ?? C1 E0 02 A3", image_size))
  {
    return "Borland C/C++";
  }

  if (PatternScan(image, "E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29", image_size))
  {
    return "Free Pascal 0.99.10";
  }
  else if (PatternScan(image, "C6 05 ?? ?? ?? ?? 01 E8 ?? ?? 00 00 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? ?? 55", image_size))
  {
    return "Free Pascal 1.0.10 [win console]";
  }
  else if (PatternScan(image, "C6 05 ?? ?? ?? ?? 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? ?? 55 89 E5", image_size))
  {
    return "Free Pascal 1.0.10 [win GUI]";
  }
  else if (PatternScan(image, "55 89 E5 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 55 31 ED 89 E0 A3 ?? ?? ?? ?? 66 8C D5 89 2D", image_size))
  {
    return "Free Pascal 1.0.4";
  }
  else if (PatternScan(image, "55 89 E5 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 6A 00 64 FF 35 00 00 00 00 89 E0 A3", image_size))
  {
    return "Free Pascal 2.0.0";
  }
  else if (PatternScan(image, "55 89 E5 C6 05 ?? ?? ?? ?? 01 68 ?? ?? ?? ?? 6A F6 E8 ?? ?? ?? ?? 50 E8", image_size))
  {
    return "Free Pascal 2.6.0";
  }
  else if (PatternScan(image, "C6 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 89 E5 C6 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 55 31 ED 89 e0 A3 ?? ?? ?? ?? 66 8C D5 89 2D ?? ?? ?? ?? DB E3 D9", image_size))
  {
    return "Free Pascal 1.0.2";
  }

  return compiler;
}

bool PE32::hasSection(std::string str)
{
  return (std::find_if(this->sections.begin(), this->sections.end(), [&](PIMAGE_FOX_SECTION_HEADER& sec)
    {
      return str.compare((char*)sec->Name) == 0;
    }) != this->sections.end());
}

PIMAGE_FOX_SECTION_HEADER PE32::getSection(std::string str)
{
  auto it = (std::find_if(this->sections.begin(), this->sections.end(), [&](PIMAGE_FOX_SECTION_HEADER& sec)
    {
      return str.compare((char*)sec->Name) == 0;
    }));

  if (it == this->sections.end())
  {
    return nullptr;
  }
  return *it;
}

uint32_t* PE32::getSectionAddress(PIMAGE_FOX_SECTION_HEADER sec)
{

  return 0;
}
