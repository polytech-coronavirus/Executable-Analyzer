#pragma once
#include "ExeParser.hpp"
#include <string>
#include <cstdint>

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_FOX_SECTION_HEADER
{
  unsigned char    Name[IMAGE_SIZEOF_SHORT_NAME];
  union
  {
    uint32_t   PhysicalAddress;
    uint32_t   VirtualSize;
  } Misc;
  
  uint32_t   VirtualAddress;
  uint32_t   SizeOfRawData;
  uint32_t   PointerToRawData;
  uint32_t   PointerToRelocations;
  uint32_t   PointerToLinenumbers;
  
  uint16_t    NumberOfRelocations;
  uint16_t    NumberOfLinenumbers;
  uint32_t   Characteristics;
} IMAGE_FOX_SECTION_HEADER, *PIMAGE_FOX_SECTION_HEADER;

typedef struct _IMAGE_FOX_FILE_HEADER
{
  uint16_t    Machine;
  uint16_t    NumberOfSections;
  uint32_t   TimeDateStamp;
  uint32_t   PointerToSymbolTable;
  uint32_t   NumberOfSymbols;
  uint16_t    SizeOfOptionalHeader;
  uint16_t    Characteristics;
} IMAGE_FOX_FILE_HEADER, *PIMAGE_FOX_FILE_HEADER;

typedef struct _IMAGE_FOX_DATA_DIRECTORY
{
  uint32_t   VirtualAddress;
  uint32_t   Size;
} IMAGE_FOX_DATA_DIRECTORY, *PIMAGE_FOX_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
typedef struct _IMAGE_FOX_OPTIONAL_HEADER64
{
  uint16_t        Magic;
  
  unsigned char        MajorLinkerVersion;
  unsigned char        MinorLinkerVersion;
  uint32_t       SizeOfCode;
  uint32_t       SizeOfInitializedData;
  uint32_t       SizeOfUninitializedData;
  uint32_t       AddressOfEntryPoint;
  uint32_t       BaseOfCode;
  uint64_t ImageBase;
  uint32_t       SectionAlignment;
  uint32_t       FileAlignment;
  uint16_t        MajorOperatingSystemVersion;
  uint16_t        MinorOperatingSystemVersion;
  uint16_t        MajorImageVersion;
  uint16_t        MinorImageVersion;
  uint16_t        MajorSubsystemVersion;
  uint16_t        MinorSubsystemVersion;
  uint32_t       Win32VersionValue;
  uint32_t       SizeOfImage;
  uint32_t       SizeOfHeaders;
  uint32_t       CheckSum;
  uint16_t        Subsystem;
  uint16_t        DllCharacteristics;
  uint64_t   SizeOfStackReserve;
  uint64_t   SizeOfStackCommit;
  uint64_t   SizeOfHeapReserve;
  uint64_t   SizeOfHeapCommit;

  uint32_t       LoaderFlags;
  uint32_t       NumberOfRvaAndSizes;
  IMAGE_FOX_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_FOX_OPTIONAL_HEADER64, *PIMAGE_FOX_OPTIONAL_HEADER64;

typedef struct _IMAGE_FOX_OPTIONAL_HEADER32
{
  uint16_t                 Magic;
  unsigned char                 MajorLinkerVersion;
  unsigned char                 MinorLinkerVersion;
  uint32_t                SizeOfCode;
  uint32_t                SizeOfInitializedData;
  uint32_t                SizeOfUninitializedData;
  uint32_t                AddressOfEntryPoint;
  uint32_t                BaseOfCode;
  uint32_t                BaseOfData;
  uint32_t                ImageBase;
  uint32_t                SectionAlignment;
  uint32_t                FileAlignment;
  uint16_t                 MajorOperatingSystemVersion;
  uint16_t                 MinorOperatingSystemVersion;
  uint16_t                 MajorImageVersion;
  uint16_t                 MinorImageVersion;
  uint16_t                 MajorSubsystemVersion;
  uint16_t                 MinorSubsystemVersion;
  uint32_t                Win32VersionValue;
  uint32_t                SizeOfImage;
  uint32_t                SizeOfHeaders;
  uint32_t                CheckSum;
  uint16_t                 Subsystem;
  uint16_t                 DllCharacteristics;
  uint32_t                SizeOfStackReserve;
  uint32_t                SizeOfStackCommit;
  uint32_t                SizeOfHeapReserve;
  uint32_t                SizeOfHeapCommit;
  uint32_t                LoaderFlags;
  uint32_t                NumberOfRvaAndSizes;
  IMAGE_FOX_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_FOX_OPTIONAL_HEADER32, *PIMAGE_FOX_OPTIONAL_HEADER32;

typedef struct _IMAGE_FOX_NT_HEADERS64
{
  uint32_t Signature;
  IMAGE_FOX_FILE_HEADER FileHeader;
  IMAGE_FOX_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_FOX_NT_HEADERS64, *PIMAGE_FOX_NT_HEADERS64;

typedef struct _IMAGE_FOX_NT_HEADERS32
{
  uint32_t Signature;
  IMAGE_FOX_FILE_HEADER FileHeader;
  IMAGE_FOX_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_FOX_NT_HEADERS32, *PIMAGE_FOX_NT_HEADERS32;

typedef struct _IMAGE_FOX_DOS_HEADER
{      // DOS .EXE header
  uint16_t   e_magic;                     // Magic number
  uint16_t   e_cblp;                      // Bytes on last page of file
  uint16_t   e_cp;                        // Pages in file
  uint16_t   e_crlc;                      // Relocations
  uint16_t   e_cparhdr;                   // Size of header in paragraphs
  uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
  uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
  uint16_t   e_ss;                        // Initial (relative) SS value
  uint16_t   e_sp;                        // Initial SP value
  uint16_t   e_csum;                      // Checksum
  uint16_t   e_ip;                        // Initial IP value
  uint16_t   e_cs;                        // Initial (relative) CS value
  uint16_t   e_lfarlc;                    // File address of relocation table
  uint16_t   e_ovno;                      // Overlay number
  uint16_t   e_res[4];                    // Reserved words
  uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
  uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
  uint16_t   e_res2[10];                  // Reserved words
  int32_t   e_lfanew;                    // File address of new exe header
} IMAGE_FOX_DOS_HEADER, *PIMAGE_FOX_DOS_HEADER;

typedef struct _IMAGE_FOX_IMPORT_DESCRIPTOR
{
  union
  {
    uint32_t   Characteristics;            // 0 for terminating null import descriptor
    uint32_t   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
  } DUMMYUNIONNAME;
  uint32_t   TimeDateStamp;                  // 0 if not bound,
                                          // -1 if bound, and real date\time stamp
                                          //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                          // O.W. date/time stamp of DLL bound to (Old BIND)

  uint32_t   ForwarderChain;                 // -1 if no forwarders
  uint32_t   Name;
  uint32_t   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_FOX_IMPORT_DESCRIPTOR, *PIMAGE_FOX_IMPORT_DESCRIPTOR;


#define FIELD_FOX_OFFSET(type, field)    ((long)(uint64_t*)&(((type *)0)->field))
#define IMAGE_FOX_FIRST_SECTION_32( ntheader ) ((PIMAGE_FOX_SECTION_HEADER)        \
    ((uint64_t)(ntheader) +                                            \
     FIELD_FOX_OFFSET( _IMAGE_FOX_NT_HEADERS32, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define IMAGE_FOX_FIRST_SECTION_64( ntheader ) ((PIMAGE_FOX_SECTION_HEADER)        \
    ((uint64_t)(ntheader) +                                            \
     FIELD_FOX_OFFSET( _IMAGE_FOX_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

class PE32 : public ExeParser
{
public:
  PE32(std::string inputFile);
  std::string getCompilationTime();
  std::string getDigitalSignature();
  std::string getBitness();
  std::string getFileType();
  std::string isUsingGPU();
  std::string getCompiler();
protected:
  std::vector<std::string> importDlls;

  bool hasImportTable;
  unsigned char bitness; //
  uint32_t compileTime; //timeDataStamp

  std::string compilerName;
};
