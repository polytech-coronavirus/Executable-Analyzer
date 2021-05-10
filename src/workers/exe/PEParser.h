#pragma once
#include "ExeParser.hpp"
#include <string>

#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_FOX_SECTION_HEADER
{
  unsigned char    Name[IMAGE_SIZEOF_SHORT_NAME];
  union
  {
    unsigned long   PhysicalAddress;
    unsigned long   VirtualSize;
  } Misc;
  unsigned long   VirtualAddress;
  unsigned long   SizeOfRawData;
  unsigned long   PointerToRawData;
  unsigned long   PointerToRelocations;
  unsigned long   PointerToLinenumbers;
  unsigned short    NumberOfRelocations;
  unsigned short    NumberOfLinenumbers;
  unsigned long   Characteristics;
} IMAGE_FOX_SECTION_HEADER, *PIMAGE_FOX_SECTION_HEADER;

typedef struct _IMAGE_FOX_FILE_HEADER
{
  unsigned short    Machine;
  unsigned short    NumberOfSections;
  unsigned long   TimeDateStamp;
  unsigned long   PointerToSymbolTable;
  unsigned long   NumberOfSymbols;
  unsigned short    SizeOfOptionalHeader;
  unsigned short    Characteristics;
} IMAGE_FOX_FILE_HEADER, *PIMAGE_FOX_FILE_HEADER;

typedef struct _IMAGE_FOX_DATA_DIRECTORY
{
  unsigned long   VirtualAddress;
  unsigned long   Size;
} IMAGE_FOX_DATA_DIRECTORY, *PIMAGE_FOX_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
typedef struct _IMAGE_FOX_OPTIONAL_HEADER64
{
  unsigned short        Magic;
  unsigned char        MajorLinkerVersion;
  unsigned char        MinorLinkerVersion;
  unsigned long       SizeOfCode;
  unsigned long       SizeOfInitializedData;
  unsigned long       SizeOfUninitializedData;
  unsigned long       AddressOfEntryPoint;
  unsigned long       BaseOfCode;
  unsigned long long ImageBase;
  unsigned long       SectionAlignment;
  unsigned long       FileAlignment;
  unsigned short        MajorOperatingSystemVersion;
  unsigned short        MinorOperatingSystemVersion;
  unsigned short        MajorImageVersion;
  unsigned short        MinorImageVersion;
  unsigned short        MajorSubsystemVersion;
  unsigned short        MinorSubsystemVersion;
  unsigned long       Win32VersionValue;
  unsigned long       SizeOfImage;
  unsigned long       SizeOfHeaders;
  unsigned long       CheckSum;
  unsigned short        Subsystem;
  unsigned short        DllCharacteristics;
  unsigned long long   SizeOfStackReserve;
  unsigned long long   SizeOfStackCommit;
  unsigned long long   SizeOfHeapReserve;
  unsigned long long   SizeOfHeapCommit;

  unsigned long       LoaderFlags;
  unsigned long       NumberOfRvaAndSizes;
  IMAGE_FOX_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_FOX_OPTIONAL_HEADER64, *PIMAGE_FOX_OPTIONAL_HEADER64;

typedef struct _IMAGE_FOX_OPTIONAL_HEADER32
{
  unsigned short                 Magic;
  unsigned char                 MajorLinkerVersion;
  unsigned char                 MinorLinkerVersion;
  unsigned long                SizeOfCode;
  unsigned long                SizeOfInitializedData;
  unsigned long                SizeOfUninitializedData;
  unsigned long                AddressOfEntryPoint;
  unsigned long                BaseOfCode;
  unsigned long                BaseOfData;
  unsigned long                ImageBase;
  unsigned long                SectionAlignment;
  unsigned long                FileAlignment;
  unsigned short                 MajorOperatingSystemVersion;
  unsigned short                 MinorOperatingSystemVersion;
  unsigned short                 MajorImageVersion;
  unsigned short                 MinorImageVersion;
  unsigned short                 MajorSubsystemVersion;
  unsigned short                 MinorSubsystemVersion;
  unsigned long                Win32VersionValue;
  unsigned long                SizeOfImage;
  unsigned long                SizeOfHeaders;
  unsigned long                CheckSum;
  unsigned short                 Subsystem;
  unsigned short                 DllCharacteristics;
  unsigned long                SizeOfStackReserve;
  unsigned long                SizeOfStackCommit;
  unsigned long                SizeOfHeapReserve;
  unsigned long                SizeOfHeapCommit;
  unsigned long                LoaderFlags;
  unsigned long                NumberOfRvaAndSizes;
  IMAGE_FOX_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_FOX_OPTIONAL_HEADER32, * PIMAGE_FOX_OPTIONAL_HEADER32;

typedef struct _IMAGE_FOX_NT_HEADERS64
{
  unsigned long Signature;
  IMAGE_FOX_FILE_HEADER FileHeader;
  IMAGE_FOX_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_FOX_NT_HEADERS64, * PIMAGE_FOX_NT_HEADERS64;

typedef struct _IMAGE_FOX_NT_HEADERS32
{
  unsigned long Signature;
  IMAGE_FOX_FILE_HEADER FileHeader;
  IMAGE_FOX_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_FOX_NT_HEADERS32, * PIMAGE_FOX_NT_HEADERS32;

typedef struct _IMAGE_FOX_DOS_HEADER
{      // DOS .EXE header
  unsigned short   e_magic;                     // Magic number
  unsigned short   e_cblp;                      // Bytes on last page of file
  unsigned short   e_cp;                        // Pages in file
  unsigned short   e_crlc;                      // Relocations
  unsigned short   e_cparhdr;                   // Size of header in paragraphs
  unsigned short   e_minalloc;                  // Minimum extra paragraphs needed
  unsigned short   e_maxalloc;                  // Maximum extra paragraphs needed
  unsigned short   e_ss;                        // Initial (relative) SS value
  unsigned short   e_sp;                        // Initial SP value
  unsigned short   e_csum;                      // Checksum
  unsigned short   e_ip;                        // Initial IP value
  unsigned short   e_cs;                        // Initial (relative) CS value
  unsigned short   e_lfarlc;                    // File address of relocation table
  unsigned short   e_ovno;                      // Overlay number
  unsigned short   e_res[4];                    // Reserved words
  unsigned short   e_oemid;                     // OEM identifier (for e_oeminfo)
  unsigned short   e_oeminfo;                   // OEM information; e_oemid specific
  unsigned short   e_res2[10];                  // Reserved words
  long   e_lfanew;                    // File address of new exe header
} IMAGE_FOX_DOS_HEADER, * PIMAGE_FOX_DOS_HEADER;

typedef struct _IMAGE_FOX_IMPORT_DESCRIPTOR
{
  union
  {
    unsigned long   Characteristics;            // 0 for terminating null import descriptor
    unsigned long   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
  } DUMMYUNIONNAME;
  unsigned long   TimeDateStamp;                  // 0 if not bound,
                                          // -1 if bound, and real date\time stamp
                                          //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                          // O.W. date/time stamp of DLL bound to (Old BIND)

  unsigned long   ForwarderChain;                 // -1 if no forwarders
  unsigned long   Name;
  unsigned long   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_FOX_IMPORT_DESCRIPTOR;
typedef IMAGE_FOX_IMPORT_DESCRIPTOR __unaligned* PIMAGE_FOX_IMPORT_DESCRIPTOR;


#define FIELD_FOX_OFFSET(type, field)    ((long)(unsigned long long*)&(((type *)0)->field))
#define IMAGE_FOX_FIRST_SECTION_32( ntheader ) ((PIMAGE_FOX_SECTION_HEADER)        \
    ((unsigned unsigned long long)(ntheader) +                                            \
     FIELD_FOX_OFFSET( _IMAGE_FOX_NT_HEADERS32, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

#define IMAGE_FOX_FIRST_SECTION_64( ntheader ) ((PIMAGE_FOX_SECTION_HEADER)        \
    ((unsigned unsigned long long)(ntheader) +                                            \
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
  unsigned long compileTime; //timeDataStamp

  std::string compilerName;
};
