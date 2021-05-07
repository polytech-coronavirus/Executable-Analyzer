#include "ExeParser.hpp"
#include "ElfParser.hpp"
#include "PEParser.h"
#include "UnknownFile.h"

#include <stdexcept>
#include <iostream>
#include <string>
#include <sstream>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <time.h>
#include <stdio.h>
#include "digestpp.hpp"

#ifndef WIN32
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef WIN32
#define stat _stat
#endif

ExeParser* getParser(const std::string& filename)
{
  std::ifstream file(filename, std::ios::binary);

  if (file.is_open())
  {
    file.seekg(0, file.end);
    int length = file.tellg();
    file.seekg(0, file.beg);
    
    if (length < 6)
    {
      return new UnknownFile(filename);
    }

    char arr[20] = { 0 };

    file.read(arr, 5);

    if (arr[0] == 'M' && arr[1] == 'Z')
    {
      return new PE32(filename);
    }
    else if (arr[0] == 0x7F && arr[1] == 'E' && arr[2] == 'L' && arr[3] == 'F')
    {
      return new Elf32Parser(filename);
    }
    else
    {
      return new UnknownFile(filename);
    }
  }
}

ExeParser::ExeParser(std::string inputFile):
  inputFile(inputFile)
{}

std::string ExeParser::GetADS()
{
	std::string toReturn;

#ifdef _WIN32
	std::wstring filename(inputFile.begin(), inputFile.end());
	WIN32_FIND_STREAM_DATA fileData, streamData;
	constexpr DWORD reserved = 0;
	int couner = 0;

	HANDLE file = FindFirstStreamW(filename.c_str(), FindStreamInfoStandard, &fileData, reserved);
	if (file == INVALID_HANDLE_VALUE)
		return;

	while (FindNextStreamW(file, &streamData)) 
	{
		toReturn += "In file: " + inputFile + '\n';
		std::wstring name(streamData.cStreamName);
		std::wstring size(std::to_wstring(streamData.StreamSize.QuadPart));

		std::string streamName(name.begin(), name.end());
		std::string streamSize(size.begin(), size.end());

		toReturn += "Stream name: " + streamName + '\t' + "Stream size: " + streamSize + '\n';
	}
#else
	toReturn += "There are no alternate data stream on this OS\n";

#endif

	toReturn += '\n';
	return toReturn;
}

std::string ExeParser::getCreationTime()
{
  struct stat t_stat;
  stat(inputFile.c_str(), &t_stat);
  struct tm* timeinfo = localtime(&t_stat.st_ctime);

  std::stringstream ss;
  ss << std::put_time(timeinfo, "%c");
  return ss.str();
}

std::string ExeParser::getLastChangeTime()
{
  struct stat result;

  if (stat(inputFile.c_str(), &result) == 0)
  {
    time_t mod_time = result.st_mtime;
    std::tm tm = *std::localtime(&mod_time);
    std::stringstream ss;
    ss << std::put_time(&tm, "%c");
    return ss.str();
  }
}

std::string ExeParser::getFileSize()
{
  std::ifstream is(inputFile, std::ifstream::binary);
  if (is.is_open())
  {
    is.seekg(0, is.end);
    int length = is.tellg();
    is.seekg(0, is.beg);

    if ((length / 1024) >= 1024)
    {
      return std::to_string(length / 1024 / 1024) + " MB";
    }
    else if (length >= 1024)
    {
      return std::to_string(length / 1024) + " KB";
    }
    else if (length < 1024)
    {
      return std::to_string(length) + " B";
    }
  }

  return "Couldn't get file size";
}

std::string ExeParser::GetSHA256()
{
  return "";
  //return "0x" + digestpp::sha256().absorb(binaryData.begin(), binaryData.end()).hexdigest();
}

std::string ExeParser::GetSHA512()
{
  return "";
  //return "0x" + digestpp::sha512().absorb(binaryData.begin(), binaryData.end()).hexdigest();
}

std::string ExeParser::GetMD5()
{
  return "";
  //return "0x" + digestpp::md5().absorb(binaryData.begin(), binaryData.end()).hexdigest();
}
