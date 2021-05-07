#include "ExeParser.hpp"

#include <stdexcept>
#include "digestpp.hpp"

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
