#pragma once
#include <string>
#include <vector>
#include <fstream>
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#include <experimental/filesystem>

class FoxHistoryManager
{
public:
  FoxHistoryManager();
  ~FoxHistoryManager();

  std::vector<std::string> getHistory();
  void pushHistoryString(std::string pathToSave);
  void clearHistory();
  unsigned int getHistorySize();
private:
  std::experimental::filesystem::path historyPath = "analyzeHistory.txt";
  std::fstream historyFile;
  std::vector<std::string> cachedHistory;
};
