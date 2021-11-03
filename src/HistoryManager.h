#pragma once
#include <string>
#include <vector>
#include <fstream>

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
  std::string historyPath = "analyzeHistory.txt";
  std::fstream historyFile;
  std::vector<std::string> cachedHistory;
};
