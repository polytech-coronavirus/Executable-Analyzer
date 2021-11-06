#pragma once
#include <string>
#include <vector>
#include <fstream>

class FoxHistoryManager
{
public:
  FoxHistoryManager();
  ~FoxHistoryManager();

  const std::vector<std::string> getHistory();
  void pushHistoryString(std::string pathToSave);
  void clearHistory();
  const unsigned int getHistorySize();
  const std::string getHistoryPath();
private:
  const std::string historyPath = "analyzeHistory.txt";
  std::fstream historyFile;
  std::vector<std::string> cachedHistory;
};
