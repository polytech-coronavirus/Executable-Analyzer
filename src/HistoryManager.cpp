#include "HistoryManager.h"
#include <fstream>
#include <stdexcept>
#include <algorithm>

FoxHistoryManager::FoxHistoryManager()
{
  std::string tempLine;
  historyFile.open(historyPath, std::ios_base::out | std::ios_base::in | std::ios_base::app);

  if (!historyFile.is_open())
  {
    throw std::runtime_error("Could not create or open history file");
  }
  

  while (std::getline(historyFile, tempLine))
  {
    cachedHistory.push_back(tempLine);
  }

  historyFile.clear();
  historyFile.seekp(0, std::ios::end);
}

FoxHistoryManager::~FoxHistoryManager()
{
  //clear history file on disk to rewrite
  if (historyFile.is_open())
  {
    std::experimental::filesystem::resize_file(historyPath, 0);
    historyFile.seekp(0);
  }
  else
  {
    throw std::runtime_error("History file not opened");
  }

  for (auto tempHistoryEntry : cachedHistory)
  {
    historyFile << tempHistoryEntry << std::endl;
  }
}

std::vector<std::string> FoxHistoryManager::getHistory()
{
  return cachedHistory;
}

void FoxHistoryManager::pushHistoryString(std::string pathToSave)
{
  cachedHistory.push_back(pathToSave);
  std::rotate(cachedHistory.rbegin(), cachedHistory.rbegin() + 1, cachedHistory.rend());
}

void FoxHistoryManager::clearHistory()
{
  cachedHistory.clear();
}

unsigned int FoxHistoryManager::getHistorySize()
{
  return cachedHistory.size();
}
