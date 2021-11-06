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
    return;
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
    historyFile.close();
    historyFile.open(historyPath, std::ios::out | std::ios::trunc);
  }
  else
  {
    return;
  }
  if (!historyFile.is_open())
  {
    return;
  }
  for (auto tempHistoryEntry : cachedHistory)
  {
    historyFile << tempHistoryEntry << std::endl;
  }
}

const std::vector<std::string> FoxHistoryManager::getHistory()
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

const unsigned int FoxHistoryManager::getHistorySize()
{
  return cachedHistory.size();
}

const std::string FoxHistoryManager::getHistoryPath()
{
  return historyPath;
}
