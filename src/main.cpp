#include "foxui.h"
#include "workers/exe/ExeParser.hpp"

#include <fstream>
#include <iostream>
#include <thread>
#include <utility>

std::mutex interfInit_lock;
bool interfInit = false;

void uiThreadRunner(FoxUI* &interf, unsigned short width, unsigned short height)
{
  try
  {
    interf = new FoxUI(width, height);

    interfInit_lock.lock();
    interfInit = true;
    interfInit_lock.unlock();

    while (interf->isAlive())
    {
      interf->runUI();
    }
  }
  catch (std::runtime_error& error)
  {
    std::cerr << "[thread] " << error.what() << "\n";
    return;
  }
}

//TODO add terminal mode (argv parsing)
int main(int, char**)
{
  //glfw in FoxUI attaches to calling thread, so using pointers
  FoxUI* interf = nullptr;
  std::thread uiThread(uiThreadRunner, std::ref(interf), 800, 600);

  while (true)
  {
    interfInit_lock.lock();
    if (interf != nullptr)
    {
      interfInit_lock.unlock();
      break;
    }
    interfInit_lock.unlock();

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }

  //will be blocked until user select path
  std::string filePath = interf->getFilePath();
  std::ifstream file(filePath, std::ios::in | std::ios::binary);

  try
  {
    //create parser object
    //TODO create abstract parser class (to set specific parser)
    ExeParser parser(file);

    if (!file.is_open())
    {
      interf->pushError("Couldn't open file");
      interf->setState(FoxUI::States::ERROR);
      uiThread.join();

      return 2;
    }

    //executable analyzation here
    //TODO separate to threads
    interf->pushField("MD5", parser.GetMD5());
    interf->pushField("SHA256", parser.GetSHA256());
    interf->pushField("SHA512", parser.GetSHA512());

    interf->setState(FoxUI::States::DONE);
  }
  catch (std::runtime_error& error)
  {
    interf->pushError("Couldn't open file");
    interf->setState(FoxUI::States::ERROR);
    uiThread.join();
  }
  
  
  //wait for render (until user closes window)
  uiThread.join();

  return 0;
}
