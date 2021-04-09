#include "foxui.h"
#include "workers/exe/ExeParser.hpp"

#include <fstream>
#include <iostream>
#include <thread>
#include <utility>

void foxWorker(FoxUI* &interf)
{
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

      return;
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
  }

}

//TODO add terminal mode (argv parsing)
int main(int, char**)
{
  //glfw in FoxUI attaches to calling thread, so using pointers
  FoxUI* interf = new FoxUI(800, 600);
  std::thread uiThread(foxWorker, std::ref(interf));
  uiThread.detach();

  while (interf->isAlive())
  {
    interf->runUI();
  }
 
  return 0;
}
