#include "foxui.h"
#include "workers/exe/ElfParser.hpp"

#include <fstream>
#include <iostream>
#include <thread>
#include <utility>
#include <iterator>
#include <vector>
#include <iomanip>

#include "digestpp.hpp"

void foxWorker(FoxUI* &interf)
{
  std::string filePath = interf->getFilePath();

  try
  {
    //create parser object
    //TODO create abstract parser class (to set specific parser)

    //executable analyzation here
    //TODO separate to threads
    Elf32Parser parser(filePath);


    interf->pushField("MD5", parser.GetMD5());
    interf->pushField("SHA256", parser.GetSHA256());
    interf->pushField("SHA512", parser.GetSHA512());

    interf->setState(FoxUI::States::DONE);
  }
  catch (std::exception& error)
  {
    interf->pushError(error.what());
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
