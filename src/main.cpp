#include "foxui.h"
#include "workers/exe/ExeParser.hpp"

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
    //executable analyzation here
    //TODO separate to threads

    ExeParser* parser = getParser(filePath);

    interf->pushField("MD5", parser->GetMD5());
    interf->pushField("SHA256", parser->GetSHA256());
    interf->pushField("SHA512", parser->GetSHA512());
    interf->pushField("Creation Time", parser->getCreationTime());
    interf->pushField("Last Modification Time", parser->getLastChangeTime());
    interf->pushField("File Size", parser->getFileSize());
    interf->pushField("File Type", parser->getFileType());

    if (parser->getFileType() != "Unknown")
    {
      interf->pushField("Bitness", parser->getBitness());
      interf->pushField("Compiler", parser->getCompiler());
      interf->pushField("Compile time", parser->getCompilationTime());
      interf->pushField("Using GPU", parser->isUsingGPU());
      interf->pushField("Digital signature", parser->getDigitalSignature());
    }

    interf->pushStream(parser->GetADS());

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
  FoxUI* interf = new FoxUI(900, 500);
  std::thread uiThread(foxWorker, std::ref(interf));
  uiThread.detach();

  while (interf->isAlive())
  {
    interf->runUI();
  }
 
  return 0;
}
