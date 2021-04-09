#pragma once

#include <string>
#include <mutex>
#include <vector>
#include <utility>

static void glfw_error_callback(int error, const char* description);

struct GLFWwindow;

class FoxUI
{
public:
  FoxUI(unsigned short, unsigned short);
  ~FoxUI();

  enum class States
  {
    WAITING_FILE_PATH,
    WAITING_ANALYZE_BUTTON,
    CALCULATING,
    DONE,
    ERROR
  };

  void runUI();
  bool isAlive();

  void setState(States state);
  States getState();

  void pushError(std::string what);
  void pushField(const std::string& field, const std::string& data);

  std::string getFilePath();
private:
  void createWindow(const std::string& name);
  void newFrame();
  void render();

  unsigned short windowWidth, windowHeight;
  std::string filepath;
  std::vector<std::string> errors;

  //doesn't need to use map
  std::vector<std::pair<std::string, std::string>> executableFields;

  std::mutex filepath_lock;
  std::mutex executableFields_lock;
  std::mutex errors_lock;
  std::mutex renderState_lock;

  States renderState = States::WAITING_FILE_PATH;

  GLFWwindow* window;
};
