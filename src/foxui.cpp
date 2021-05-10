#include "foxui.h"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl2.h"
#include "ImGuiFileBrowser.h"

#include <chrono>
#include <thread>
#include <iostream>
#include <stdio.h>
#include <stdexcept>

#ifdef __APPLE__
#define GL_SILENCE_DEPRECATION
#endif

#include <GLFW/glfw3.h>


static void glfw_error_callback(int error, const char* description)
{
  fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

void Resize(GLFWwindow*, const int width, const int heigth)
{
  glViewport(0, 0, width, heigth);
}

FoxUI::FoxUI(unsigned short winW, unsigned short winH):
  windowWidth(winW),
  windowHeight(winH)
{
  glfwSetErrorCallback(glfw_error_callback);
  if (!glfwInit())
  {
    throw std::runtime_error("[FoxUI] Could not initialize glfw");
  }

  createWindow("Executable Analyzer");

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO(); (void)io;

  ImGuiStyle* style = &ImGui::GetStyle();

  style->Colors[ImGuiCol_Text] = ImVec4(0.80f, 0.80f, 0.83f, 1.00f);
  style->Colors[ImGuiCol_TextDisabled] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
  style->Colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
  style->Colors[ImGuiCol_ChildBg] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
  style->Colors[ImGuiCol_PopupBg] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
  style->Colors[ImGuiCol_Border] = ImVec4(0.80f, 0.80f, 0.83f, 0.88f);
  style->Colors[ImGuiCol_BorderShadow] = ImVec4(0.92f, 0.91f, 0.88f, 0.00f);
  style->Colors[ImGuiCol_FrameBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
  style->Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
  style->Colors[ImGuiCol_FrameBgActive] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
  style->Colors[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
  style->Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(1.00f, 0.98f, 0.95f, 0.75f);
  style->Colors[ImGuiCol_TitleBgActive] = ImVec4(0.07f, 0.07f, 0.09f, 1.00f);
  style->Colors[ImGuiCol_MenuBarBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
  style->Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
  style->Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
  style->Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
  style->Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
  style->Colors[ImGuiCol_CheckMark] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
  style->Colors[ImGuiCol_SliderGrab] = ImVec4(0.80f, 0.80f, 0.83f, 0.31f);
  style->Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
  style->Colors[ImGuiCol_Button] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
  style->Colors[ImGuiCol_ButtonHovered] = ImVec4(0.24f, 0.23f, 0.29f, 1.00f);
  style->Colors[ImGuiCol_ButtonActive] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
  style->Colors[ImGuiCol_Header] = ImVec4(0.10f, 0.09f, 0.12f, 1.00f);
  style->Colors[ImGuiCol_HeaderHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
  style->Colors[ImGuiCol_HeaderActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
  style->Colors[ImGuiCol_ResizeGrip] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
  style->Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.56f, 0.56f, 0.58f, 1.00f);
  style->Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.06f, 0.05f, 0.07f, 1.00f);
  style->Colors[ImGuiCol_PlotLines] = ImVec4(0.40f, 0.39f, 0.38f, 0.63f);
  style->Colors[ImGuiCol_PlotLinesHovered] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
  style->Colors[ImGuiCol_PlotHistogram] = ImVec4(0.40f, 0.39f, 0.38f, 0.63f);
  style->Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(0.25f, 1.00f, 0.00f, 1.00f);
  style->Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.25f, 1.00f, 0.00f, 0.43f);
  //style->Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(1.00f, 0.98f, 0.95f, 0.73f);

  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL2_Init();
}

FoxUI::~FoxUI()
{
  ImGui_ImplOpenGL2_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();

  glfwDestroyWindow(window);
  glfwTerminate();
}

void FoxUI::runUI()
{
  static imgui_addons::ImGuiFileBrowser file_test;
  static std::string selected_file;
  static bool file_dialog_open = true;

  newFrame();

  int display_w, display_h;
  glfwGetFramebufferSize(window, &display_w, &display_h);
  windowWidth = display_w;
  windowHeight = display_h;

  ImGui::SetNextWindowPos(ImVec2(0, 0));
  ImGui::SetNextWindowSize(ImVec2(windowWidth, windowHeight));
  if (ImGui::Begin("Exec", 0, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize))
  {
    auto current_state = getState(); //thread safe fox shit
    switch (current_state)
    {
    case States::WAITING_FILE_PATH:
      //only once popup
      if (file_dialog_open)
      {
        ImGui::OpenPopup("Open File");
        file_dialog_open = false;
      }
      ImGui::SetNextWindowSize(ImVec2(windowWidth, windowHeight));
      if (file_test.showFileDialog("Open File", imgui_addons::ImGuiFileBrowser::DialogMode::OPEN, ImVec2(windowWidth, windowHeight), ".exe,.sh,.out"))
      {
        selected_file = file_test.selected_path;

        //for main fox thread

        //write selected file
        filepath_lock.lock();
        this->filepath = selected_file;
        filepath_lock.unlock();

        //set state to "waiting analyze button"
        renderState_lock.lock();
        this->renderState = States::WAITING_ANALYZE_BUTTON; //next state after file path wait
        renderState_lock.unlock();
      }
      break;
    case States::WAITING_ANALYZE_BUTTON:
      ImGui::TextColored(ImVec4(1.0, 0.0, 0.0, 1.0), "Selected file path: %s", selected_file.c_str());
      ImGui::Separator();
      if (ImGui::Button("Analyze"))
      {
        renderState_lock.lock();
        this->renderState = States::CALCULATING; //next state after file path wait
        renderState_lock.unlock();
      }
      break;

    case States::CALCULATING:
      ImGui::TextColored(ImVec4(0.0, 1.0, 0.0, 1.0), "Analyzing %s", selected_file.c_str());
      break;
    case States::DONE:
      ImGui::TextColored(ImVec4(0.0, 1.0, 0.0, 1.0), "Done\nResults for %s", selected_file.c_str());

      executableFields_lock.lock();
      for (auto element : executableFields)
      {
        ImGui::TextColored(ImVec4(1.0, 1.0, 1.0, 1.0), "%s : %s", element.first.c_str(), element.second.c_str());
      }
      executableFields_lock.unlock();
      break;

    case States::ERROR:
      ImGui::TextColored(ImVec4(1.0, 0.0, 0.0, 1.0), "Errors happened:");
      errors_lock.lock();
      for (auto element : this->errors)
      {
        ImGui::TextColored(ImVec4(1.0, 0.0, 0.0, 1.0), "%s", element.c_str());
      }
      errors_lock.unlock();
      break;

    default:
      ImGui::TextColored(ImVec4(1.0, 0.0, 0.0, 1.0), "UNKNOWN FOXUI STATE");
    }

    ImGui::End();
  }
  //ImGui::ShowDemoWindow();

  render();
}

bool FoxUI::isAlive()
{
  return !glfwWindowShouldClose(window);
}

void FoxUI::setState(FoxUI::States state)
{
  renderState_lock.lock();
  this->renderState = state;
  renderState_lock.unlock();
}

FoxUI::States FoxUI::getState()
{
  States tempState;

  renderState_lock.lock();
  tempState = this->renderState;
  renderState_lock.unlock();

  return tempState;
}

void FoxUI::pushError(std::string what)
{
  errors_lock.lock();
  this->errors.push_back(what);
  errors_lock.unlock();
}

void FoxUI::pushField(const std::string& field, const std::string& data )
{
  std::pair<std::string, std::string> tempPairField(field, data);
  executableFields_lock.lock();
  executableFields.push_back(tempPairField);
  executableFields_lock.unlock();
}

std::string FoxUI::getFilePath()
{
  using namespace std::chrono_literals;

  std::string tempFilePath;
  while (true)
  {
    filepath_lock.lock();
    renderState_lock.lock();
    if (!filepath.empty() && (renderState != States::WAITING_FILE_PATH) && (renderState != States::WAITING_ANALYZE_BUTTON))
    {
      tempFilePath = filepath;
      filepath_lock.unlock();
      renderState_lock.unlock();
      break;
    }
    renderState_lock.unlock();
    filepath_lock.unlock();


    std::this_thread::sleep_for(10ms);
  }
  return tempFilePath;
}

void FoxUI::createWindow(const std::string& name)
{
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 1);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_ANY_PROFILE);
  glfwWindowHint(GLFW_RESIZABLE, true);

/*#ifdef __APPLE__
  glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif*/

  window = glfwCreateWindow(windowWidth, windowHeight, name.c_str(), 0, 0);
  if (window == 0)
  {
    throw std::runtime_error("[FoxUI] Could not create window");
  }

  glfwMakeContextCurrent(window);
  glfwSetFramebufferSizeCallback(window, Resize);

  //vsync
  glfwSwapInterval(1);
}

void FoxUI::newFrame()
{
  glfwPollEvents();

  ImGui_ImplOpenGL2_NewFrame();
  ImGui_ImplGlfw_NewFrame();
  ImGui::NewFrame();
}

void FoxUI::render()
{
  ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

  ImGui::Render();
  

  glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
  glClear(GL_COLOR_BUFFER_BIT);

  ImGui_ImplOpenGL2_RenderDrawData(ImGui::GetDrawData());

  glfwSwapBuffers(window);
}
