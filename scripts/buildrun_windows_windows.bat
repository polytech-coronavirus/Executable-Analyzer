@echo off
cls
cd ..

if exist build\ (
  cd build
  cmake --build .
) else (
  echo RUN CONFIGURE FIRST! BUILD FOLDER DOES NOT EXIST
)

if %errorlevel% == 0 (
    ..\build\Debug\ExecutableAnalyzer.exe
    pause
)


pause