# Executable-Analyzer

Программное обеспечение для анализа исполняемых файлов (Linux, Windows)

## Описание
В ходе проекта должно быть написано программное обеспечение, которое должно анализировать исполняемые файлы по данным критериям: время создания, время последнего изменения, контрольная сумма (**MD5, SHA256, SHA512**), размер файла, наличие цифровой подписи, наличие и размер альтернативных потоков данных файловой системы у файла, разрядность запускаемого приложения, тип исполняемого файла. Также в отличие от известных решений, оно должно определить по характерным признакам компилятор, используемый для сборки исполняемого файла, непосредственное обращение к аппаратным ресурсам ПК, в частности к **GPU**, и (при возможности) время компиляции.

## GUI

Приложение поддерживает пользовательский интерфейс (но также может использоваться и в консольном режиме).
Было решено использовать кроссплатформенную библиотеку [imgui](https://github.com/ocornut/imgui) с рендером на opengl ([GLFW](https://github.com/glfw/glfw)).

## Установка и настройка репа
1. Не забываем добавить содержимое **.ssh/id_rsa.pub** в ключи гитхаба (если его нету, то выполняем ```ssh-keygen```)
2. Форкаем и выкачиваем реп по ```ssh```
3. ```cd Executable-Analyzer```
4. ```git submodule update --init --progress```
5. ```git config --global core.autocrlf input``` (для автоматической замены **CRLF** на **LF**)

## Разработка
Всё как на гитлабе, делаем изменения в форке и открываем ```pull request```

## Сборка Windows->Windows

1. Устанавливаем [cmake](https://cmake.org/download/) (Windows x64 Installer)
2. Не забываем при установке выбрать "Add CMake to the system PATH for all users".
3. Идем в папку ```scripts``` и запускаем ```configure_windows_windows.bat```  
Будут сгенерированы файлы для сборки, а также проект .sln для вижуалки. При добавлении файлов в ней, не забудьте поменять путь внизу на <путь до репа>/ExecutableAnalyzer/src (по умолчанию стоит <путь до репа>/ExecutableAnalyzer/build).
Сборка по кнопке пока что не работает.
4. Далее запускаем ```build_windows_windows.bat```  
Либо ```buildrun_windows_windows.bat```, тогда следующий пункт пропускаем.
5. Идем в папку build/Debug/ и стартуем наше приложение.

## Сборка Windows->Linux

```пусто```

## Сборка Linux->Linux

1. Идем в папку ```scripts```
2. Запускаем ```./configure_linux_linux.sh```
3. ```./build_linux_linux.sh``` для сборки проекта (исполняемый файл в папке build)

## Сборка Linux->Windows

```не поддерживается```
