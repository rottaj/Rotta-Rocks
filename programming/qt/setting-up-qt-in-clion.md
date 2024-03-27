# Setting up Qt in CLion

## Introduction

This page is for configuring CLion for Qt development.&#x20;

If having trouble with "Go to declaration": Invalid caches, if this doesn't work: Close Project > Open Project > Select CMakeList.txt

## CMakeList.txt

Note: When first building your cmake project, you may need to delete `target_link_libraries` and add it after the initial build. For some reason I've had problems with CMake detecting the source.

```cmake
cmake_minimum_required(VERSION 3.27)
project(client)

set(CMAKE_CXX_STANDARD 14)

set(Qt6_DIR "~/Qt/6.5.3/gcc_64/lib/cmake/Qt6")

find_package(Qt6 COMPONENTS Core Widgets REQUIRED)

include_directories("~/Qt/6.5.3/gcc_64/include/")
include_directories("~/Qt/6.5.3/gcc_64/include/QtCore")

add_executable(client
        main.cpp
)


target_link_libraries(client Qt6::Core Qt6::Widgets)
```

## CMakeList.txt meta-object compiler

We need to specify sources to include in the moc (meta-object compiler) we can do this as follows:\
If we don't include this we will get all sorts of ugly vtable errors.

```cmake
set (SOURCES
        main.cpp
        Src/App/AppManager.cpp
        Src/App/MainWindow.cpp

)

set (HEADERS
        AppGlobalNamespace.h
        Include/App/AppManager.h
        Include/App/MainWindow.h
)


QT6_WRAP_CPP(MOC_SOURCES ${HEADERS})

add_executable(client ${SOURCES} ${MOC_SOURCES})
```

###

## CLion CMake Profile

Next you need to add a custom CMake profile for Qt. This is as follows:

<figure><img src="../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

Here is what is needed:

* Add working directory: \~/Qt/\<version>/\<compiler>/bin
* Remote "Before Launch" and add "CMake: Target: all"







