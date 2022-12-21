#ifndef RUNCODE_H
#define RUNCODE_H

#include <windows.h> //Windows API functions, macros , data types
#include <ctime> //get and manipulate date and time information
#include <sstream> // string streams
#include <fstream> // Input/Output File stream 
#include <cstdlib> //stdlib.h (dynamic memory man., rnd num gen usw)
#include <string> //string class

std::string CommandDispatcher(std::string request);
std::string CodeExecution(std::string command);

#endif