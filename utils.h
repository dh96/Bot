#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

class utils {
public:
    static std::vector<std::string> split(std::string s, std::string delimiter);

    static std::string concatVector(std::vector<std::string> vec, std::string delimiter = "");
};



#endif