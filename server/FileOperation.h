#pragma once
#include <iostream>
#include <map>
#include <sstream>
#include <fstream>
#include <filesystem>

class FileOperation
{
public:
    bool fileExists(const std::string& fileName);
    void createFile(const std::string& fileName, bool fileType);
    bool deleteFile(const std::string& filePath);
    void getFilesInDirectory(const std::string& directoryPath, std::map<std::string, int>& files);
    std::string readFromFile(const std::string& filePath);
};