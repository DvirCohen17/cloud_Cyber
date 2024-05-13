#include "FileOperation.h"

std::string FileOperation::readFromFile(const std::string& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    return content;
}

bool FileOperation::fileExists(const std::string& fileName)
{
    std::ifstream file(fileName);
    return file.good();
}

void FileOperation::createFile(const std::string& fileName, bool fileType)
{
    std::ofstream file(fileName);
    if (file.is_open())
    {
        if (fileType)
        {
            //file << "Initial content of the file.";

        }
        file.close();
    }
    else
    {
        std::cerr << "Error creating the file: " << fileName << std::endl;
    }
}

bool FileOperation::deleteFile(const std::string& filePath)
{
    if (std::remove(filePath.c_str()) == 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

void FileOperation::getFilesInDirectory(const std::string& directoryPath, std::map<std::string, int>& files) {
    try {
        
        for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
            if (std::filesystem::is_regular_file(entry)) {
                std::string fileName = entry.path().filename().string();
                int fileSize = static_cast<int>(std::filesystem::file_size(entry.path()));

                // Check if the file already exists in the map
                auto it = files.find(fileName);
                if (it == files.end()) {
                    files[fileName] = 0;
                }
            }
        }
        
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading directory: " << e.what() << std::endl;
    }
}

