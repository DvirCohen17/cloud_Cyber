#include "Operations.h"

void Operations::insert(std::fstream& file, const std::string& data, const int& index)
{
    // Move the file pointer to the insertion index
    file.seekg(index, std::ios::beg);

    // Read the content after the insertion point
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string originalContentAfterIndex = buffer.str();

    // Move the file pointer back to the insertion index
    file.seekp(index, std::ios::beg);

    // Insert the new string
    file << data + originalContentAfterIndex;
}

void Operations::deleteContent(std::fstream& file, const int& lengthToDelete, const int& index, std::string name)
{
    // Read the entire content of the file into a string
    std::stringstream contentBuffer;
    contentBuffer << file.rdbuf();
    std::string fileContent = contentBuffer.str();
    // Check if the deletion index is within the bounds of the file content
    if (index >= 0 && index < fileContent.length()) {
        // Modify the content in memory
        fileContent.erase(index, lengthToDelete);

        // Clear the content of the file
        file.seekp(0, std::ios::beg);
        file.close();

        // Open the file again to truncate it
        file.open(name, std::ios::out | std::ios::trunc);

        // Write the modified content back to the file
        file << fileContent;
    }

    // Close the file
    file.close();
}

void Operations::replace(std::fstream& file, const int& selectionLength, const std::string& replacementText, const int& index, std::string name)
{
    // Read the entire content of the file into a string
    std::stringstream contentBuffer;
    contentBuffer << file.rdbuf();
    std::string fileContent = contentBuffer.str();
    // Check if the deletion index is within the bounds of the file content
    if (index >= 0 && index < fileContent.length()) {
        // Modify the content in memory
        fileContent.erase(index, selectionLength);
        fileContent.insert(index, replacementText);

        // Clear the content of the file
        file.seekp(0, std::ios::beg);
        file.close();

        // Open the file again to truncate it
        file.open(name, std::ios::out | std::ios::trunc);

        // Write the modified content back to the file
        file << fileContent;
    }

    // Close the file
    file.close();
}
/*
void Operations::insert(std::string& fileData, const std::string& data, const int& index)
{
    fileData.insert(index, data);
}

void Operations::deleteContent(std::string& fileData, const int& lengthToDelete, const int& index)
{

    if (index + lengthToDelete <= fileData.size())
    {
        fileData.erase(index, lengthToDelete);
    }
    else
    {
        throw std::runtime_error("Invalid delete operation: Index and selection length exceed file size");
    }
}

void Operations::replace(std::string& fileData, const int& selectionLength, const std::string& replacementText, const int& index)
{
    // Handle replace operation: delete data at the specific index and insert new data
    deleteContent(fileData, selectionLength, index);
    insert(fileData, replacementText, index);
}
*/