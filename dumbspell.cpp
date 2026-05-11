#include <iostream>
#include <fstream>
#include <string>
#include <unordered_set>

// Process input and print based on presence in dict
void process_stream(std::istream& in, const std::unordered_set<std::string>& dict, bool list_mis, bool list_cor) {
    std::string token;
    while (in >> token) {
        bool exists = (dict.find(token) != dict.end());
        if ((list_mis && !exists) || (list_cor && exists)) {
            std::cout << token << "\n";
        }
    }
}

int main(int argc, char* argv[]) {
    // Fast I/O
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    std::string dict_base;
    bool list_mis = false;
    bool list_cor = false;

    // Pass 1: Parse flags
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-d" && i + 1 < argc) {
            dict_base = argv[++i];
        } else if (arg == "-l") {
            list_mis = true;
        } else if (arg == "-G") {
            list_cor = true;
        }
    }

    if (dict_base.empty()) {
        std::cerr << "Usage: " << argv[0] << " -d <dict_name> [-l | -G] [file...]\n";
        return 1;
    }

    // Load Dictionary
    std::unordered_set<std::string> dict;
    std::ifstream dfile(dict_base + ".dic");
    if (!dfile) return 1;

    std::string line;
    // Skip the count header
    std::getline(dfile, line);
    
    while (std::getline(dfile, line)) {
        // Strip trailing \r (CRLF) if present
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) {
            dict.insert(line);
        }
    }
    dfile.close();

    // Pass 2: Process files provided as arguments
    bool file_arg_found = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        // Skip flags and their arguments
        if (arg == "-l" || arg == "-G") continue;
        if (arg == "-d") {
            i++; 
            continue;
        }

        // Treat anything else as an input file
        std::ifstream ifile(arg);
        if (ifile) {
            process_stream(ifile, dict, list_mis, list_cor);
            file_arg_found = true;
        }
    }

    // If no files were passed, default to stdin
    if (!file_arg_found) {
        process_stream(std::cin, dict, list_mis, list_cor);
    }

    return 0;
}
