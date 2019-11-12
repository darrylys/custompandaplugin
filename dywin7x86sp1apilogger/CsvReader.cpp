/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "CsvReader.h"

#include <sstream>

namespace csvreader {
    
    /**
     * Splits one line csv separated by comma (,) into tokens.
     * @param str
     * @param cells, output vector of list of strings.
     * @return true if successful, false otherwise
     */
    bool parse_csv(const char * str, std::vector<std::string> &cells) {
        
        std::stringstream stream_csv(str);
        std::string cell;
        
        while(std::getline(stream_csv, cell, ',')) {
            cells.push_back(cell);
        }
        
        // handling last trailing comma, adding empty string
        // if str is "A,B,C,D," , cells contain "A", "B", "C", "D" and "" (empty string, quotes for clarity)
        if (!stream_csv && cell.empty()) {
            cells.push_back("");
        }
        
        return true;
        
    }
    
}
