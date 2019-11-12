/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   CsvReader.h
 * Author: darryl
 *
 * Created on October 28, 2018, 9:15 PM
 */

#ifndef CSVREADER_H
#define CSVREADER_H

#include <vector>
#include <string>

namespace csvreader {
    
    bool parse_csv(const char * str, std::vector<std::string> &cells);
    
}

#endif /* CSVREADER_H */

