/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   logger.h
 * Author: darryl
 *
 * Created on July 30, 2017, 3:11 PM
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <cstdarg>

#define MYINFO(format, ...) unpacker::logger::info(format, __VA_ARGS__)
#define MYDEBUG(format, ...) unpacker::logger::debug(format, __VA_ARGS__)
#define MYWARN(format, ...) unpacker::logger::warn(format, __VA_ARGS__)
#define MYERROR(format, ...) unpacker::logger::error(format, __VA_ARGS__)

namespace unpacker {
    namespace logger {
        
        void info(const char * str, ...);
        void debug(const char * str, ...);
        void warn(const char * str, ...);
        void error(const char * str, ...);
        
    }
}

#endif /* LOGGER_H */

