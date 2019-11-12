/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   logger_impl.h
 * Author: darryl
 *
 * Created on July 30, 2017, 4:10 PM
 */

#ifndef LOGGER_IMPL_H
#define LOGGER_IMPL_H

#include <cstdio>
#include <cstdarg>

namespace unpacker {
    namespace logger {
        class Logger {
        public:
            Logger();
            Logger(const char * fileName);
            ~Logger();
            
            void info(const char * str, va_list args);
            void debug(const char * str, va_list args);
            void warn(const char * str, va_list args);
            void error(const char * str, va_list args);
            
        private:
            Logger(Logger const&);
            void operator=(Logger const&);
            
            FILE * m_file;
            void writelog(const char * prefix, const char * format, va_list args);
            
        };
    }
}

#endif /* LOGGER_IMPL_H */

