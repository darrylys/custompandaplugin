/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "logger.h"
#include "logger_impl.h"

#include "config.h"

#include <cstdio>
#include <cstdarg>

#include <sstream>
using std::stringstream;

namespace unpacker {
    namespace logger {
        
        // convenience methods
        
        /**
         * 
         * @param str
         */
        void info(const char * str, ...) {
            va_list args;
            va_start (args, str);
            unpacker::config::Config::getInstance().getLogger().info(str, args);
            va_end (args);
        }
        
        /**
         * 
         * @param str
         */
        void debug(const char * str, ...) {
            va_list args;
            va_start (args, str);
            unpacker::config::Config::getInstance().getLogger().debug(str, args);
            va_end (args);
        }
        
        /**
         * 
         * @param str
         */
        void warn(const char * str, ...) {
            va_list args;
            va_start (args, str);
            unpacker::config::Config::getInstance().getLogger().warn(str, args);
            va_end (args);
        }
        
        /**
         * 
         * @param str
         */
        void error(const char * str, ...) {
            va_list args;
            va_start (args, str);
            unpacker::config::Config::getInstance().getLogger().error(str, args);
            va_end (args);
        }
        
        Logger::Logger() {
            this->m_file = stdout;
        }
        
        Logger::Logger(const char* fileName) {
            if (fileName != NULL) {
                this->m_file = fopen(fileName, "w");
            }
            
            if (this->m_file == NULL) {
                printf("Log file cannot be opened, logs are sent to stdout");
                this->m_file = stdout;
            }
        }
        
        Logger::~Logger() {
            if (this->m_file && this->m_file != stdout) {
                fclose(this->m_file);
            }
        }
        
        void Logger::writelog(const char* prefix, const char* format, va_list args) {
            if (this->m_file) {
                stringstream ss;
                ss << prefix << " " << format << std::endl;
                vfprintf(this->m_file, ss.str().c_str(), args);
            }
        }
        
        void Logger::info(const char * str, va_list args) {
            this->writelog("[INFO]", str, args);
        }
        
        void Logger::debug(const char * str, va_list args) {
            this->writelog("[DEBUG]", str, args);
        }
        
        void Logger::warn(const char * str, va_list args) {
            this->writelog("[WARN]", str, args);
        }
        
        void Logger::error(const char * str, va_list args) {
            this->writelog("[ERROR]", str, args);
        }
    }
}
