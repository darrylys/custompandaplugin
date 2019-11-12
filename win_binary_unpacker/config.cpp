/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "config.h"

#include "logger_impl.h"
#include "environment.h"

#include <string>
using std::string;

#include <ctime>

// memset
#include <cstring>

// snprintf
#include <cstdio>

#define PLUGIN_NAME "win_binary_unpacker"

namespace unpacker {
    namespace config {
        
        // does nothing class
        class NopDumper : public unpacker::env::Dumper {
        public:
            NopDumper() : unpacker::env::Dumper("") { }
            ~NopDumper() { }
            void start() { }
            void dump_exe(types::byte_t * buf, int len) { }
            void dump_heap(types::byte_t * buf, int len) { }
            void dump_injected(types::byte_t * buf, int len) { }
            void end() { }
        };
        
        Config& Config::getInstance() {
            static Config instance;
            return instance;
        }
        
        Config::Config() {
            this->m_initialized = false;
            this->m_logger = NULL;
        }
        
        Config::~Config() {
            delete this->m_logger;
            delete this->m_m2d_dumper;
        }
        
        unpacker::logger::Logger& Config::getLogger() {
            if (this->m_initialized) {
                if (this->m_logger != NULL) {
                    return *(this->m_logger);
                }
            }
            static unpacker::logger::Logger StdoutLogger;
            return StdoutLogger;
        }
        
        unpacker::env::Dumper& Config::getEnvDumper() {
            if (this->m_initialized) {
                if (this->m_m2d_dumper != NULL) {
                    return *(this->m_m2d_dumper);
                }
            }
            static NopDumper NopInstance;
            return NopInstance;
        }
        
        bool Config::init() {
            if (!this->m_initialized) {
                this->create_folder_name();
                
                bool fex = unpacker::env::create_dir(this->m_folder_name.c_str());
                if (fex) {
                
                    delete this->m_logger;
                    string flx = this->m_folder_name + "/PandaUnpacker.log";
                    
                    this->m_logger = new unpacker::logger::Logger(flx.c_str());
                    this->m_m2d_dumper = new unpacker::env::Dumper(this->m_folder_name.c_str());
                    
                    this->m_initialized = true;
                    
                } else {
                    printf("Unable to create directory [%s]\n", this->m_folder_name.c_str());
                    
                }
            }
            return this->m_initialized;
        }
        
        const char * Config::get_plugin_name() const {
            return PLUGIN_NAME;
        }
        
        void Config::create_folder_name() {
            
            time_t rawtime;
            struct tm * timeinfo;

            time(&rawtime);
            timeinfo = localtime(&rawtime);
            
            char buf[32];
            memset(buf, 0, sizeof(buf));
                             //yyyy___mm___dd___hh___mm___ss
            snprintf(buf, 31, "%04d_%02d_%02d_%02d_%02d_%02d", 
                    timeinfo->tm_year + 1900,
                    timeinfo->tm_mon + 1,
                    timeinfo->tm_mday,
                    timeinfo->tm_hour,
                    timeinfo->tm_min,
                    timeinfo->tm_sec);
            
            this->m_folder_name = buf;
            
        }
        
        void Config::set_target_pid(int pid) {
            this->m_target_pid = pid;
        }
        
        int Config::get_target_pid() {
            return this->m_target_pid;
        }
        
        void Config::set_target_proc_name(const char* proc_name) {
            this->m_target_proc_name = proc_name;
        }
        
        const char * Config::get_target_proc_name() {
            return this->m_target_proc_name;
        }
        
        uint64_t Config::get_target_cr3() {
            return this->m_target_cr3;
        }
        
        void Config::set_target_cr3(uint64_t target_cr3) {
            this->m_target_cr3 = target_cr3;
        }
        
    }
}

