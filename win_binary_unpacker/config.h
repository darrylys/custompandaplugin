/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   config.h
 * Author: darryl
 *
 * Created on July 30, 2017, 3:38 PM
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "environment.h"
#include "logger_impl.h"
#include <cstdint>

#include <string>

namespace unpacker {
    namespace config {
        
        class Config {
        public:
            static Config& getInstance();
            
            /**
             * Get the logger
             * @return 
             */
            unpacker::logger::Logger& getLogger();
            
            /**
             * Get the Object to dump to disk
             * @return 
             */
            unpacker::env::Dumper& getEnvDumper();
            
            ~Config();
            
            bool init();
            const char * get_plugin_name() const;
            
            void set_target_pid(int pid);
            int get_target_pid();
            
            void set_target_proc_name(const char * proc_name);
            const char * get_target_proc_name();
            
            void set_target_cr3(uint64_t target_cr3);
            uint64_t get_target_cr3();
            
            
        private:
            // make singleton
            Config();
            Config(Config const&);
            void operator=(Config const&);
            
            std::string m_folder_name;
            unpacker::logger::Logger * m_logger;
            
            int m_target_pid;
            const char * m_target_proc_name;
            uint64_t m_target_cr3;
            bool m_initialized;
            unpacker::env::Dumper * m_m2d_dumper;
            
            void create_folder_name();
            
        };
    }
}

#endif /* CONFIG_H */

