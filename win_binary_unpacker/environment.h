/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   environment.h
 * Author: darryl
 *
 * Created on July 30, 2017, 11:07 PM
 */

#ifndef ENVIRONMENT_H
#define ENVIRONMENT_H

#include "types.h"

#include <string>
using std::string;

namespace unpacker {
    namespace env {
        
        /**
         * Creates ONE directory with access 0777. 
         * Cannot create directory trees
         * @param dir_name
         * @return 
         */
        bool create_dir(const char * dir_name);
        
        /**
         * Creates ONE directory with specified access mode. 
         * Cannot create directory trees
         * @param dir_name
         * @param mode
         * @return 
         */
        bool create_dir(const char * dir_name, unsigned int mode);
        
        
        /**
         * Create directories each with access mode 0777
         * Not supporting root directories
         * Maximum directory length (total) is 512 characters.
         * 
         * @param dir. format: dir1/dir2/dir3/.../dirn. 
         * Total length must be 512 or smaller
         * 
         * @return true if the directory is created, or already exist
         */
        bool create_dir_tree(const char * dir);
        
        /**
         * writes stuff to disk
         */
        class Dumper {
        public:
            Dumper(const char * root_folder);
            virtual ~Dumper();
            
            /**
             * Starts the dump process
             * A new folder is created
             */
            virtual void start();
            
            /**
             * Dump executable memory to disk
             * @param buf
             * @param len
             */
            virtual void dump_exe(types::byte_t * buf, int len);
            
            /**
             * Dump buffer to disk
             * @param buf
             * @param len
             */
            virtual void dump_heap(types::byte_t * buf, int len);
            
            /**
             * Dump injected memory buffer to disk
             * @param buf
             * @param len
             */
            virtual void dump_injected(types::byte_t * buf, int len);
            
            /**
             * Completes the dump process
             */
            virtual void end();
            
        private:
            
            Dumper(Dumper const&);
            void operator=(Dumper const&);
            string m_root_folder;
            
            
        };
    }
}

#endif /* ENVIRONMENT_H */

