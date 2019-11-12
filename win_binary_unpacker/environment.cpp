/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "environment.h"
#include "logger.h"

#include <sys/stat.h>
#include <cstdio>
#include <cstring>

namespace unpacker {
    namespace env {
        
        const int DIRBUFLEN = 520;
        const int DIRBUFLENMAX = 512;
        
        bool create_dir(const char * dir_name) {
            return create_dir(dir_name, 0777);
        }
        
        bool create_dir(const char * dir_name, unsigned int mode) {
            return mkdir(dir_name, mode) != -1;
        }
        
        bool create_dir_tree(const char * dir) {
            char dircpy[DIRBUFLEN];
            memset(dircpy, 0, sizeof(dircpy));

            int dirlen = strlen(dir);
            
            if (dirlen > DIRBUFLENMAX) {
                //printf("Error, dir length more than 512 characters\n");
                return false;
            }

            strncpy(dircpy, dir, dirlen);

            if (dircpy[dirlen] != '/') {
                dircpy[dirlen] = '/';
            }

            bool mkstat = true;
            char * pp = dircpy;
            char * tp;

            while (mkstat && (tp = strchr(pp, '/')) != 0) {
                *tp = '\0';
                struct stat sb;
                if (stat(dircpy, &sb) == 0 && S_ISDIR(sb.st_mode)) {
                    // directory already exist
                    //printf("Directory %s already exist, skipping\n", dircpy);
                } else {
                    mkstat = create_dir(dircpy, 0777);
                }
                *tp = '/';
                pp = tp+1;
            }

            if (!mkstat) {
                return false;
            }

            return true;
        }
        
        
        
        Dumper::Dumper(const char* root_folder) 
        : m_root_folder(root_folder) {
            
        }
        
        Dumper::~Dumper() {
            
        }
        
        void Dumper::start() {
            
        }
        
        void Dumper::dump_exe(types::byte_t* buf, int len) {
            
        }
        
        void Dumper::dump_heap(types::byte_t* buf, int len) {
            
        }
        
        void Dumper::dump_injected(types::byte_t* buf, int len) {
            
        }
        
        void Dumper::end() {
            
        }
    }
}

