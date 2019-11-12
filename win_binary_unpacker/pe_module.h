/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   pe_module.h
 * Author: darryl
 *
 * Represents the PE image in memory, including main executable and the import
 * dlls. This is just a passive object.
 * 
 * Created on August 12, 2017, 10:16 PM
 */

#ifndef PE_MODULE_H
#define PE_MODULE_H

#include "types.h"

#include <string>
using std::string;

#include <vector>
using std::vector;

#include <cstdint>

// TODO: add capabilities to PEModule
// 

namespace unpacker {
    namespace module {
        
        struct PEImport {
            
            string dll_name;
            
            vector<string> v_import_func_name;
            
        };
        
        struct PESection {
            
            // name of section
            string name;
            
            // section size when loaded to memory
            types::size_t virtual_size;
            
            // section size in disk
            types::size_t disk_size;
            
            // section address when loaded to memory
            types::addr_t rva_virtual_addr;
            
            // section address in disk
            uint32_t rva_disk_addr;
            
            // 
            uint32_t characteristics;
        };
        
        class PEModule {
            
        public:
            PEModule();
            ~PEModule();
            
            void set_base_addr(types::addr_t base_addr);
            types::addr_t get_base_addr() const;
            
            void set_image_name(const char * image_name);
            const char * get_image_name() const;
            
            void set_timestamp(uint64_t timestamp);
            uint64_t get_timestamp() const;
            
            void set_image_size(uint32_t size);
            uint32_t get_image_size() const;
            
            vector<PEImport>& get_imports();
            
            vector<string>& get_exports();
            
            vector<PESection>& get_sections();
            
        private:
            
            PEModule(PEModule const&);
            void operator=(PEModule const&);
            
            static const int MAX_IMPORTS;
            
            types::addr_t m_base_addr;
            string m_image_full_name;
            uint64_t m_timestamp;
            uint32_t m_image_size;
            
            // import table of the module
            vector<PEImport> m_imports;
            
            // export function list
            vector<string> m_exports;
            
            
            vector<PESection> m_sections;
            
            // don't use PE Header info
            // that is tied in to Windows platform
            // just extract what is needed from PE Header info
            // and put it here
        };
    }
}

#endif /* PE_MODULE_H */

