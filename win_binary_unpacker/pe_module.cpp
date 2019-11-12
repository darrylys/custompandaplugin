/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "pe_module.h"

namespace unpacker {
    namespace module {
        const int PEModule::MAX_IMPORTS = 128;
        
        PEModule::PEModule() {
            
        }
        
        PEModule::~PEModule() {
            
        }
        
        void PEModule::set_base_addr(types::addr_t base_addr) {
            this->m_base_addr = base_addr;
        }
        
        types::addr_t PEModule::get_base_addr() const {
            return this->m_base_addr;
        }
        
        void PEModule::set_image_name(const char* image_name) {
            this->m_image_full_name = image_name;
        }
        
        const char * PEModule::get_image_name() const {
            return this->m_image_full_name.c_str();
        }
        
        void PEModule::set_timestamp(uint64_t timestamp) {
            this->m_timestamp = timestamp;
        }
        
        uint64_t PEModule::get_timestamp() const {
            return this->m_timestamp;
        }
        
        void PEModule::set_image_size(uint32_t size) {
            this->m_image_size = size;
        }
        
        uint32_t PEModule::get_image_size() const {
            return this->m_image_size;
        }
        
        vector<PEImport>& PEModule::get_imports() {
            return this->m_imports;
        }
        
        vector<string>& PEModule::get_exports() {
            return this->m_exports;
        }
        
        vector<PESection>& PEModule::get_sections() {
            return this->m_sections;
        }
        
    }
}
