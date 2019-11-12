#include "SectionTable.h"
#include "Tracer.h"
#include <assert.h>
#include <string.h>

namespace section {
	SectionTable::SectionTable() 
	: sec_autogen_id_last(1)
	{
		
	}
	
	SectionTable::~SectionTable() {
		
	}
	
	bool SectionTable::init() {
		this->m_initialized = true;
		return m_initialized;
	}
	
	bool SectionTable::uninit() {
		return true;
	}
	
	/* // this function is useless because HANDLE is only unique if paired with ASID.
	   // forcing open remote process with HANDLE the same as current asid is useless.
	bool SectionTable::map_section_to_process_with_open(uint64_t current_asid, uint64_t target_asid, uint32_t handle, 
		uint64_t base_addr, uint32_t size, void* p) {
		//
		assert(this->m_initialized);
		
		auto cspl_it = this->m_section_process_entry.find(target_asid);
		if (cspl_it == this->m_section_process_entry.end()) {
			const SECTION_GLOBAL_ENTRY* p_sgb = this->find_section_global_entry(current_asid, handle);
			assert(p_sgb != NULL);
			SECTIONID ns = p_sgb->id;
			assert(ns > 0);
			
			// turns out the remote process handle cannot be assumed to be the same
			// as the current handle.
			// handle index is specific for each process.
			assert(this->_open_section_with_id(target_asid, handle, ns, p));
		}
		
		return this->map_section_to_process(target_asid, handle, base_addr, size, p);
	}
	*/
	
	bool SectionTable::map_section_to_process(uint64_t current_asid, uint32_t current_handle, 
				uint64_t remote_asid, uint64_t base_addr, uint32_t size, void* p) {
		// one issue not handled here:
		// TODO: handle: it is possible to map a same section more than once in one process!
		
		assert(this->m_initialized);
        
		auto cspl_it = this->m_section_process_entry.find(current_asid);
		// check if current_asid already in process entry
		// if not exist, meaning the ZwOpen/CreateSection has not been included in recording
		// which is should be!!
		if (cspl_it == this->m_section_process_entry.end()) {
			tracer::TrcTrace(p, TRC_BIT_WARN, "Unable to find current process entry with asid=%lx", 
					current_asid);
			return false;
		}
		
		const SECTION_PROCESS_LIST& cspl = cspl_it->second;
		
		auto csh_it = cspl.handle_to_section_map.find(current_handle);
		// if not exist, meaning the ZwOpen/CreateSection has not been included in recording
		// which is should be!!
		if (csh_it == cspl.handle_to_section_map.end()) {
			tracer::TrcTrace(p, TRC_BIT_WARN, "Unable to find current handle %x in current process %lx",
					current_handle, current_asid);
			return false;
		}
		
		SECTIONID section_id = csh_it->second;
		
		// add section to process
		// if process does not exist, add it.
		SECTION_PROCESS_LIST& spl = this->m_section_process_entry[remote_asid];
		
		// base_addr should not have been mapped. Otherwise, there must have been
		// unmap call that's missed!!
		assert(spl.sections_map.find(base_addr) == spl.sections_map.end());
		
		// TODO: same section can be mapped at multiple different base addresses
		//spl.sections_to_base_addr_map[section_id] = base_addr;
		spl.section_to_base_set_map[section_id].insert(base_addr);
		
		SECTION_PROCESS_ENTRY spe;
		spe.base_addr = base_addr;
		// handle information is specific per process. Same section opened in two different
		// process will have two different handle value.
		if (remote_asid == current_asid) {
			spe.handle = current_handle;
		} else {
			spe.handle = INVALID_HANDLE_VALUE;
		}
		spe.id = section_id;
		spe.size = size;
		spl.sections_map[base_addr] = spe;
		
		// if handle_to_section_map already contain SECTIONID data, 
		// ZwCreate / Open must have been called previously, and thus, global section entry must contain
		// the sectionid.
		assert(this->m_global_section_entry.find(section_id) != this->m_global_section_entry.end());
		SECTION_GLOBAL_ENTRY& sge = this->m_global_section_entry[section_id];
		sge.mapped_asid_set.insert(remote_asid);
		
		return true;
		
	}
	
	bool SectionTable::is_section_open_in_process(uint64_t asid, uint32_t handle, void* p) const {
		assert(this->m_initialized);
		
		auto cspl_it = this->m_section_process_entry.find(asid);
		if (cspl_it == this->m_section_process_entry.end()) {
			return false;
		}
		
		const SECTION_PROCESS_LIST& cspl = cspl_it->second;
		if (cspl.handle_to_section_map.find(handle) == cspl.handle_to_section_map.end()) {
			return false;
		} else {
			return true;
		}
	}
	
	bool SectionTable::_is_str_empty(const char* str) {
		return str == NULL || strcmp(str, "") == 0;
	}
	
	//bool SectionTable::create_new_section(uint64_t asid, uint32_t handle, 
	//const char* name, void* p) {
	//	return this->create_new_section(asid, handle, name, p, 0, 0);
	//}
	
	bool SectionTable::create_new_section(uint64_t asid, uint32_t handle, 
	const char* name, void* p, uint64_t pc, uint32_t tid) {
		assert(this->m_initialized);
		
        // in Windows 7, create new section with same name will result in Error. Thus, it can be made NOP if
        // create new section with same name is performed.
		// nope, since this func is just monitoring, whatever. just rewrite it anyway.
        // if Name is NULL / empty --> create new section everytime.
		
		SECTION_GLOBAL_ENTRY entry;
		SECTIONID section_id = this->_autogen_section_id();
		entry.id = section_id;
		//entry.creator_asid = asid;
		entry.creator_exec.asid = asid;
		entry.creator_exec.insn_addr = pc;
		entry.creator_exec.tid = tid;
		if (name == NULL || strcmp(name, "") == 0) {
			entry.name = "";
		} else {
			// named section means it might be accessible from other processes.
			// and names must be unique throughout entire Windows object names.
			entry.name = name;
			this->m_global_section_name_map[entry.name] = section_id;
		}
		
		this->m_global_section_entry[section_id] = entry;
		
		SECTION_PROCESS_LIST& spl = this->m_section_process_entry[asid];
		spl.handle_to_section_map[handle] = section_id;
		
		return true;
		
	}
	
	bool SectionTable::unmap_section_in_process(uint64_t asid, uint64_t base_addr, void* p) {
		assert(this->m_initialized);
		
        // check if section is not mapped, then simply NOP.
        if (this->m_section_process_entry.find(asid) == this->m_section_process_entry.end()) {
			tracer::TrcTrace(p, TRC_BIT_WARN, "cannot find process with asid=%lx to unmap", asid);
			return false;
		}
		
		SECTION_PROCESS_LIST& spl = this->m_section_process_entry[asid];
		if (spl.sections_map.find(base_addr) == spl.sections_map.end()) {
			tracer::TrcTrace(p, TRC_BIT_WARN, "cannot find section mapped to %lx in process with asid %lx",
					base_addr, asid);
			return false;
		}
		
		const SECTION_PROCESS_ENTRY& copy_spe = spl.sections_map[base_addr];
		
		// global section data must exist
		// if SECTION_PROCESS_LIST has been handled.
		assert(this->m_global_section_entry.find(copy_spe.id) != this->m_global_section_entry.end());
		bool is_remove_section = false;
		
		if (spl.section_to_base_set_map.find(copy_spe.id) != 
		spl.section_to_base_set_map.end()) {
			std::set < uint64_t >& base_set = spl.section_to_base_set_map[copy_spe.id];
			assert(base_set.find(base_addr) != base_set.end());
			if (base_set.size() == 1) {
				is_remove_section = true;
			}
			base_set.erase(base_addr);
		}
		
		SECTION_GLOBAL_ENTRY& sge = this->m_global_section_entry[copy_spe.id];
		
		
		if (is_remove_section) {
			spl.section_to_base_set_map.erase(copy_spe.id);
			// INVALID_HANDLE_VALUE can occur if the Section is opened by remote process (via NtMapViewOfSection)
			// and the current process does nothing about it (no create/open/others)
			if (copy_spe.handle != INVALID_HANDLE_VALUE) {
				// error, only remove it if no more mapped sections in process.
				if (spl.handle_to_section_map.find(copy_spe.handle) != spl.handle_to_section_map.end()) {
					spl.handle_to_section_map.erase(copy_spe.handle);
				}
			}
			
			// if base_addr is recorded, then the global entry must contain the asid of the process
			// in mapped_asid_set.
			//assert(spl.sections_map.size() == 1);
			assert(sge.mapped_asid_set.find(asid) != sge.mapped_asid_set.end());
			sge.mapped_asid_set.erase(asid);
		}
		
		spl.sections_map.erase(base_addr);
		
		return true;
	}
	
	bool SectionTable::find_all_mapped_sections(uint64_t source_asid, uint64_t write_addr, 
	uint32_t write_size, std::vector < SECTION_WRITE_ENTRY >& out, void* p) const {
		assert(this->m_initialized);
		
		auto pit = this->m_section_process_entry.find(source_asid);
		// possible for no section entries at beginning.
		if (pit == this->m_section_process_entry.end()) {
			return false;
		}
		
		const SECTION_PROCESS_LIST& spl = pit->second;
		// the following case is possible if the section hasn't been mapped yet, but opened.
		if (spl.sections_map.empty()) {
			return false;
		}
		
		// check for overlapping addresses in sections_map.
		// there shouldn't be any overlapping memory regions.
		uint64_t prev_high = 0;
		for (auto it = spl.sections_map.begin(); it != spl.sections_map.end(); ++it) {
			assert(it->first == it->second.base_addr);
			if (prev_high > 0) {
				assert(prev_high <= it->first);
			}
			prev_high = it->first + it->second.size;
		}
		
		auto spl_lb_it = spl.sections_map.lower_bound(write_addr);
		
		// write_rva is the offset of write_addr relative to its section base address
		uint64_t write_rva = 0;
		SECTIONID found_section_id = 0;
		const SECTION_PROCESS_ENTRY& selb = spl_lb_it->second;
		if (selb.base_addr == write_addr) {
			if (selb.base_addr + selb.size >= write_addr + write_size) {
				// match the region
				write_rva = write_addr - selb.base_addr;
				found_section_id = selb.id;
			}
		} else {
			if (spl_lb_it != spl.sections_map.begin()) {
				spl_lb_it--;
				
				const SECTION_PROCESS_ENTRY& nselb = spl_lb_it->second;
				
				if (nselb.base_addr <= write_addr && 
				nselb.base_addr + nselb.size >= write_addr + write_size) {
					write_rva = write_addr - nselb.base_addr;
					found_section_id = nselb.id;
				}
			}
		}
		
		if (found_section_id == 0) {
			return false;
		}
		
		assert(this->m_global_section_entry.find(found_section_id) != this->m_global_section_entry.end());
		const SECTION_GLOBAL_ENTRY& sgb = this->m_global_section_entry.find(found_section_id)->second;
		
		for (auto it = sgb.mapped_asid_set.begin(); it != sgb.mapped_asid_set.end(); ++it) {
			uint64_t proc_asid = *it;
			
			// skip writes to current process
			if (source_asid == proc_asid) {
				continue;
			}
			
			auto pit = this->m_section_process_entry.find(proc_asid);
			assert(pit != this->m_section_process_entry.end());
			
			const SECTION_PROCESS_LIST& proc_spl = pit->second;
			
			//auto psit = proc_spl.sections_to_base_addr_map.find(found_section_id);
			//assert(psit != proc_spl.sections_to_base_addr_map.end());
			auto psit = proc_spl.section_to_base_set_map.find(found_section_id);
			assert(psit != proc_spl.section_to_base_set_map.end());
			
			const std::set < uint64_t >& base_set = psit->second;
			for (auto bit = base_set.begin(); bit != base_set.end(); ++bit) {
				// obtain section base address
				//uint64_t proc_sba = psit->second;
				uint64_t proc_sba = *bit;
				
				SECTION_WRITE_ENTRY swe;
				swe.asid = proc_asid;
				swe.size = write_size;
				swe.addr = write_rva + proc_sba;
				
				out.push_back(swe);
			}
			
		}
		
		return true;
	}
	
	bool SectionTable::_open_section_with_id(uint64_t asid, uint32_t handle, SECTIONID section_id, void* p) {
		assert(this->m_initialized);
		assert(this->m_global_section_entry.find(section_id) != this->m_global_section_entry.end());
		
		// if no SECTION_PROCESS_LIST found, add it automatically.
		SECTION_PROCESS_LIST& spl = this->m_section_process_entry[asid];
		
		spl.handle_to_section_map[handle] = section_id;
		return true;
	}
	
    // create a new open_section (private method), change const char* name to SECTIONID instead.
    // old open_section will call this new one.
    
	bool SectionTable::open_section(uint64_t asid, uint32_t handle, const char * name, void* p) {
		assert(this->m_initialized);
		
		if (_is_str_empty(name)) {
			tracer::TrcTrace(p, TRC_BIT_WARN, "name is empty for trying to open section in process %lx, handle %x",
					asid, handle);
			return false;
		}
		
		std::string str_name(name);
		auto git = this->m_global_section_name_map.find(str_name);
		if (git == this->m_global_section_name_map.end()) {
			tracer::TrcTrace(p, TRC_BIT_WARN, "unable to find name [%s] in global section entry",
					name);
			return false;
		}
		
		SECTIONID section_id = git->second;
		return this->_open_section_with_id(asid, handle, section_id, p);
		
	}
	
	const SECTION_GLOBAL_ENTRY* SectionTable::find_section(const char * name) const {
		std::string str_name(name);
		
		auto it = this->m_global_section_name_map.find(str_name);
		if (it == this->m_global_section_name_map.end()) {
			return NULL;
		}
		
		SECTIONID section_id = it->second;
		
		auto sit = this->m_global_section_entry.find(section_id);
		assert(sit != this->m_global_section_entry.end());
		
		return &(sit->second);
	}
		
	const SECTION_PROCESS_ENTRY* SectionTable::find_section(
	uint64_t asid, uint32_t section_handle, uint64_t base_addr) const {
		
		const std::set < uint64_t >* p_bs = this->find_mapped_base_addr_for_section(
				asid, section_handle);
		if (p_bs == NULL) {
			return NULL;
		}
		
		auto secit = p_bs->find(base_addr);
		assert(secit != p_bs->end());
		
		const SECTION_PROCESS_LIST& spl = this->m_section_process_entry.find(asid)->second;
		assert(spl.sections_map.find(base_addr) != spl.sections_map.end());
		
		return &(spl.sections_map.find(base_addr)->second);
	}
	
	const std::set < uint64_t >* SectionTable::find_mapped_base_addr_for_section(
	uint64_t asid, uint32_t section_handle) const {
		
		auto sit = this->m_section_process_entry.find(asid);
		if (sit == this->m_section_process_entry.end()) {
			return NULL;
		}
		
		const SECTION_PROCESS_LIST& spl = sit->second;
		auto split = spl.handle_to_section_map.find(section_handle);
		if (split == spl.handle_to_section_map.end()) {
			return NULL;
		}
		
		SECTIONID section_id = split->second;
		
		auto ssit = spl.section_to_base_set_map.find(section_id);
		assert(ssit != spl.section_to_base_set_map.end());
		
		return &(ssit->second);
		
	}
	
	bool SectionTable::check_mapped_section(uint64_t asid, uint32_t section_handle) const {
		auto sit = this->m_section_process_entry.find(asid);
		if (sit == this->m_section_process_entry.end()) {
			return false;
		}
		
		const SECTION_PROCESS_LIST& spl = sit->second;
		auto split = spl.handle_to_section_map.find(section_handle);
		if (split == spl.handle_to_section_map.end()) {
			return false;
		}
		
		SECTIONID section_id = split->second;
		
		auto ssit = spl.section_to_base_set_map.find(section_id);
		if (ssit == spl.section_to_base_set_map.end()) {
			return false;
		} else {
			return true;
		}
	}
	
	const SECTION_PROCESS_ENTRY* SectionTable::find_section_by_base_addr(uint64_t asid, uint64_t base_addr) const {
		auto sit = this->m_section_process_entry.find(asid);
		if (sit == this->m_section_process_entry.end()) {
			return NULL;
		}
		
		const SECTION_PROCESS_LIST& spl = sit->second;
		auto secit = spl.sections_map.find(base_addr);
		if (secit == spl.sections_map.end()) {
			return NULL;
		}
		
		return &(secit->second);
	}
	
	const SECTION_GLOBAL_ENTRY* SectionTable::find_section_global_entry_by_base_addr(uint64_t asid, 
	uint64_t base_addr) const {
		
		const SECTION_PROCESS_ENTRY* p_spe = this->find_section_by_base_addr(asid, base_addr);
		assert(p_spe != NULL);
		
		auto it = this->m_global_section_entry.find(p_spe->id);
		assert(it != this->m_global_section_entry.end());
		
		return &(it->second);
	}
		
	const SECTION_GLOBAL_ENTRY* SectionTable::find_section_global_entry(uint64_t asid, uint32_t section_handle) const {
		
		auto sit = this->m_section_process_entry.find(asid);
		if (sit == this->m_section_process_entry.end()) {
			return NULL;
		}
		
		const SECTION_PROCESS_LIST& spl = sit->second;
		auto split = spl.handle_to_section_map.find(section_handle);
		if (split == spl.handle_to_section_map.end()) {
			return NULL;
		}
		
		SECTIONID sid = split->second;
		assert(sid > 0);
		
		auto git = this->m_global_section_entry.find(sid);
		assert(git != this->m_global_section_entry.end());
		
		return &(git->second);
		
	}
	
	SECTIONID SectionTable::_autogen_section_id() {
		return this->sec_autogen_id_last++;
	}
	
}
