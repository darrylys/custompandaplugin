#ifndef SECTIONTABLE_H
#define SECTIONTABLE_H

#include <map>
#include <set>
#include <cstdint>
#include <string>
#include <vector>

namespace section {
	
	typedef uint32_t SECTIONID;
	
	typedef struct _EXEC_INFO {
		uint64_t asid;
		uint64_t insn_addr;
		uint32_t tid;
	} EXEC_INFO;
	
	typedef struct _SECTION_GLOBAL_ENTRY {
		
		// section id, autoincrement. This does not correspond to OS, just a convenient key for 
		// this plugin
		SECTIONID id;
		
		// set of asid of processes that mapped this section into their memory space
		std::set < uint64_t > mapped_asid_set;
		
		// section name.
		std::string name;
		
		// the process who creates this section (calls ZwCreateSection)
		//uint64_t creator_asid;
		//uint64_t creator_ins_addr;
		
		// execution context that creates this section (process, thread, instruction)
		EXEC_INFO creator_exec;
		
	} SECTION_GLOBAL_ENTRY;
	
	#define INVALID_HANDLE_VALUE ((uint32_t)(~0))
	
	typedef struct _SECTION_PROCESS_ENTRY {
		
		SECTIONID id;
		uint32_t handle;
		uint64_t base_addr;
		uint32_t size;
		
	} SECTION_PROCESS_ENTRY;
	
	typedef struct _SECTION_PROCESS_LIST {
		
		// key = base_addr
		std::map < uint64_t, SECTION_PROCESS_ENTRY > sections_map;
		
		// change this. Possible to map same section to one process multiple times
		// resulting in multiple different base addresses!
		// std::map < SECTIONID, uint64_t > sections_to_base_addr_map;
		
		// mapping for section to set of base addresses where SECTIONID is mapped to
		// one section can be mapped multiple times in one process, resulting in
		// mapped in different base addresses
		// key = SECTIONID
		std::map < SECTIONID, std::set < uint64_t > > section_to_base_set_map;
		
		// key = section handle
		// this does not always have handle
		// possible if target process is the target for some other process calls
		// NtMapViewOfSection. 
		std::map < uint32_t, SECTIONID > handle_to_section_map;
		
		
	} SECTION_PROCESS_LIST;
	
	typedef struct _SECTION_WRITE_ENTRY {
		
		uint64_t asid;
		uint64_t addr;
		uint32_t size;
		
	} SECTION_WRITE_ENTRY;
	
	class SectionTable {
	public:
		SectionTable();
		~SectionTable();
		
		bool init();

		/**
		 * @brief map section to specified asid
		 * @param current_asid the asid of process where this section will be mapped
		 * @param current_handle section handle opened / created by the process
		 * @param remote_asid the asid of targeted process. Might be the same as current process
		 * @param base_addr base address of section in target process
		 * @param size size of section in target process
		 * @param p
		 * @return 
		 */
		bool map_section_to_process(uint64_t current_asid, uint32_t current_handle, 
				uint64_t remote_asid, uint64_t base_addr, uint32_t size, void* p);
		
		
		/**
		 * @brief checks if the section is opened in process
		 * @param asid asid of process
		 * @param handle section handle supposedly opened in process
		 * @param p
		 * @return 
		 */
		bool is_section_open_in_process(uint64_t asid, uint32_t handle, void* p) const;
		
		/**
		 * @brief creates a new section in a process
		 * @param asid the asid of the caller that creates the section
		 * @param handle section handle
		 * @param name name of section
		 * @param p
		 * @return 
		 */
		//bool create_new_section(uint64_t asid, uint32_t handle, const char* name, void* p);
		
		/**
		 * @brief creates a new section in a process with added pc and tid information
		 * @param asid the asid of the caller that creates the section
		 * @param handle section handle
		 * @param name name of section
		 * @param p
		 * @param pc
		 * @param tid
		 * @return 
		 */
		bool create_new_section(uint64_t asid, uint32_t handle, const char* name, void* p, uint64_t pc, uint32_t tid);
		
		/**
		 * @brief 
		 * @param asid the asid of process where this section will be mapped
		 * @param base_addr base address of section in target process
		 * @param p
		 * @return 
		 */
		bool unmap_section_in_process(uint64_t asid, uint64_t base_addr, void* p);
		
		
		/**
		 * @brief obtains the list of processes that mapped the specified section to
		 * their memory space.
		 * @param source_asid asid of execution code
		 * @param write_addr address of written byte in source_asid
		 * @param write_size size of written address
		 * @param out output
		 * @param p
		 * @return 
		 */
		bool find_all_mapped_sections(uint64_t source_asid, uint64_t write_addr, 
		uint32_t write_size, std::vector < SECTION_WRITE_ENTRY >& out, void* p) const;
		
		/**
		 * @brief opens section to process, but this section has not been mapped.
		 * @param asid current asid of process
		 * @param handle current handle of process
		 * @param name name of section, may be empty / NULL
		 * @param p
		 * @return 
		 */
		bool open_section(uint64_t asid, uint32_t handle, const char * name, void* p);
		
		/**
		 * @brief finds section by name in global registry.
		 * @param name
		 * @param out
		 * @return NULL if failed
		 * Warning: Pointer might be invalid if the sections are modified later on.
		 */
		const SECTION_GLOBAL_ENTRY* find_section(const char * name) const;
		
		/**
		 * @brief finds section by asid and section_handle. The section must have been mapped
		 * in specified process
		 * 
		 * @param asid the asid of the specified process
		 * @param section_handle the handle of section in process
		 * @param base_addr
		 * @return NULL if failed
		 * Warning: Pointer might be invalid if the sections are modified later on.
		 */
		const SECTION_PROCESS_ENTRY* find_section(uint64_t asid, uint32_t section_handle, uint64_t base_addr) const;
		
		/**
		 * @brief obtain base addresses for section
		 * @param asid
		 * @param section_handle
		 * @return 
		 */
		const std::set < uint64_t >* find_mapped_base_addr_for_section(uint64_t asid, uint32_t section_handle) const;
		
		/**
		 * @brief checks if section is mapped in specified process
		 * @param asid current asid of process
		 * @param section_handle section handle of process
		 * @return 
		 */
		bool check_mapped_section(uint64_t asid, uint32_t section_handle) const;
		
		/**
		 * @brief 
		 * @param asid asid of process where the section is mapped at base_addr
		 * @param base_addr address where the section is mapped in process with specified asid
		 * @return NULL if failed
		 * Warning: Pointer might be invalid if the sections are modified later on.
		 */
		const SECTION_PROCESS_ENTRY* find_section_by_base_addr(uint64_t asid, uint64_t base_addr) const;
		
		/**
		 * @brief obtains the global entry section info. This method can only work if
		 * the section has been mapped to remote process.
		 * @param asid asid of remote process
		 * @param base_addr address where the section is mapped to in remote process
		 * @return 
		 */
		const SECTION_GLOBAL_ENTRY* find_section_global_entry_by_base_addr(uint64_t asid, uint64_t base_addr) const;
		
		/**
		 * @brief finds section global entry. This section might not have been mapped in specified process,
		 * but it has been opened by that process. To find the section which has not been opened in
		 * specified process, use the section name.
		 * 
		 * @param asid the asid of the specified process
		 * @param section_handle the handle
		 * @param out
		 * @return NULL if failed
		 * Warning: Pointer might be invalid if the sections are modified later on.
		 */
		const SECTION_GLOBAL_ENTRY* find_section_global_entry(uint64_t asid, uint32_t section_handle) const;
		
		/**
		 * @brief uninit object. After uninit, it cannot be used again.
		 * @return 
		 */
		bool uninit();
		
	private:
		SECTIONID sec_autogen_id_last;
		bool m_initialized;
		
		std::map < SECTIONID, SECTION_GLOBAL_ENTRY > m_global_section_entry;
		
		// key = asid
		std::map < uint64_t, SECTION_PROCESS_LIST > m_section_process_entry;
		
		std::map < std::string, SECTIONID > m_global_section_name_map;
		
		SECTIONID _autogen_section_id();
		
		bool _open_section_with_id(uint64_t asid, uint32_t handle, SECTIONID section_id, void* p);
		
		/**
		 * @brief Checks if str is null / empty
		 * @param str
		 * @return 
		 */
		static bool _is_str_empty(const char * str);
		
	};
}

#endif