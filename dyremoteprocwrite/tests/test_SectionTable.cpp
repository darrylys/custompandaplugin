#include "tests/test_main.h"
#include "SectionTable.h"
#include <cstdio>
#include <assert.h>

namespace section {
	namespace test {
		
		void create_section_expect_success() {
			printf("create_section_expect_success()\n");
			
			SectionTable st;
			
			uint64_t exp_asid = 0x10000;
			uint32_t exp_handle = 0x50;
			const char * exp_name = "expect_name";
			
			assert(st.init());
			assert(st.create_new_section(exp_asid, exp_handle, exp_name, NULL, 0, 0));
			
			const SECTION_GLOBAL_ENTRY* p_obs = st.find_section(exp_name);
			assert(p_obs != NULL);
			
			assert(p_obs->mapped_asid_set.empty());
			assert(p_obs->id == 1);
			assert(p_obs->name == exp_name);
			//assert(p_obs->creator_asid == exp_asid);
			assert(p_obs->creator_exec.asid == exp_asid);
			
			const SECTION_GLOBAL_ENTRY* p_fail = st.find_section("not_found_name");
			assert(p_fail == NULL);
			
			assert(!st.check_mapped_section(exp_asid, exp_handle));
			
			const SECTION_GLOBAL_ENTRY* p_egb = st.find_section_global_entry(exp_asid, exp_handle);
			assert(p_egb == p_obs);
			
			assert(st.uninit());
			
			printf("create_section_expect_success(): success\n");
		}
		
		void create_and_open_expect_success() {
			printf("create_and_open_expect_success()\n");
			
			SectionTable st;
			
			uint64_t exp_asid = 0x10000;
			uint32_t exp_handle = 0x50;
			const char * exp_name = "expect_name";
			
			assert(st.init());
			assert(st.create_new_section(exp_asid, exp_handle, exp_name, NULL, 0, 0));
			
			uint64_t exp_asid2 = 0x20000;
			uint32_t exp_handle2 = 0x100;
			
			assert(st.open_section(exp_asid2, exp_handle2, exp_name, NULL));
			assert(!st.check_mapped_section(exp_asid2, exp_handle2));
			assert(st.find_section_global_entry(exp_asid2, exp_handle2) == st.find_section(exp_name));
			assert(st.find_section_global_entry(exp_asid2, exp_handle2) == st.find_section_global_entry(exp_asid, exp_handle));
			
			assert(st.uninit());
			
			printf("create_and_open_expect_success(): success\n");
		}
		
		void create_and_map_expect_success() {
			printf("create_and_map_expect_success()\n");
			
			SectionTable st;
			
			uint64_t exp_asid = 0x10000;
			uint32_t exp_handle = 0x50;
			const char * exp_name = "expect_name";
			
			assert(st.init());
			assert(st.create_new_section(exp_asid, exp_handle, exp_name, NULL, 0, 0));
			
			uint64_t exp_base_addr = 0x4000000;
			uint32_t exp_size = 0x4000;
			assert(st.map_section_to_process(exp_asid, exp_handle, exp_asid, exp_base_addr, exp_size, NULL));
			
			const SECTION_PROCESS_ENTRY* p_spe_obs = st.find_section(exp_asid, exp_handle, exp_base_addr);
			assert(p_spe_obs != NULL);
			assert(p_spe_obs->handle == exp_handle);
			assert(p_spe_obs->id == 1);
			assert(p_spe_obs->size == exp_size);
			assert(p_spe_obs->base_addr == exp_base_addr);
			
			const SECTION_GLOBAL_ENTRY* p_glb = st.find_section(exp_name);
			assert(p_glb->mapped_asid_set.size() == 1);
			assert(*p_glb->mapped_asid_set.begin() == exp_asid);
			
			assert(st.uninit());
			
			printf("create_and_map_expect_success(): success\n");
		}
		
		void create_map_find_expect_success() {
			printf("create_map_find_expect_success()\n");
			
			SectionTable st;
			
			uint64_t exp_asid = 0x10000;
			uint32_t exp_handle = 0x50;
			const char * exp_name = "expect_name";
			
			assert(st.init());
			assert(st.create_new_section(exp_asid, exp_handle, exp_name, NULL, 0, 0));
			
			std::vector < SECTION_WRITE_ENTRY > out;
			assert(!st.find_all_mapped_sections(0x1234, 0, 0, out, NULL));
			assert(!st.find_all_mapped_sections(exp_asid, 0, 0, out, NULL));
			
			uint32_t write_off = 0x2345;
			
			uint64_t exp_base_addr = 0x4000000;
			uint32_t exp_size = 0x4000;
			assert(st.map_section_to_process(exp_asid, exp_handle, exp_asid, exp_base_addr, exp_size, NULL));
			
			assert(!st.find_all_mapped_sections(exp_asid, 0x50000, 4, out, NULL));
			assert(st.find_all_mapped_sections(exp_asid, exp_base_addr + write_off, 4, out, NULL));
			assert(out.empty());
			
			uint64_t exp_asid2 = 0x245000;
			uint32_t exp_handle2 = 0x6000;
			assert(st.open_section(exp_asid2, exp_handle2, exp_name, NULL));
			
			uint64_t exp_base_addr2 = 0xa20000;
			uint32_t exp_size2 = exp_size;
			assert(st.map_section_to_process(exp_asid2, exp_handle2, exp_asid2, exp_base_addr2, exp_size2, NULL));
			assert(st.find_all_mapped_sections(exp_asid2, exp_base_addr2 + write_off, 4, out, NULL));
			assert(out.size() == 1);
			
			assert(out[0].asid == exp_asid);
			assert(out[0].addr == exp_base_addr + write_off);
			assert(out[0].size == 4);
			
			printf("create_map_find_expect_success(): success\n");
		}
		
		void create_map_unmap_expect_success() {
			printf("create_map_unmap_expect_success()\n");
			
			SectionTable st;
			
			uint64_t exp_asid = 0x10000;
			uint32_t exp_handle = 0x50;
			const char * exp_name = "expect_name";
			
			assert(st.init());
			assert(st.create_new_section(exp_asid, exp_handle, exp_name, NULL, 0, 0));
			
			uint64_t exp_base_addr = 0x4000000;
			uint32_t exp_size = 0x4000;
			assert(st.map_section_to_process(exp_asid, exp_handle, exp_asid, exp_base_addr, exp_size, NULL));
			assert(st.check_mapped_section(exp_asid, exp_handle));
			const SECTION_GLOBAL_ENTRY* p_gb = st.find_section(exp_name);
			assert(p_gb->mapped_asid_set.size() == 1);
			assert(*p_gb->mapped_asid_set.begin() == exp_asid);
			
			assert(st.unmap_section_in_process(exp_asid, exp_base_addr, NULL));
			assert(!st.check_mapped_section(exp_asid, exp_handle));
			p_gb = st.find_section(exp_name);
			assert(p_gb->mapped_asid_set.empty());
			
			printf("create_map_unmap_expect_success(): success\n");
		}
		
		void create_sections_2x_expect_success() {
			printf("create_sections_2x_expect_success()\n");
			
			SectionTable st;
			
			uint64_t exp_asid = 0x10000;
			uint32_t exp_handle = 0x50;
			const char * exp_name = "expect_name";
			
			assert(st.init());
			assert(st.create_new_section(exp_asid, exp_handle, exp_name, NULL, 0, 0));
			const SECTION_GLOBAL_ENTRY* p_gb = st.find_section(exp_name);
			assert(p_gb->id == 1);
			
			uint64_t exp_asid2 = 0x20000;
			uint32_t exp_handle2 = 0x10;
			const char * exp_name2 = "expect_name2";
			assert(st.create_new_section(exp_asid2, exp_handle2, exp_name2, NULL, 0, 0));
			const SECTION_GLOBAL_ENTRY* p_gb2 = st.find_section(exp_name2);
			assert(p_gb2->id == 2);
			
			printf("create_sections_2x_expect_success(): success\n");
		}
		
		void unmap_no_mapping_expect_fail() {
			printf("unmap_no_mapping_expect_fail()\n");
			
			SectionTable st;
			
			assert(st.init());
			assert(!st.unmap_section_in_process(0x12345, 0x67890, NULL));
			
			assert(st.create_new_section(0x10000, 0x20, "", NULL,0,0));
			assert(st.map_section_to_process(0x10000, 0x20, 0x10000, 0x45000, 0x40, NULL));
			assert(!st.unmap_section_in_process(0x10000, 0x67890, NULL));
			assert(st.unmap_section_in_process(0x10000, 0x45000, NULL));
			
			printf("unmap_no_mapping_expect_fail(): success\n");
		}
		
		void map_to_remote_process_no_create_expect_success() {
			printf("map_to_remote_process_no_create_expect_success()\n");
			
			SectionTable st;
			assert(st.init());
			
			uint64_t exp_asid = 0x10000;
			uint32_t exp_handle = 0x50;
			const char * exp_name = "expect_name";
			assert(st.create_new_section(exp_asid, exp_handle, exp_name, NULL, 0, 0));
			
			uint64_t exp_asid2 = 0x234604;
			uint64_t exp_base_addr2 = 0x004d0000;
			uint32_t exp_size2 = 0x6000;
			assert(st.map_section_to_process(exp_asid, exp_handle, exp_asid2, 
					exp_base_addr2, exp_size2, NULL));
			const SECTION_PROCESS_ENTRY* pspr = st.find_section(exp_asid2, exp_handle, exp_base_addr2);
			assert(pspr == NULL);
			
			const SECTION_PROCESS_ENTRY* pevid = st.find_section_by_base_addr(exp_asid2, exp_base_addr2);
			assert(pevid != NULL);
			assert(pevid->handle == INVALID_HANDLE_VALUE);
			assert(pevid->size == exp_size2);
			assert(pevid->base_addr == exp_base_addr2);
			
			const SECTION_GLOBAL_ENTRY* peg = st.find_section_global_entry_by_base_addr(exp_asid2, exp_base_addr2);
			//assert(peg->creator_asid == exp_asid);
			assert(peg->creator_exec.asid == exp_asid);
			assert(peg->id == pevid->id);
			assert(peg->name == exp_name);
			assert(peg->mapped_asid_set.size() == 1);
			assert(*peg->mapped_asid_set.begin() == exp_asid2);
			
			const SECTION_GLOBAL_ENTRY* pev = st.find_section(exp_name);
			assert(pev == peg);
			
			printf("map_to_remote_process_no_create_expect_success(): success\n");
		}
		
		void map_twice_expect_success() {
			printf("map_twice_expect_success()\n");
			
			SectionTable st;
			assert(st.init());
			
			uint64_t exp_asid = 0x10000;
			uint32_t exp_handle = 0x50;
			const char * exp_name = "expect_name";
			assert(st.create_new_section(exp_asid, exp_handle, exp_name, NULL, 0, 0));
			
			uint64_t exp_base_addr2 = 0x004d0000;
			uint32_t exp_size2 = 0x6000;
			assert(st.map_section_to_process(exp_asid, exp_handle, exp_asid, exp_base_addr2, exp_size2, NULL));
			
			uint64_t exp_base_addr3 = 0x005d0000;
			
			assert(st.map_section_to_process(exp_asid, exp_handle, exp_asid, exp_base_addr3, exp_size2, NULL));
			
			const std::set < uint64_t >* ps = st.find_mapped_base_addr_for_section(exp_asid, exp_handle);
			assert(ps != NULL);
			assert(ps->size() == 2);
			auto psit = ps->begin();
			assert(*(psit) == exp_base_addr2);
			psit++;
			assert(*(psit) == exp_base_addr3);
			
			assert(st.find_section_global_entry_by_base_addr(exp_asid, exp_base_addr2) == 
			st.find_section_global_entry_by_base_addr(exp_asid, exp_base_addr3));
			
			const SECTION_PROCESS_ENTRY* pevid2 = st.find_section_by_base_addr(exp_asid, exp_base_addr2);
			assert(pevid2 != NULL);
			assert(pevid2->handle == exp_handle);
			assert(pevid2->size == exp_size2);
			assert(pevid2->base_addr == exp_base_addr2);
			
			const SECTION_PROCESS_ENTRY* pevid3 = st.find_section_by_base_addr(exp_asid, exp_base_addr3);
			assert(pevid3 != NULL);
			assert(pevid3->handle == exp_handle);
			assert(pevid3->size == exp_size2);
			assert(pevid3->base_addr == exp_base_addr3);
			
			// test unmap 1x
			assert(st.unmap_section_in_process(exp_asid, exp_base_addr2, NULL));
			const SECTION_GLOBAL_ENTRY* pgb = st.find_section_global_entry(exp_asid, exp_handle);
			assert(pgb != NULL);
			assert(pgb->mapped_asid_set.size() == 1);
			assert(*(pgb->mapped_asid_set.begin()) == exp_asid);
			assert(ps->size() == 1);
			assert(*(ps->begin()) == exp_base_addr3);
			
			// test unmap 1x
			assert(st.unmap_section_in_process(exp_asid, exp_base_addr3, NULL));
			const SECTION_GLOBAL_ENTRY* pgb2 = st.find_section_global_entry(exp_asid, exp_handle);
			assert(pgb2 == NULL);
			assert(pgb->mapped_asid_set.empty());
			assert(!st.check_mapped_section(exp_asid, exp_handle));
			
			printf("map_twice_expect_success(): success\n");
		}
		
	}
}

void run_test_SectionTable() {
	section::test::create_section_expect_success();
	section::test::create_and_open_expect_success();
	section::test::create_and_map_expect_success();
	section::test::create_map_find_expect_success();
	section::test::create_map_unmap_expect_success();
	section::test::create_sections_2x_expect_success();
	section::test::unmap_no_mapping_expect_fail();
	section::test::map_to_remote_process_no_create_expect_success();
	section::test::map_twice_expect_success();
}

