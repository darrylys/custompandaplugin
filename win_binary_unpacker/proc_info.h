/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   proc_info.h
 * Author: darryl
 *
 * Created on July 30, 2017, 11:14 PM
 */

#ifndef PROC_INFO_H
#define PROC_INFO_H

#include "types.h"
#include "IHeuristics.h"
#include "pe_module.h"
#include "IProcDumper.h"
#include "IProcParser.h"

#include <map>
#include <string>
#include <cstring>

namespace unpacker {

    class CloneMemory;

    /**
     * Includes:
     * PE info, PE Header, memory range, number of sections, etc.
     * IAT of the PE
     * Dynamic memory ranges
     *
     * This is a GOD object!
     * As long as there is only one GOD, it should be fine
     *
     */
    class ProcessInfo {
    public:
        ProcessInfo(unpacker::dumper::IProcDumper& d, unpacker::pep::IProcParser& p);
        ~ProcessInfo();

        void set_mem_written(types::addr_t eip, types::addr_t addr, types::size_t size, void * buf);
        bool is_mem_written(types::addr_t addr);
        void clear_mem_written();
        bool read_cloned_memory(types::addr_t addr, types::size_t size, types::byte_t *out);

        /**
         * checks whether the eip is in a written address, and passes few heuristics
         * @param oep
         * @param opaque, passed to heuristic object
         */
        void check_eip(types::addr_t oep, void * opaque = 0);

        int get_pid();
        void set_pid(int pid);

        int get_ppid();
        void set_ppid(int ppid);

        const char * get_proc_name();
        void set_proc_name(const char * proc_name);

        types::addr_t get_current_oep() const;

        unpacker::module::PEModule& get_module();
        void parse_module(void * opaque = 0);

        types::addr_t get_base_addr() const;
        void set_base_addr(types::addr_t base_addr);

    private:
        // cannot use static const, this is the workaround
        enum { HEUR_LEN = 16 };

        void init();
        void dump_proc(types::addr_t oep);
        CloneMemory * m_mmu;
        unpacker::heuristics::IHeuristics* m_heur_list[HEUR_LEN];
        types::addr_t m_prev_addr;
        std::string m_proc_name;
        int m_pid;
        int m_ppid;
        types::addr_t m_oep;
        types::addr_t m_base_addr;

        unpacker::module::PEModule m_exe;
        unpacker::dumper::IProcDumper& m_dumper;
        unpacker::pep::IProcParser& m_proc_parser;


    };
}

#endif /* PROC_INFO_H */

