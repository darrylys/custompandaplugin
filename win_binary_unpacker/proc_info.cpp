/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "proc_info.h"
#include "logger.h"

namespace unpacker {

    namespace heuristics {
        class NopHeuristic : public unpacker::heuristics::IHeuristics {
        public:
            NopHeuristic() {
            }

            ~NopHeuristic() {
            }

            double eval(unpacker::ProcessInfo& proc, void * opaque = 0) {
                return 2.0;
            }

        };
    }

    const int T_PAGE_EXP = 12;
    const int T_PAGE_MASK = (1<<T_PAGE_EXP)-1;

    struct SimPage {
        enum MemState {
            S_WRITTEN = 1,
            S_EXECUTED = 2
        };

        SimPage() {
            memset(this->page, 0, sizeof(this->page));
        }

        MemState state;
        uint8_t page[1<<T_PAGE_EXP];
    };

    // Class to keep the memory buffer that is written
    // since the OS can put some pages to disk, it is not guaranteed that
    // panda tool can read the pages out of memory at any time.
    // CPU might page to disk some of them and as a result, fails to read them
    // panda tool cannot force CPU to load the pages. It will ruin the replay
    //
    // one solution to this is to also monitor all writes to the target process CR3
    // and put them. Since the exe on disk must be loaded to memory, it MUST be written
    // to memory. This can be stated as "Initialization" state.
    class CloneMemory {
    public:
        bool set_mem(types::addr_t addr, types::size_t size, void * buf) {

            types::addr_t page_id;
            int page_addr;
            uint8_t * ubuf = reinterpret_cast<uint8_t*>(buf);

            for (types::size_t i=0; i<size; ++i) {
                page_id = (addr + i) >> T_PAGE_EXP;
                page_addr = (addr + i) & T_PAGE_MASK;

                this->m_cloned[page_id].page[page_addr] = ubuf[i];
            }

            return true;
        }

        void clear_mem() {
            this->m_cloned.clear();
        }

        void set_written(types::addr_t addr) {
            this->set_state(addr, SimPage::MemState::S_WRITTEN);
        }

        void set_executed(types::addr_t addr) {
            this->set_state(addr, SimPage::MemState::S_EXECUTED);
        }

        bool is_written(types::addr_t addr) {
            return this->get_state(addr) == SimPage::MemState::S_WRITTEN;
        }

        bool is_executed(types::addr_t addr) {
            return this->get_state(addr) == SimPage::MemState::S_EXECUTED;
        }

        bool get_mem(types::addr_t addr, types::size_t size, uint8_t * outbuf) {
            if (outbuf == NULL || size == 0) {
                return false;
            }

            types::addr_t page_id;
            int page_addr;

            for (types::size_t i=0; i<size; ++i) {
                page_id = (addr + i) >> T_PAGE_EXP;
                page_addr = (addr + i) & T_PAGE_MASK;

                if (this->m_cloned.find(page_id) != this->m_cloned.end()) {
                    outbuf[i] = this->m_cloned[page_id].page[page_addr];

                } else {
                    // error!
                    MYERROR("Error accessing cloned mem in page 0x%016lx", page_id);
                    return false;

                }

            }

            return true;
        }

    private:
        std::map<types::addr_t, SimPage> m_cloned;
        typedef std::map<types::addr_t, SimPage>::iterator cloned_it_t;

        SimPage::MemState get_state(types::addr_t addr) {
            return this->m_cloned[addr >> T_PAGE_EXP].state;
        }

        void set_state(types::addr_t addr, SimPage::MemState state) {
            this->m_cloned[addr >> T_PAGE_EXP].state = state;
        }

    };

    ProcessInfo::ProcessInfo(unpacker::dumper::IProcDumper& d, unpacker::pep::IProcParser& p)
    :   m_oep(0),
        m_base_addr(0),
        m_dumper(d),
        m_proc_parser(p) {

        this->init();

    }

    ProcessInfo::~ProcessInfo() {
        for (int i=0; i<ProcessInfo::HEUR_LEN; ++i) {
            delete this->m_heur_list[i];
        }
        //delete this->m_exe;

        delete this->m_mmu;

    }

    void ProcessInfo::init() {

        // initialize the m_heur_list array
        for (int i=0; i<ProcessInfo::HEUR_LEN; ++i) {
            this->m_heur_list[i] = NULL;
        }

        // TODO: possible to just move the heur list initialization outside
        // this class just use them. The memory management is done outside
        // in unpacker_main.cpp

        this->m_heur_list[0] = new unpacker::heuristics::NopHeuristic();
        this->m_mmu = new CloneMemory();
    }

    void ProcessInfo::set_mem_written(
            types::addr_t eip,
            types::addr_t addr,
            types::size_t size,
            void* buf) {

        this->m_mmu->set_mem(addr, size, buf);
        this->m_mmu->set_written(addr);

        //this->m_written_addr[addr] = true;

    }

    bool ProcessInfo::read_cloned_memory(
            types::addr_t addr,
            types::size_t size,
            types::byte_t *out) {

        return this->m_mmu->get_mem(addr, size, out);

    }

    bool ProcessInfo::is_mem_written(types::addr_t addr) {
        //return this->m_written_addr.find(addr) != this->m_written_addr.end();

        return this->m_mmu->is_written(addr);
    }

    void ProcessInfo::clear_mem_written() {
        this->m_mmu->clear_mem();
        //this->m_written_addr.clear();
    }

    void ProcessInfo::dump_proc(types::addr_t oep) {
        MYINFO("dump process with oep=0x%016lx", oep);
        this->m_oep = oep;
        this->m_dumper.dump(*this);
    }

    types::addr_t ProcessInfo::get_current_oep() const {
        return this->m_oep;
    }

    int ProcessInfo::get_pid() {
        return this->m_pid;
    }

    void ProcessInfo::set_pid(int pid) {
        this->m_pid = pid;
    }

    int ProcessInfo::get_ppid() {
        return this->m_ppid;
    }

    void ProcessInfo::set_ppid(int ppid) {
        this->m_ppid = ppid;
    }

    const char * ProcessInfo::get_proc_name() {
        return this->m_proc_name.c_str();
    }

    void ProcessInfo::set_proc_name(const char* proc_name) {
        this->m_proc_name = proc_name;
    }

    types::addr_t ProcessInfo::get_base_addr() const {
        return this->m_base_addr;
    }

    void ProcessInfo::set_base_addr(types::addr_t base_addr) {
        m_base_addr = base_addr;
    }

    /**
     * checks whether oep is in written addr. if not, simply ignore
     * if yes, prepare to dump the process and empty the written addr cache
     * @param oep
     */
    void ProcessInfo::check_eip(types::addr_t oep, void * opaque) {
        if (this->is_mem_written(oep)) {

            // check heuristics
            // read list of heuristics, obtain overall score
            double score = 0.0;
            for (int i=0; i<ProcessInfo::HEUR_LEN; ++i) {
                if (this->m_heur_list[i] != NULL) {
                    score += this->m_heur_list[i]->eval(*this, opaque);
                }
            }

            // TODO: check the threshold
            if (score >= 1.0) {
                // prepare to dump under certain threshold
                // and other things

                // sample
                this->dump_proc(oep);
                this->m_mmu->set_executed(oep);
                //this->clear_mem_written();
            }

        }
    }

    unpacker::module::PEModule& ProcessInfo::get_module() {
        return this->m_exe;
    }

    void ProcessInfo::parse_module(/*types::addr_t base_addr, */void* opaque) {
        this->m_proc_parser.parse(*this, m_base_addr, opaque);
    }



}
