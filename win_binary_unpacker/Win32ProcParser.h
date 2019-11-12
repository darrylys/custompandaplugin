/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   Win32ProcParser.h
 * Author: darryl
 *
 * Created on August 16, 2017, 9:11 AM
 */

#ifndef WIN32PROCPARSER_H
#define WIN32PROCPARSER_H

#include "IProcParser.h"
#include "types.h"

namespace unpacker {
    namespace winpe32 {

        class Win32ProcParser : public unpacker::pep::IProcParser {

        public:
            Win32ProcParser();
            virtual ~Win32ProcParser();

            virtual void parse(ProcessInfo& mod, types::addr_t base_addr, void * opaque = 0);

        private:
            int read_mem(ProcessInfo& mod, types::addr_t src, types::byte_t *out, int size, void * opaque = 0);
            bool is_in_kernel(void * opaque = 0);

            bool m_is_parsed;


        };

    }
}

#endif /* WIN32PROCPARSER_H */

