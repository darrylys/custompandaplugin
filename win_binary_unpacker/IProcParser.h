/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * File:   IProcParser.h
 * Author: darryl
 *
 * Interface to read PE Header in memory
 *
 * Created on August 16, 2017, 9:06 AM
 */

#ifndef IPROCPARSER_H
#define IPROCPARSER_H

#include "pe_module.h"
#include "types.h"

namespace unpacker {

    class ProcessInfo;

    namespace pep {

        class IProcParser {

        public:
            IProcParser() { }
            virtual ~IProcParser() { }

            /**
             * Parses the information from memory and insert to PEModule
             * @param mod
             * @param base_addr
             * @param opaque
             */
            virtual void parse(ProcessInfo& mod,
                types::addr_t base_addr, void * opaque = 0) = 0;

        };

    }
}

#include "proc_info.h"

#endif /* IPROCPARSER_H */

