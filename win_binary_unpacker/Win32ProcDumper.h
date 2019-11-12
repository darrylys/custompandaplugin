/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Win32ProcDumper.h
 * Author: darryl
 *
 * Created on August 14, 2017, 4:46 PM
 */

#ifndef WIN32PROCDUMPER_H
#define WIN32PROCDUMPER_H

#include "IProcDumper.h"
#include "proc_info.h"
#include "panda/plugin.h"

namespace panda {
    namespace win {
        namespace dumper {
            
            class Win32ProcDumper : public unpacker::dumper::IProcDumper {
                
            public:
                Win32ProcDumper();
                ~Win32ProcDumper();
                
                void set_env(CPUState * env);
                void dump(unpacker::ProcessInfo& d);
                
            private:
                CPUState * m_env;
                
            };
            
        }
    }
}

#endif /* WIN32PROCDUMPER_H */

