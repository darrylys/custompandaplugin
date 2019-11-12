/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "Win32ProcDumper.h"

namespace panda {
    namespace win {
        namespace dumper {

            Win32ProcDumper::Win32ProcDumper() {

            }

            Win32ProcDumper::~Win32ProcDumper() {

            }

            void Win32ProcDumper::set_env(CPUState* env) {
                this->m_env = env;
            }

            void Win32ProcDumper::dump(unpacker::ProcessInfo& d) {

                // TODO: implement dumper routine

                // recreate PE file

                // append dynamic codes to new sections

                // reconstruct iat

                // uses Config::getEnvDumper() to dump the memory to disk

            }

        }
    }
}
