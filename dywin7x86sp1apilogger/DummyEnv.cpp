/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

#include "IEnv.h"
#include "DummyEnv.h"

//  sample dummy env for testing
// for real, must use Panda!

namespace WinApiLib {

    const uint8_t data[] = {
        0x0a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    DummyEnv::DummyEnv() {

    }

    DummyEnv::~DummyEnv() {

    }

    int DummyEnv::readEnv(uint64_t addr, uint8_t* buf, int len, void* extra) {
        int datalen = sizeof (data) / sizeof (data[0]);
        uint32_t iAddr = (uint32_t) (addr);
        for (int i = 0; i < len; ++i) {
            *(buf + i) = data[(iAddr + i) % (datalen)];
        }

        return IEnv::S_OK;
    }

    int DummyEnv::writeEnv(uint64_t addr, uint8_t* buf, int len, void* extra) {
        // does nothing
        return IEnv::E_ERR;
    }

}