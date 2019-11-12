#ifndef PP_RANGE_H
#define PP_RANGE_H

#include <stdint.h>

class PPRange {
public:

    PPRange();
    ~PPRange();

    void addAddr(uint64_t addr);
    uint64_t getBegin() const;
    uint64_t getEnd() const;

private:
    uint64_t ppBegin;
    uint64_t ppEnd;

};

#endif