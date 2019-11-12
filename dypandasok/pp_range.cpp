#include "pp_range.h"

#include <stdint.h>

PPRange::PPRange()
: ppBegin(~0), ppEnd(0) 
{

} 

PPRange::~PPRange()
{
    
}

void PPRange::addAddr(uint64_t addr)
{
    ppEnd = addr > ppEnd ? addr : ppEnd;
    ppBegin = addr < ppBegin ? addr : ppBegin;
}

uint64_t PPRange::getBegin() const
{
    return this->ppBegin;
}

uint64_t PPRange::getEnd() const
{
    return this->ppEnd;
}
