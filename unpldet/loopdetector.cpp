/*
 * Current implementation uses byte-per-byte memory records.
 * This caused a lot of files being generated because many times, the memory
 * writes are not perfectly consecutive.
 * 
 * Solutions:
 * 1. defer dumping until set threshold has been reached, like, 50KB or some shit
 *    problem when dealing with decrypted data that is deleted soon after usage
 * 
 * 
 */

#include "loopdetector.h"

#include <map>
#include <stack>
#include <string>
#include <vector>

#include <sstream>
#include <fstream>

using std::stringstream;
using std::ofstream;

//#define _L_DEBUG

#include <iostream>
#include <iomanip>
using std::cerr;
using std::hex;
using std::dec;
using std::setfill;
using std::setw;
using std::endl;

using std::map;
using std::pair;
using std::stack;
using std::vector;

#include "utility.h"

namespace loopdetector {
    
    namespace types {
        
        typedef pair<ADDRINT, ADDRINT> P_UIUI;
        
    }
    
    class WriteBuf {
    private:
        types::ADDRINT ptr;
        types::ADDRINT size;

    public:
        WriteBuf(types::ADDRINT _ptr, types::ADDRINT _size)
            : ptr(_ptr), size(_size)
        {
        }

        WriteBuf()
            : ptr(0), size(0)
        {
        }

        ~WriteBuf()
        {
        }

        types::ADDRINT getPtr()
        {
            return this->ptr;
        }

        types::ADDRINT getSize()
        {
            return size;
        }

        void setPtr(types::ADDRINT ptr)
        {
            this->ptr = ptr;
        }

        void setSize(types::ADDRINT size)
        {
            this->size = size;
        }
    };
    
    class Edge {
    private:
        types::P_UIUI edge;
        int count;
        int loopNo;

    public:
        Edge()
            : edge(0, 0), count(0), loopNo(-1)
        {
        }

        Edge(types::ADDRINT addrTail, types::ADDRINT addrLeader, int addrCount)
            : edge(addrTail, addrLeader), count(addrCount), loopNo(-1)
        {
        }

        Edge(types::ADDRINT addrTail, types::ADDRINT addrLeader, int addrCount, 
            int _loopNo)
            : edge(addrTail, addrLeader), count(addrCount), loopNo(_loopNo)
        {
        }

        ~Edge()
        {
        }

        void addCount(int count)
        {
            this->count += count;
        }

        void setCount(int count)
        {
            this->count = count;
        }

        int getCount()
        {
            return this->count;
        }

        int getLoopNo()
        {
            return this->loopNo;
        }

        void setLoopNo(int l)
        {
            this->loopNo = l;
        }

        types::P_UIUI getEdge()
        {
            return this->edge;
        }
    };
    
    class Loop {
    private:
        map<types::ADDRINT, WriteBuf> writeZone;
        map<types::ADDRINT, WriteBuf> readZone; // TODO

        typedef map<types::ADDRINT, WriteBuf>::iterator bufZoneIter;
        
        types::ADDRINT minAddr;
        types::ADDRINT maxAddr;
        
    public:
        Loop()
        : minAddr(0xFFFFFFFF), maxAddr(0)
        {
        }

        ~Loop()
        {
        }

        map<types::ADDRINT, WriteBuf>& getWriteZones()
        {
            return this->writeZone;
        }

        bool getWriteBuf(types::ADDRINT ptr, WriteBuf& out)
        {
            bufZoneIter it = this->writeZone.find(ptr);
            if (it == this->writeZone.end())
            {
                return false;
            }
            else
            {
                out = it->second;
                return true;
            }
        }

        void putWriteBuf(types::ADDRINT ptr, WriteBuf& in)
        {
            this->writeZone[ptr] = in;
        }
        
        /**
         * Adds the address of the instructions in the loop.
         * @param addr
         */
        void addLoopAddr(types::ADDRINT addr) {
            if (addr < this->minAddr) {
                this->minAddr = addr;
            }
            
            if (addr > this->maxAddr) {
                this->maxAddr = addr;
            }
        }
        
        /**
         * 
         * @return pair of (min, max)
         * default is (0xFFFFFFFF, 0x00000000)
         */
        types::P_UIUI getMinMaxInsAddr() {
           return types::P_UIUI(this->minAddr, this->maxAddr);
        }
    };
    
    class Globals
    {
    private:
        map< types::P_UIUI, Edge > countMap;
        typedef map< pair<types::ADDRINT, types::ADDRINT>, Edge >::iterator countMapIter;

        map< types::P_UIUI, int > loopInsSet;
        typedef map< types::P_UIUI, int >::iterator loopInsSetIter;
        
        map< types::P_UIUI, map<types::ADDRINT, WriteBuf> > memWrites;
        typedef map< types::P_UIUI, map<types::ADDRINT, WriteBuf> >::iterator memWritesIter;

        stack< types::ADDRINT > insStack4loop;

        map< int, Loop > loopZoneMap;
        typedef map< int, Loop >::iterator loopZoneMapIter;

        //Loop loopZone;
        types::ADDRINT currInsAddr;
        //bool inLoop;
        int currLoopNo;
        int runningLoopNo;
        int loopDumpNo;
        //std::ofstream * pOut;
        
        FILE * pFileOut;
        
        EnvironmentAccessor * m_env;
        utility::Disassembler m_disasm;
        
        // returns a pointer to loop. Don't delete it
        Loop * getLoop()
        {
            if (this->runningLoopNo > 0)
            {
                loopZoneMapIter it = loopZoneMap.find(runningLoopNo);
                //Loop *loop = NULL;

                if (it == loopZoneMap.end())
                {
                    std::pair<loopZoneMapIter, bool> insRet;
                    insRet = loopZoneMap.insert(std::make_pair(this->runningLoopNo, Loop()));
                    return &(insRet.first->second);
                    //
                    //loopZoneMap[runningLoopNo] = Loop();
                    //return &(loopZoneMap[runningLoopNo]);
                }
                else
                {
                    return &(it->second);
                }

                //return loop;
            }
            return NULL;
        }

        void dumpBuffer(types::ADDRINT begin, types::ADDRINT end) {
            
            vector<char> vbuf(end-begin);
            
            int bytes_read = this->m_env->read_mem(begin, (types::BYTE*)&vbuf[0], end-begin);
            
            if (bytes_read > 0) {
                
                // check for entropy / chisquare / printable strings would be interesting!
                // dump the buffer to file
                
                stringstream ss;
                
                if (bytes_read >= 256) {
                    ss.str("");
                    ss <<
                        "[LOOP-DUMP " << setfill('0') << setw(10) << dec << (this->loopDumpNo++) << "]" <<
                        "[WRITE-ADDR 0x" << hex << setfill('0') << setw(8) << begin << "-" <<
                        "0x" << hex << setfill('0') << setw(8) << (end-1) << "]" << 
                        "[# " << dec << this->runningLoopNo << "]";
                    
                    double ent = utility::entropy((uint8_t*)&vbuf[0], vbuf.size());
                    if (ent >= 0) {
                        ss << "[ENTROPY " << dec << ent << "]";
                    }
                    
                    double chisq = utility::chisquare((uint8_t*)&vbuf[0], vbuf.size());
                    if (chisq >= 0) {
                        ss << "[X2 " << dec << chisq << "]";
                    }
                    
                    ss << endl;
                    
                    fprintf(this->pFileOut, "%s", ss.str().c_str());
                
                    //pOut->write(ss.str().c_str(), ss.str().length());
                    //ofstream out(ss.str().c_str(), ofstream::out | ofstream::binary);
                    ::fwrite(&vbuf[0], sizeof(char), vbuf.size(), this->pFileOut);
                    //pOut->write(&vbuf[0], vbuf.size());

                    int disasm_size = 128;
                    this->m_disasm.disasm(this->pFileOut, &vbuf[0], disasm_size, begin);

                    //ss.str("");
                    //ss << endl << endl;

                    //pOut->write(ss.str().c_str(), ss.str().length());
                    fprintf(this->pFileOut, "\n\n");
                }
                
            } else {
#ifdef _L_DEBUG
                // paged out!!
#endif
                // do something here log it or some kind.
            }
            //delete [] buf;
        }

    public:
        Globals(EnvironmentAccessor * env)
        : currInsAddr(0), 
        //inLoop(false), 
        currLoopNo(1), 
        runningLoopNo(0),
        loopDumpNo(0),
        m_env(env),
        m_disasm()
        {
            //pOut = new ofstream("LOOPDump.bin", ofstream::out | ofstream::app | ofstream::binary);
            this->pFileOut = fopen("LOOPDump.bin", "ab");
            this->m_disasm.init();
        }

        ~Globals()
        {
            //pOut->close();
            //delete pOut;
            if (this->pFileOut) {
                fclose(this->pFileOut);
            }
        }


        void addWritesToLoop(types::ADDRINT prevIP, types::ADDRINT currIP)
        {

#ifdef _L_DEBUG
            cerr << "[DEBUG] ::addWritesToLoop("
                << hex << setw(8) << setfill('0') << prevIP << " --> "
                << hex << setw(8) << setfill('0') << currIP << ")" << endl;
#endif
            Loop * loop = this->getLoop();
            if (loop == NULL)
            {
                return;
            }

            // this loop is empty!
            map<types::ADDRINT, WriteBuf>& memRecord = this->getMemWriteRecords(prevIP, currIP);
            for (map< types::ADDRINT, WriteBuf >::iterator it = memRecord.begin();
                it != memRecord.end();
                ++it)
            {

#ifdef _L_DEBUG
                cerr << "[DEBUG] iterator::pair (ADDRINT="
                    << hex << setw(8) << setfill('0') << it->first << ", MemWritePtr="
                    << hex << setw(8) << setfill('0') << it->second.getPtr() << ", MemWriteSize="
                    << dec << it->second.getSize() << " (0x" << hex << it->second.getSize() << "))" << endl;
#endif
                
                loop->addLoopAddr(currIP);
                
                //loopZone.putWriteBuf(it->first, it->second);
                loop->putWriteBuf(it->first, it->second);
            }
            
            memRecord.clear();
            this->removeMemWriteRecord(prevIP, currIP);
        }

        void addWriteBufToLoop(types::ADDRINT ptr, WriteBuf& in)
        {
            Loop * loopZone = getLoop();
            if (loopZone)
            {
                loopZone->putWriteBuf(ptr, in);
            }
        }

        //map<ADDRINT, WriteBuf>& getMemWritesInLoop()
        //{
        //    return loopZone.getWriteZones();
        //}

        bool getMemWriteBufInLoop(types::ADDRINT ptr, loopdetector::WriteBuf& out)
        {
            Loop * loopZone = getLoop();
            if (loopZone)
            {
                return loopZone->getWriteBuf(ptr, out);
            }
            return false;
        }

        void dumpLoop()
        {
            // open file, dump the loop contents
            // not worked for now
#ifdef _L_DEBUG
            cerr << "[DEBUG] DUMP LOOP CONTENTS" << endl;
#endif

            //ADDRINT min = 0xFFFFFFFF;
            //ADDRINT max = 0;
            Loop * loopZone = getLoop();
            if (loopZone == NULL)
            {
#ifdef _L_DEBUG
                cerr << "[WARNING] DUMP LOOP FAILED, LOOP-" << this->runningLoopNo << " DOES NOT EXIST!" << endl;
#endif
                return;
            }

            types::ADDRINT begin = 0;
            types::ADDRINT end = 0;
            bool ready = false;
            
            for (map<types::ADDRINT, WriteBuf>::iterator it = loopZone->getWriteZones().begin();
                it != loopZone->getWriteZones().end();
                ++it)
            {

                if (ready)
                {
                    // glue forward if the difference is less than 32 bytes (arbitrary)
                    // might change this to page-granularity instead!
                    if (end + 32 < it->second.getPtr()) 
                    {
                        if (end > begin)
                        {
                            dumpBuffer(begin, end);
                        }

                        if (it->second.getPtr() >= 8) {
                            begin = it->second.getPtr() - 8;
                        } else {
                            begin = 0;
                        }
                        end = begin + it->second.getSize();
                    }
                    else
                    {
                        end = it->second.getPtr() + it->second.getSize();
                    }
                }
                else
                {
                    // take last 8 bytes for more coverage
                    if (it->second.getPtr() >= 8) {
                        begin = it->second.getPtr() - 8;
                    } else {
                        begin = 0;
                    }
                    end = it->second.getPtr() + it->second.getSize();
                    
                    ready = true;
                }

#ifdef _L_DEBUG
                cerr << "[DEBUG] Write to " <<
                    hex << setfill('0') << setw(8) << it->second.getPtr() <<
                    " size=" << dec << it->second.getSize() << 
                    " (0x" << hex << it->second.getSize() << ")" << endl;
#endif

                //if (min > it->second.getPtr())
                //{
                //    min = it->second.getPtr();
                //}
                //
                //if (max < it->second.getPtr())
                //{
                //    max = it->second.getPtr();
                //}
            }

            if (end > begin)
            {
                dumpBuffer(begin, end);
            }

            //if (min < max)
            //{
            //    cerr << "[DEBUG] LOOP WRITE ZONE in [" << 
            //        hex << setfill('0') << setw(8) << min << " , " <<
            //        hex << setfill('0') << setw(8) << max << "]" << endl;
            //
            //    char * buffer = new char[max - min + 2];
            //    size_t nread = PIN_SafeCopy(buffer, reinterpret_cast<VOID*>(min), (max-min+1));
            //
            //    for (unsigned i=0; i<nread; ++i)
            //    {
            //        if (i%40)
            //        {
            //            cerr << " " << hex << setfill('0') << setw(2) << (int)(buffer[i] & 0xFF);
            //        }
            //        else
            //        {
            //            cerr << endl;
            //            cerr << "\t" << hex << setfill('0') << setw(2) << (int)(buffer[i] & 0xFF);
            //        }
            //    }
            //
            //    cerr << endl << endl;
            //
            //    delete [] buffer;
            //}

            this->clearLoop();
        }

        void clearLoop()
        {
            Loop * loopZone = getLoop();
            if (loopZone)
            {
                loopZone->getWriteZones().clear();
            }
        }

        map<types::ADDRINT, WriteBuf>& getMemWriteRecords(types::ADDRINT prevIP, types::ADDRINT currIP)
        {
            types::P_UIUI key = types::P_UIUI(prevIP, currIP);
            memWritesIter it = this->memWrites.find(key);
            if (it == this->memWrites.end())
            {
                std::pair<memWritesIter, bool> insRet;
                insRet = this->memWrites.insert(std::make_pair(key, map<types::ADDRINT, WriteBuf>()));
                return insRet.first->second;
                //
                //this->memWrites[key] = map<ADDRINT, WriteBuf>();
                //return this->memWrites[key];
            }
            else
            {
                return it->second;
            }
        }


        void removeMemWriteRecord(types::ADDRINT prevIP, types::ADDRINT currIP)
        {
            this->memWrites.erase(types::P_UIUI(prevIP, currIP));
        }

        int getLoopNo()
        {
            return this->currLoopNo;
        }

        void incLoopNo()
        {
            this->currLoopNo++;
        }

        types::ADDRINT getCurrInsAddr()
        {
            return this->currInsAddr;
        }

        void setCurrInsAddr(types::ADDRINT ip)
        {
            this->currInsAddr = ip;
        }


        
        //bool isInLoop()
        //{
        //    return this->inLoop;
        //}
        //
        //void setInLoop(bool inLoop)
        //{
        //    this->inLoop = inLoop;
        //}


        int getRunningLoopNo()
        {
            return this->runningLoopNo;
        }

        void setRunningLoopNo(int loopNo)
        {
            this->runningLoopNo = loopNo;
        }


        //void addLoopIns(ADDRINT prev, ADDRINT curr)
        //{
        //    types::P_UIUI key = types::P_UIUI(prev, curr);
        //    if (this->loopInsSet.find(key) == this->loopInsSet.end())
        //    {
        //        this->loopInsSet[key] = 1;
        //    }
        //    else
        //    {
        //        this->loopInsSet[key] += 1;
        //    }
        //}
        //
        //void clearLoopIns()
        //{
        //    this->loopInsSet.clear();
        //}
        //
        //int inLoopIns(ADDRINT prev, ADDRINT curr)
        //{
        //    types::P_UIUI key = types::P_UIUI(prev, curr);
        //    loopInsSetIter it = this->loopInsSet.find(key);
        //    if (it == this->loopInsSet.end())
        //    {
        //        return 0;
        //    }
        //    else
        //    {
        //        return it->second;
        //    }
        //}
        //
        //void clearLoopCountsMatchesLoopIns()
        //{
        //    for (loopInsSetIter it = this->loopInsSet.begin(); it != this->loopInsSet.end(); ++it)
        //    {
        //        removeEdge(it->first.first, it->first.second);
        //    }
        //    this->loopInsSet.clear();
        //}


        void pushStack(types::ADDRINT addr)
        {
            this->insStack4loop.push(addr);
        }

        types::ADDRINT popStack()
        {
            if (this->insStack4loop.empty())
            {
                return 0;
            }

            types::ADDRINT top = this->insStack4loop.top();
            this->insStack4loop.pop();
            return top;
        }

        void clearStack()
        {
            while (!this->insStack4loop.empty())
            {
                this->insStack4loop.pop();
            }
        }


        // this works because the Edge out param is only used as READ by the main app!
        // if one tries to modify the edge, it fails!
        bool checkEdge(types::ADDRINT prev, types::ADDRINT curr, Edge& out)
        {
            types::P_UIUI key = types::P_UIUI(prev, curr);
            countMapIter it = this->countMap.find(key);

            if (it == this->countMap.end())
            {
                return false;
            }
            else
            {
                // This duplicates it->second and put its contents in out.
                // whatever done to out, it->second is not affected.
                out = it->second;
                return true;
            }
        }

        void setEdgeLoopNo(types::ADDRINT prev, types::ADDRINT curr, int loopNo)
        {
            types::P_UIUI key = types::P_UIUI(prev, curr);
            countMapIter it = this->countMap.find(key);

            if (it == this->countMap.end())
            {
                //std::pair<countMapIter, bool> insRet = 
                countMap.insert(std::make_pair(key, Edge(prev, curr, 1, loopNo)));
                //this->countMap[key] = Edge(prev, curr, 1, loopNo);
#ifdef _L_DEBUG
                cerr << "[WARNING] edge(" << hex 
                    << setw(8) << setfill('0') << prev << " --> " 
                    << setw(8) << setfill('0') << curr << ") NOT FOUND!" << endl;
#endif
            }
            else
            {
                it->second.setLoopNo(loopNo);
            }
        }

        void addEdge(types::ADDRINT prev, types::ADDRINT curr, int count = 1)
        {
            types::P_UIUI key = types::P_UIUI(prev, curr);
            countMapIter it = this->countMap.find(key);

            if (it == this->countMap.end())
            {
                //std::pair<countMapIter, bool> insRet = 
                countMap.insert(std::make_pair(key, Edge(prev, curr, count)));
                //this->countMap[key] = Edge(prev, curr, count);
            }
            else
            {
                it->second.addCount(count);
            }

        }

        void removeEdge(types::ADDRINT prev, types::ADDRINT curr)
        {
            types::P_UIUI key = types::P_UIUI(prev, curr);
            countMapIter it = this->countMap.find(key);

            if (it != this->countMap.end())
            {
                this->countMap.erase(it);
            }
        }

    };
    
    class LoopDetectorImpl {
    private:
        Globals * g_info;
        
    public:
        LoopDetectorImpl(EnvironmentAccessor * env) 
        {
            printf("LoopDetectorImpl(%p)\n", env);
            this->g_info = new Globals(env);
        }
        
        ~LoopDetectorImpl() {
            delete this->g_info;
        }
        
        void before_ins_exec(types::ADDRINT pc, const char * disasm) {
            types::ADDRINT ip = pc; //PIN_GetContextReg(ctx, REG_EIP);

            if (g_info->getCurrInsAddr())
            {
                types::ADDRINT prevIP = g_info->getCurrInsAddr();
                types::ADDRINT currIP = ip;
                
                Edge edge;
                if (g_info->checkEdge(prevIP, currIP, edge) && edge.getCount() > 0)
                {
                    if (edge.getCount() >= 2)
                    {
                        if (edge.getCount() == 2 && edge.getLoopNo() <= 0)
                        {
                            if (g_info->getRunningLoopNo() != 0)
                            {
                                // end previous loop.
                                // dump
#ifdef DEBUG
                                cerr << "[INFO] End loop code " << g_info->getRunningLoopNo() << endl;
#endif
                                g_info->setRunningLoopNo(edge.getLoopNo());
                            }

#ifdef DEBUG
                            cerr << "[INFO] New Loop detected with edge(" << hex 
                                << setw(8) << setfill('0') << prevIP << " --> "
                                << setw(8) << setfill('0') << currIP << ")" << endl;
#endif
                            // new loop
                            // loop for stack
                            // add the edges
                            // set the edge loop number
                            types::ADDRINT topIP = g_info->popStack();
                            types::ADDRINT loopBase = topIP;
                            types::ADDRINT nextIns = topIP;
                            types::ADDRINT loopBottom = 0;

                            g_info->setRunningLoopNo(g_info->getLoopNo());

#ifdef DEBUG
                            cerr << "[INFO] set Edge("
                                    << hex << setw(8) << setfill('0') << prevIP << " --> "
                                    << hex << setw(8) << setfill('0') << currIP << ", loopNo="
                                    << dec << g_info->getLoopNo() << ")" << endl;
#endif

                            g_info->setEdgeLoopNo(prevIP, currIP, g_info->getLoopNo());
                            
                            g_info->addWritesToLoop(prevIP, currIP);

#ifdef DEBUG
                            cerr << "[INFO] [START STACK] topIP=" << hex << setw(8) << setfill('0') << topIP << endl;
#endif

                            while ((topIP = g_info->popStack()) && topIP != loopBase)
                            {
                                if (loopBottom == 0)
                                {
                                    loopBottom = topIP;
                                }

#ifdef DEBUG
                                cerr << "[INFO] set Edge("
                                    << hex << setw(8) << setfill('0') << topIP << " --> "
                                    << hex << setw(8) << setfill('0') << nextIns << ", loopNo="
                                    << dec << g_info->getLoopNo() << ")" << endl;
#endif

                                g_info->setEdgeLoopNo(topIP, nextIns, g_info->getLoopNo());
                                g_info->addWritesToLoop(topIP, nextIns);

                                nextIns = topIP;
                            }

                            g_info->pushStack(loopBase);
                            g_info->pushStack(loopBottom);

#ifdef DEBUG
                            cerr << "[INFO] [END STACK] topIP=" << hex << setw(8) << setfill('0') << topIP << endl;
#endif
                            g_info->incLoopNo();
#ifdef DEBUG
                            if (!topIP)
                            {
                                cerr << "[ERROR] topIP is NULL!" << endl;
                            }
#endif
                            // first time end, next must not come here again!
                        }
                        else
                        {
                            // existing loop
                            if (g_info->getRunningLoopNo() == 0)
                            {
#ifdef DEBUG
                                cerr << "[INFO] setRunningLoop(" << edge.getLoopNo() << ")" << endl;
#endif
                                g_info->setRunningLoopNo(edge.getLoopNo());
                            }

                            // check the loopNo from edge code
                            if (edge.getLoopNo() != g_info->getRunningLoopNo())
                            {
                                // no need to check edge.getLoopNo() == -1
                                // to reach this block, the following cases are considered.
                                // edge.getLoopNo() > 0 && edge.getCount() == 2. This is the case we handle
                                // edge.getLoopNo() <= 0 && edge.getCount() > 2. This is impossible. When the edge.count == 2, the loop num is assigned
                                // edge.getLoopNo() > 0 && edge.getCount() > 2. Same as first case.
                                if (edge.getLoopNo() > g_info->getRunningLoopNo())
                                {
                                    // the parent loop.
                                    // dump this
                                    // if there exists loop before and monitors its write instructions, dump the buffers here...
                                
                                    g_info->dumpLoop();
#ifdef DEBUG
                                    cerr << "[INFO] [DUMP BUFFERS]" << endl;
#endif
                                }

                                g_info->setRunningLoopNo(edge.getLoopNo());
                                // break loop
#ifdef DEBUG
                                cerr << "[INFO] " 
                                    << "[END LOOP] [" << hex << setw(8) << setfill('0') << currIP << "] "
                                    << "[" << *disasm << "]" << endl;
#endif
                            }
                            else
                            {
#ifdef DEBUG
                                cerr << "[INFO] " 
                                    << "[IN LOOP] [" << hex << setw(8) << setfill('0') << currIP << "] "
                                    << "[" << *disasm << "]" << endl;
#endif
                                // still in loop.
                            }

                        }
                        // loop detect
                    }
                    else if (edge.getCount() == 1)
                    {
                        // don't add to stack
#ifdef DEBUG
                        cerr << "[INFO] edge("
                            << hex << setw(8) << setfill('0') << prevIP << " --> "
                            << hex << setw(8) << setfill('0') << currIP << ") COUNT=1"
                            << endl;
#endif

                        // if there exists loop before and monitors its write instructions, dump the buffers here...
                        // ...
                        if (g_info->getRunningLoopNo())
                        {
#ifdef DEBUG
                            cerr << "[INFO] [END-LOOP] End Loop " << g_info->getRunningLoopNo() << endl;
#endif
                            g_info->dumpLoop();
                            g_info->setRunningLoopNo(0);

#ifdef DEBUG
                            cerr << "[INFO] [DUMP BUFFERS]" << endl;
#endif
                        }
                    }
                }
                else
                {
#ifdef DEBUG
                    cerr << "[INFO] New Edge(" << hex 
                        << setw(8) << setfill('0') << prevIP << " --> "
                        << setw(8) << setfill('0') << currIP << ")" << endl;
#endif
                    // add to stack
                    g_info->pushStack(currIP);

                    // if there exists loop before and monitors its write instructions, dump the buffers here...
                    // ...
                    if (g_info->getRunningLoopNo())
                    {
#ifdef DEBUG
                        cerr << "[INFO] [END-LOOP] End Loop " << g_info->getRunningLoopNo() << endl;
#endif
                        g_info->dumpLoop();
                        g_info->setRunningLoopNo(0);
#ifdef DEBUG
                        cerr << "[INFO] [DUMP BUFFERS]" << endl;
#endif
                    }
                }

                g_info->addEdge(prevIP, currIP);
            }
            else
            {
                g_info->pushStack(ip);
            }
            g_info->setCurrInsAddr(ip);
        }
        
        void before_virt_mem_write(
                types::ADDRINT pc, types::ADDRINT write_addr, 
                void * write_buf, types::SIZE_T write_size) {
            
            types::ADDRINT ip = pc;

            if (g_info->getRunningLoopNo())
            {
                WriteBuf wb(write_addr, write_size);
                g_info->addWriteBufToLoop(write_addr, wb);
            }
            else if (g_info->getCurrInsAddr())
            {
                types::ADDRINT prevIP = g_info->getCurrInsAddr();
                types::ADDRINT currIP = ip;

#ifdef _L_DEBUG
                cerr << "[DEBUG] ::pre_recordMemWrite("
                    << setw(8) << setfill('0') << prevIP << " --> "
                    << setw(8) << setfill('0') << currIP << ")" << endl;
#endif

                map<types::ADDRINT, WriteBuf>& writes = g_info->getMemWriteRecords(prevIP, currIP);
                writes[write_addr] = WriteBuf(write_addr, write_size);
            }
            // ignore this
        }
    };
    
    
    EnvironmentAccessor::EnvironmentAccessor() {
        // does nothing
    }
    
    EnvironmentAccessor::~EnvironmentAccessor() {
        // does nothing
    }
    
    int EnvironmentAccessor::read_mem(types::ADDRINT src, types::BYTE* out, int size) {
        return this->impl_read_mem(src, out, size);
    }
    
    void EnvironmentAccessor::debug_print(const char* str) {
        this->impl_debug_print(str);
    }
    
    void EnvironmentAccessor::impl_debug_print(const char* str) {
        // does nothing
    }
    

    LoopDetector::LoopDetector(EnvironmentAccessor* env) 
    : m_env(env)
    {
        this->m_impl = new LoopDetectorImpl(env);
    }
    /*
    void before_ins_exec(types::ADDRINT pc, const char * disasm) {
            m_impl->before_ins_exec(pc, disasm);
        }
        
        void before_virt_mem_write(types::ADDRINT pc, types::ADDRINT write_addr, types::SIZE_T write_size) {
            m_impl->before_virt_mem_write(pc, write_addr, write_size);
        }
    */
    
    void LoopDetector::before_ins_exec(types::ADDRINT pc, const char* disasm) {
        this->m_impl->before_ins_exec(pc, disasm);
    }
    
    void LoopDetector::before_virt_mem_write(types::ADDRINT pc, 
            types::ADDRINT write_addr, void * write_buf, types::SIZE_T write_size) {
        
        this->m_impl->before_virt_mem_write(pc, write_addr, write_buf, write_size);
    }
    
    LoopDetector::~LoopDetector() {
        delete this->m_impl;
    }
    
}

