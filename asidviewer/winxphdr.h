/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   winxphdr.h
 * Author: darryl
 *
 * Created on April 27, 2017, 9:52 AM
 */

#ifndef WINXPHDR_H
#define WINXPHDR_H

// GDT
#define KMODE_FS           0x030 // Segment number of FS in kernel mode

// KPCR
#define KPCR_CURTHREAD_OFF 0x124 // _KPCR.PrcbData.CurrentThread

// ETHREAD
#define ETHREAD_EPROC_OFF  0x220 // _ETHREAD.ThreadsProcess

// from EPROCESS
#define EPROC_TYPE_OFF     0x000 // _EPROCESS.Pcb.Header.Type
#define EPROC_SIZE_OFF     0x002 // _EPROCESS.Pcb.Header.Size
#define EPROC_TYPE          0x03 // Value of Type
#define EPROC_SIZE          0x1b // Value of Size
#define EPROC_DTB_OFF      0x018 // _EPROCESS.Pcb.DirectoryTableBase
#define EPROC_PID_OFF      0x084 // _EPROCESS.UniqueProcessId
#define EPROC_LINKS_OFF    0x088 // _EPROCESS.ActiveProcessLinks
#define EPROC_LINKS_FLINK_OFF    EPROC_LINKS_OFF // _EPROCESS.ActiveProcessLinks.Flink
#define EPROC_LINKS_BLINK_OFF    0x08c // _EPROCESS.ActiveProcessLinks.Blink
#define EPROC_PPID_OFF     0x14c // _EPROCESS.InheritedFromUniqueProcessId
#define EPROC_SESSIONLINKS_OFF     0x0b4 // _EPROCESS.SessionProcessLinks
#define EPROC_OBJECTTABLE_OFF      0x0c4 // _EPROCESS.ObjectTable
#define EPROC_VADROOT_OFF      0x11c // _EPROCESS.VadRoot
#define EPROC_NAME_OFF     0x174 // _EPROCESS.ImageFileName
#define EPROC_PEB_OFF      0x1b0 // _EPROCESS.Peb
#define EPROC_ACTIVETHREADS_OFF      0x1a0 // _EPROCESS.ActiveThreads



#endif /* WINXPHDR_H */

