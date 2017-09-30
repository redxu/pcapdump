/*****************************************************************************
* File Descrip : Log Module
* Create Time  ：20170316
* Author	   ：RedXu
*****************************************************************************/


#ifndef __QQLOG__H__
#define __QQLOG__H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * [记录日志]
 */
void qq_log(const char* filename, const char* format, ...);

void qq_log_buf(const char* filename, const uint8_t* buf, uint32_t sz, char* tips);

#ifdef __cplusplus
}
#endif

#endif

