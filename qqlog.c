/*****************************************************************************
* File Descrip : Log Module
* Create Time  ：20170316
* Author	   ：RedXu
*****************************************************************************/


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "qqlog.h"


/**
 * [记录日志]
 */
void qq_log(const char* filename, const char* format, ...) {
  char buf[4096];
  FILE *file = NULL;
  va_list ap;
  
  file = fopen(filename,"ab+");
  if(file == NULL) {
    printf("Can't Create %s!!\n", filename);
    return;
  }
    
  memset(buf,0,sizeof(buf));
  va_start(ap,format);
  vsprintf(buf,format,ap);
  strcat(buf,"\r\n");
  va_end(ap);
  
  fwrite(buf,strlen(buf),1,file);
  
  fflush(file);
  fclose(file); 
}

/**
 * [记录BUF]
 */
void qq_log_buf(const char* filename, const uint8_t* buffer, uint32_t sz, char* tips) {
  char buf[40960];
  FILE *file = NULL;
  int i;
  
  file = fopen(filename,"ab+");
  if(file == NULL) {
    printf("Can't Create %s!!\n", filename);
    return;
  }

  if(tips == NULL)
  	sprintf(buf, "**************** buf size=%d ****************\r\n", sz);
  else
  	sprintf(buf, "**************** buf[%s] size=%d ****************\r\n", tips, sz);
  fwrite(buf,strlen(buf),1,file);

  memset(buf, 0, sizeof(buf));
  for(i = 0; i < sz; i++) {
  	sprintf(buf+strlen(buf), "%02X ", buffer[i]);
  	if((i+1)%16 == 0) {
  		strcat(buf, "\r\n");
  	}
  }
  fwrite(buf,strlen(buf),1,file);
  memset(buf, 0, sizeof(buf));

  strcat(buf,"\r\n****************************************************************\r\n");
  fwrite(buf,strlen(buf),1,file);
  
  fflush(file);
  fclose(file); 
}
