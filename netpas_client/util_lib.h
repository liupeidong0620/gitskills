/*-----------------------------------------------
 * @Description 工具函数头文件
 * @author chejianwen <chejianwen@netpas.cc>
 * @version 
 * @date $Id: util_lib.h 153 2014-03-04 11:08:24Z chejianwen $ 增加文件头
 *-----------------------------------------------*/

#ifndef _NETPAS_UTIL_LIB_H_
#define _NETPAS_UTIL_LIB_H_
#include <time.h>
#include <math.h>

#define  DEBUG       7
#define  INFO        6
#define  NOTICE      5
#define  WARN        4
#define  ERROR       3
#define  ERR         3
#define  CRIT        2
#define  ALERT       1
#define  EMERG       0

struct sockaddr_in;

extern unsigned short g_debuglevel;

void netpas_debug (const char *logfile, const unsigned short level, char *format, ...);
char * netpas_get_date_str();
int file_exists (const char * file);
char * trim_ends (char * buffer);
unsigned long get_peer_ipaddr(struct sockaddr_in *addr);
unsigned short get_peer_port(struct sockaddr_in *addr);
int netpas_pidof(const char * process);
time_t strtime_tosec(char * strtime);
int netpas_pid(const char * pidfile);
unsigned long resolve_ipaddr (const char * string);

#endif /* _NETPAS_UTIL_LIB_H_ */

/* End Of File */
