/*-----------------------------------------------
 * @Description 工具函数 c 文件
 * @author chejianwen <chejianwen@netpas.cc>
 * @version 
 * @date $Id: util_lib.c 222 2014-08-12 15:04:11Z chejianwen $ 增加文件头
 *-----------------------------------------------*/

#define _XOPEN_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include "config.h"
#include "util_lib.h"

unsigned short g_debuglevel = DEBUG_LEVEL;

/*--------------------------------------------------*
 * netpas_debug - 打印debug信息
 *--------------------------------------------------*/
void netpas_debug(const char *logfile, const unsigned short level, char *format, ...)
{
	FILE * pf;
	char levelstr[15] = "";
	va_list formatlist;
	unsigned short tofile = 0;
	char * nowtime = netpas_get_date_str();

	if(level > g_debuglevel)
	    return;

	switch(level)
	{
		case EMERG:
			strcpy(levelstr, "[EMERG]: ");
			break;
		case ALERT:
			strcpy(levelstr, "[ALERT]: ");
			break;
		case CRIT:
			strcpy(levelstr, "[CRIT]: ");
			break;
		case ERROR:
			strcpy(levelstr, "[ERROR]: ");
			break;
		case WARN:
			strcpy(levelstr, "[WARNING]: ");
			break;
		case NOTICE:
			strcpy(levelstr, "[NOTICE]: ");
			break;
		case INFO:
			strcpy(levelstr, "[INFO]: ");
			break;
		case DEBUG:
			strcpy(levelstr, "[DEBUG]: ");
			break;
		default:
			return;
    }

    va_start(formatlist, format);

    if(level == EMERG)
    {
        fprintf(stderr, "[%s] %s", nowtime, levelstr);
        vfprintf(stderr, format, formatlist);
        fprintf(stderr, "\n");
    }

    if((logfile != NULL) && (strcasecmp(logfile, "stdout") != 0))
    {
        tofile = 1;
        pf = fopen(logfile, "a");
        if(pf == NULL)
        {
            fprintf(stdout, "ERROR: Failed to open log file %s!\n", logfile);
            tofile = 0;
        }
    }
    if(tofile)
    {
        fprintf(pf, "[%s] %s", nowtime, levelstr);
        vfprintf(pf, format, formatlist);
        fprintf(pf, "\n");
        fclose(pf);
    }
    else if(level == EMERG) ;
    else
    {
        fprintf(stdout, "[%s] %s", nowtime, levelstr);
        vfprintf(stdout, format, formatlist);
        fprintf(stdout, "\n");
    }
	va_end(formatlist);

	return;
}

/*-----------------------------------------------
 * iLanE_getdatestr - 得到当前时间的字符串表示
 * 年-月-日 时:分:秒
  *-----------------------------------------------*/
char * netpas_get_date_str ()
{
    static char nowtime[20] = "";
    time_t now;
    struct tm *ptm;

    time(&now);
    ptm = localtime(&now);
    strftime(nowtime, 20, "%Y-%m-%d %H:%M:%S", ptm);

    return nowtime;
}


/*--------------------------------------------------*
 * file_exists - 检查文件是否存在
 *--------------------------------------------------*/
int file_exists(const char * file)
{
    return(access(file, 0) == 0);
}

/*------------------------------------------------
 *  trim_ends - 删除字符串前后的空格
 *-----------------------------------------------*/
char * trim_ends (char * buffer)
{
	char *start, *end;

	start = buffer;
	//去掉串首的空格
	 while (isspace(*start))
		++start;
	end = strchr(start, '\0');
	//去掉串尾的空格
	while (start < end && isspace(end[-1]))
		--end;
	*end = '\0';
	return start;
}

/*------------------------------------------------
 *  get_peer_ipaddr - 获取对端IP地址
 *-----------------------------------------------*/
unsigned long get_peer_ipaddr(struct sockaddr_in *addr)
{
    return (ntohl(addr->sin_addr.s_addr));
}

unsigned short get_peer_port(struct sockaddr_in *addr)
{
    return (ntohs(addr->sin_port));
}

/*------------------------------------------------
 *  netpas_pidof - 获取进程id号
 *-----------------------------------------------*/
int netpas_pidof(const char * process)
{
    FILE *fp;
    char tmpbuf[MAX_FILENAME_LENGTH];
    int pid;

    sprintf(tmpbuf, "/sbin/pidof %s > /tmp/%s.pid", process, process);
    if(system(tmpbuf)) return (-1);

    sprintf(tmpbuf, "/tmp/%s.pid", process);
    fp = fopen(tmpbuf, "r");
    if(fp == NULL) return (-1);
    fscanf(fp, "%d", &pid);
    fclose(fp);
    return (pid);
}

/*------------------------------------------------
 *  strtime_tosec - 字符串时间转换成秒
 *-----------------------------------------------*/
time_t strtime_tosec(char * strtime) {
    struct tm tc;
    int year, month;

    sscanf(strtime, "%d-%d-%d %d:%d:%d", &year, &month, &tc.tm_mday, &tc.tm_hour, &tc.tm_min, &tc.tm_sec);
    tc.tm_year = year - 1900;
    tc.tm_mon = month - 1;
    tc.tm_isdst = -1;
    return mktime(&tc);
}

/*------------------------------------------------
 *  netpas_pidof - 获取进程id号
 *-----------------------------------------------*/
int netpas_pid(const char * pidfile)
{
    FILE *fp;
    int pid;

    fp = fopen(pidfile, "r");
    if(fp == NULL) return (-1);
    fscanf(fp, "%d", &pid);
    fclose(fp);
    return (pid);
}

/*------------------------------------------------
 *  resolve_ipaddr - 把域名或者IP地址转换为长整型
 *-----------------------------------------------*/
unsigned long resolve_ipaddr (const char * string)
{
    char * lastfield;
    unsigned long ipaddr;
    struct hostent *ph = NULL;

    lastfield = strrchr(string, '.');
    if(isdigit(*string) && isdigit(*lastfield++))
    {
        ipaddr = inet_addr(string);
    }
    else
    {
        ph = gethostbyname(string);
        if(!ph)
        {
            ipaddr = 0;
        }
        if(ph->h_addrtype != AF_INET)
        {
            ipaddr = 0;
        }
        ipaddr = ((struct in_addr *)ph->h_addr_list[0])->s_addr;
    }

    return ipaddr;
}
/* End of file */
