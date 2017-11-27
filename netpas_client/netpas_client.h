/**@file netpas_client.h
 *@brief 程序主流程头文件
 *@author
 */

#ifndef _NETPAS_CLIENT_H_
#define _NETPAS_CLIENT_H_

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/time.h>
#include <ctype.h>
#include "config.h"
#include "../submodules/netpas_msg_lib/msg_lib.h"
#include "util_lib.h"

#define SEND_RETRY              2       // 每个ip重复发送的次数
#define SEND_TIMEOUT            2

#define USER_PASS_VERIFY        1       // 认证
#define CLIENT_CONNECT          2       // 上线
#define CLIENT_DISCONNECT       3       // 下线

#define NETPAS_AUTH_ZERO        0
#define NETPAS_AUTH_OK          1
#define NETPAS_AUTH_FAILED      2
#define NETPAS_AUTH_ERRUSER     3
#define NETPAS_AUTH_EXPIRE      4
#define NETPAS_AUTH_ERRPASS     5
#define NETPAS_AUTH_DUPUSER     6
#define NETPAS_AUTH_NOACT       7
#define NETPAS_AUTH_FREEZE      8
#define NETPAS_AUTH_NOFREE      9
#define NETPAS_AUTH_SVCWARN     10

#define MAX_SERVER_IP_COUNT     3 // 最大备份ip个数

char g_configfile[MAX_FILENAME_LENGTH] = "/netpas/etc/openvpn/netpas_0_client.conf";
char g_program[MAX_FILENAME_LENGTH] = "";
char g_logfile[] = "/var/log/netpas_client.log";

unsigned short g_opertype = 0;
char g_username[USERNAME_LENGTH] = "";
char g_password[PASSWORD_LENGTH] = "";
char g_localip[IPADDRESS_LENGTH] = "";
char g_untrustedip[IPADDRESS_LENGTH] = "";
unsigned short g_untrustedport = 0;
char g_trustedip[IPADDRESS_LENGTH] = "";
char g_netpasip[IPADDRESS_LENGTH] = "";
unsigned short g_trustedport = 0;
unsigned long long g_inbytes = 0;
unsigned long long g_outbytes = 0;
char g_pipename[MAX_FILENAME_LENGTH] = "";

unsigned long g_srvipaddress[MAX_SERVER_IP_COUNT] = {};
unsigned short g_srvport = UDP_PORT;
char g_loipaddress[IPADDRESS_LENGTH] = "";
char g_clientdir[MAX_FILENAME_LENGTH] = "";
char g_routedir[MAX_FILENAME_LENGTH] = "";
unsigned int g_named_rl = 0;
char g_named_dns[IPADDRESS_LENGTH] = "";
int g_socket = 0;

char g_sendbuf[SEND_BUFFER_SIZE] = "";
unsigned short g_sendlen = 0;
char g_recvbuf[RECV_BUFFER_SIZE] = "";
unsigned short g_recvlen = 0;
auth_reply g_authreply;

unsigned short g_server_ip_count = 0; // 服务端ip个数
struct sockaddr_in g_srvaddr;

/**
 *@brief 读取环境变量
 *@param [in] void
 *@return none
 */
static void read_env ();

/**
 *@brief 获取命令行参数
 *@param [in] int argc 命令行参数个数
 *@param [in] char **argv 命令行参数数组
 *@return none
 */
static void parse_command_line (int argc, char ** argv);

/**
 *@brief 打印程序使用提示
 *@param [in] void
 *@return none
 */
static void netpas_usage ();

/**
 *@brief 读取配置文件
 *@param [in] const char *configfile 配置文件路径
 *@return int 返回1正确，返回-1失败
 */
static void read_config(const char * configfile);

/**
 *@brief 初始化socket接口
 *@param [in] const char *loipaddress 本地地址
 *@return int 返回socket描述符
 */
static int init_socket (const char * loipaddress);

/**
 *@brief 创建消息
 *@param [in] void
 *@return none
 */
static void make_message ();

/**
 *@brief 发送消息
 *@param [in] void
 *@return none
 */
static void netpas_send ();

/**
 *@brief 消息处理
 *@param [in] unsigned short msgcode 消息检查码
 *@return none
 */
static int check_message (unsigned short msgcode);

/**
 *@brief 对收到的消息进行其它处理
 *@param [in] void
 *@return none
 */
static void post_send ();

/**
 *@brief 完成断开连接的最后处理
 *@param [in] void
 *@return none
 */
static void process_disconnect_post();

/**
 *@brief 完成认证过程的最后处理，通知服务认证结果
 *@param [in] void
 *@return none
 */
static void process_auth_post();

/**
 *@brief 解析ip地址
 *@param [in] char *ip 输入特定格式的字符串
 *@return none
 */
static void server_ip_parse (char *ip);

/**
 *@brief 初始化远端发送地址
 *@param [in] void
 *@return none
 */
static void init_srvaddr ();

/**
 *@brief 构建配置文件路径
 *@param [in] char *path 程序运行的路径
 *@return none
 */
void build_config_file (char *path);

#endif /* _NETPAS_CLIENT_H_ */

/* End Of File */
