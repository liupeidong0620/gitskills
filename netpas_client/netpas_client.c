/**@file netpas_client.c
 *@brief 在openvpn中和用户建立连接和断开时跟认证程序通讯用
 *@author
 */

#include "netpas_client.h"

int main(int argc, char **argv)
{
#ifdef _DEBUG_
    g_debuglevel = DEBUG;
    netpas_debug(g_logfile, DEBUG, "Begin");
#endif
    strncpy(g_program, argv[0], sizeof(g_program) - 1);
    /* 构建配置文件路径 */
    build_config_file(argv[0]);
    read_env();

    /*解析命令行参数*/
    parse_command_line (argc, argv);

    /* 读取配置文件 */
    read_config(g_configfile);

    /* 创建socket端口 */
    g_socket = init_socket (g_loipaddress);
    /* 初始化远端地址 */
    init_srvaddr();

    make_message();

    netpas_send();

    post_send();

    exit(0);
}

/**
 *@brief 构建配置文件路径
 *@param [in] char *path 程序运行的路径
 *@return none
 */
void build_config_file (char *path)
{
    char *path_tmp = NULL;
    char *config_tmp = NULL;
    char tmpbuf[MAX_FILENAME_LENGTH] = "";

    bzero(tmpbuf, sizeof(tmpbuf));
    path_tmp = strrchr(path, '/');
    config_tmp = strrchr(g_configfile, '/');
    *(config_tmp + 1) = '\0';
    sprintf(tmpbuf, "%s%s%s", g_configfile, (path_tmp + 1), ".conf");
    strncpy(g_configfile, tmpbuf, MAX_FILENAME_LENGTH);
}

/**
 *@brief 读取环境变量
 *@param [in] void
 *@return none
 */
static void read_env()
{
    char *rev;

#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter read_env()");
#endif

    rev = getenv("script_type");
    if(!rev)
        netpas_usage();
    else if(strcmp(rev, "user-pass-verify") == 0)
        g_opertype = USER_PASS_VERIFY;
    else if(strcmp(rev, "client-connect") == 0)
        g_opertype = CLIENT_CONNECT;
    else if(strcmp(rev, "client-disconnect") == 0)
        g_opertype = CLIENT_DISCONNECT;
    else
        netpas_usage();
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "script_type: %s", rev);
#endif
    rev = getenv("username");
    if(!rev)
        netpas_usage();
    else
        strncpy(g_username, rev, sizeof(g_username) - 1);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "username: %s", g_username);
#endif
    rev = getenv("password");
    if(!rev && g_opertype == USER_PASS_VERIFY)
        netpas_usage();
    else if(rev)
        strncpy(g_password, rev, sizeof(g_password) - 1);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "password: %s", g_password);
#endif
    rev = getenv("untrusted_ip");
    if(!rev && g_opertype == USER_PASS_VERIFY)
        netpas_usage();
    else if(rev)
        strncpy(g_untrustedip, rev, sizeof(g_untrustedip) - 1);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "untrusted_ip: %s", g_untrustedip);
#endif
    rev = getenv("untrusted_port");
    if(!rev && g_opertype == USER_PASS_VERIFY)
        netpas_usage();
    else if(rev)
        sscanf(rev, "%hu", &g_untrustedport);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "untrusted_port: %hu", g_untrustedport);
#endif
    rev = getenv("trusted_ip");
    if(!rev && g_opertype != USER_PASS_VERIFY)
        netpas_usage();
    else if(rev)
        strncpy(g_trustedip, rev, sizeof(g_trustedip) - 1);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "trusted_ip: %s", g_trustedip);
#endif
    rev = getenv("local");
    if(!rev && g_opertype == CLIENT_CONNECT)
        netpas_usage();
    else if(rev)
        strncpy(g_localip, rev, sizeof(g_localip) - 1);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "local: %s", g_localip);
#endif
    rev = getenv("ifconfig_pool_remote_ip");
    if(!rev && g_opertype == CLIENT_CONNECT)
        netpas_usage();
    else if(rev)
        strncpy(g_netpasip, rev, sizeof(g_netpasip) - 1);

    rev = getenv("trusted_port");
    if(!rev && g_opertype != USER_PASS_VERIFY)
        netpas_usage();
    else if(rev)
        sscanf(rev, "%hu", &g_trustedport);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "trusted_port: %hu", g_trustedport);
#endif
    rev = getenv("bytes_received");
    if(!rev && g_opertype == CLIENT_DISCONNECT)
        netpas_usage();
    else if(rev)
        sscanf(rev, "%llu", &g_outbytes);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "bytes_received: %llu", g_outbytes);
#endif
    rev = getenv("bytes_sent");
    if(!rev && g_opertype == CLIENT_DISCONNECT)
        netpas_usage();
    else if(rev)
        sscanf(rev, "%llu", &g_inbytes);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "bytes_sent: %llu", g_inbytes);
#endif
}

/**
 *@brief 获取命令行参数
 *@param [in] int argc 命令行参数个数
 *@param [in] char **argv 命令行参数数组
 *@return none
 */
static void parse_command_line (int argc, char ** argv)
{
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter parse_command_line()");
#endif

    if(argc > 2)
        netpas_usage();
    if(g_opertype == USER_PASS_VERIFY)
    {
        if(argc < 2)
            netpas_usage();
        else
        {
            strncpy(g_pipename, argv[1], sizeof(g_pipename) - 1);
        }
        if(access(g_pipename, W_OK) < 0)
        {
            fprintf(stdout, "Error: Can not write to file %s\n", g_pipename);
            exit(-1);
        }
    }
}

/**
 *@brief 打印程序使用提示
 *@param [in] void
 *@return none
 */
void netpas_usage ()
{
    fprintf(stdout, "Build at %s %s\n", __DATE__, __TIME__);
    fprintf(stdout, "This program can not be used this way.\n");
    fprintf(stdout, "Must be used with other daemon program.\n");
    fprintf(stdout, "Some environment variables must be set.\n");
    fprintf(stdout, "Config file: %s\n", g_configfile);
    fprintf(stdout, "server=<server IP>\n");
    fprintf(stdout, "port=<server PORT>\n");
    fprintf(stdout, "clientdir=<client config directory>\n");
    fprintf(stdout, "routedir=<route file directory>\n");
    fprintf(stdout, "named_rl=<named route list>\n");
    fprintf(stdout, "named_dns=<named dns server ip>\n");

    fprintf(stdout, "\nUsage: %s <filename>\n", g_program);
    exit(-1);
}

/**
 *@brief 读取配置文件
 *@param [in] const char *configfile 配置文件路径
 *@return int 返回1正确，返回-1失败
 */
static void read_config (const char * configfile)
{
    FILE * pf;
    char line[MAX_FILELINE_LENGTH];
    char * var, *val;
    unsigned short num = 0;
    struct stat stat_buf;

#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter read_config()");
#endif

    pf = fopen(configfile, "r");
    if(pf == NULL)
    {
        fprintf (stdout, "Error: Fail to open config file %s!\n", configfile);
        exit (-1);
    }

    num = 0;
    for(;;)
    {
        ++num;
        if(fgets(line, MAX_FILELINE_LENGTH, pf) == NULL)
        {
            if(feof(pf)) break;
            if (!ferror(pf))
            {
                fprintf (stdout, "Error: Error reading config file '%s'\n", configfile);
                fclose(pf);
                exit (-1);
            }
        }

        var = trim_ends(line);
        if (*var == '#')
            continue;
        if (*var == ';')
            continue;
        if (*var == '\0')
            continue;

        val = strchr(var, '=');

        *val++ = '\0';
        var = trim_ends (var);
        val = trim_ends (val);

        //将配置文件中的值赋予全局变量
        if(strcasecmp(var, "server") == 0)
        {
#ifdef _DEBUG_
            netpas_debug(g_logfile, DEBUG, "srvipaddr: %s", val);
#endif
            server_ip_parse(val);
            continue;
        }
        if(strcasecmp(var, "port") == 0)
        {
            sscanf(val, "%hu", &g_srvport);
            continue;
        }
        if(strcasecmp(var, "named_rl") == 0)
        {
            sscanf(val, "%u", &g_named_rl);
            continue;
        }
        if(strcasecmp(var, "clientdir") == 0)
        {
            strncpy(g_clientdir, val, sizeof(g_clientdir) - 1);
            continue;
        }
        if(strcasecmp(var, "routedir") == 0)
        {
            strncpy(g_routedir, val, sizeof(g_routedir) - 1);
            continue;
        }
        if(strcasecmp(var, "local") == 0)
        {
            strncpy(g_loipaddress, val, sizeof(g_loipaddress) - 1);
            continue;
        }
        if(strcasecmp(var, "named_dns") == 0)
        {
            strncpy(g_named_dns, val, sizeof(g_named_dns) - 1);
            continue;
        }
    }

    fclose(pf);

#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Param: %u.%u.%u.%u %s %s",
                    (g_srvipaddress>>24)&255, (g_srvipaddress>>16)&255, (g_srvipaddress>>8)&255, g_srvipaddress&255,
                    g_clientdir, g_routedir);
#endif
    if(g_srvipaddress == 0) exit(-1);
    if(strncmp(g_clientdir, "", sizeof(g_clientdir)) == 0) exit(-1);
    if(strncmp(g_routedir, "", sizeof(g_routedir)) == 0) exit(-1);

    if(stat(g_clientdir, &stat_buf) < 0)
    {
        if(errno == ENOENT)
            mkdir(g_clientdir, 0777);
    }
}

/**
 *@brief 解析ip地址
 *@param [in] char *ip 输入特定格式的字符串
 *@return none
 */
static void server_ip_parse(char *ip)
{
    char *tmp = NULL;
    char *token = NULL;
    int i = 0;

    g_server_ip_count = 0;
    tmp = trim_ends(ip);
    token = strtok(tmp, ",");
    if(token == NULL) {
        exit(-1);
    }
    for(i = 0; i < MAX_SERVER_IP_COUNT;i++) {
        if(token == NULL) {
            break;
        }
        g_server_ip_count ++;
        tmp = trim_ends(token);
        g_srvipaddress[i] = resolve_ipaddr(tmp);
        token = strtok(NULL, ",");
    }

    if(g_server_ip_count == 0) {
        exit(-1);
    }
}

/**
 *@brief 初始化远端发送地址
 *@param [in] void
 *@return none
 */
static void init_srvaddr()
{
    static unsigned short index = 0;

    bzero(&g_srvaddr, sizeof(g_srvaddr));
    g_srvaddr.sin_family = AF_INET;
    g_srvaddr.sin_port = htons(g_srvport);
    while(1) {
        index = index % g_server_ip_count;
        if(g_srvipaddress[index] == 0 ) {
            index ++;
            continue;
        }
        g_srvaddr.sin_addr.s_addr = g_srvipaddress[index];
        index ++;
        break;
    }
}

/**
 *@brief 初始化socket接口
 *@param [in] const char *loipaddress 本地地址
 *@return int 返回socket描述符
 */
static int init_socket (const char * loipaddress)
{
    struct sockaddr_in addr;
    int s;
    char *lastfield;

#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter init_socket()");
#endif

    s = socket (PF_INET, SOCK_DGRAM, 0);
    if(s < 0)
    {
        fprintf (stdout, "Error: socket error: %s", strerror(errno));
        exit (-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    lastfield = strrchr(loipaddress, '.');
    if(strcmp(loipaddress, "") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    else if(isdigit(*loipaddress) && isdigit(*lastfield++))
    {
        addr.sin_addr.s_addr = inet_addr(loipaddress);
        if(addr.sin_addr.s_addr == INADDR_NONE)
        {
            fprintf (stdout, "Error: Invalid IP address %s!", loipaddress);
            close(s);
            exit (-1);
        }
    }

    if(bind(s, (struct sockaddr *)&addr, sizeof(addr))<0) {
        fprintf(stdout, "Error: Bind ip failed!\n");
    }

    return (s);
}

/**
 *@brief 创建消息
 *@param [in] void
 *@return none
 */
static void make_message()
{
    auth_request auth;
    connect_info connect;
    traffic_info disconnect;

#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter make_message()");
#endif

    switch(g_opertype)
    {
        case USER_PASS_VERIFY:
            strncpy(auth.username, g_username, USERNAME_LENGTH);
            strncpy(auth.password, g_password, PASSWORD_LENGTH);
            auth.ipaddr = ntohl(inet_addr(g_untrustedip));
            g_sendlen = build_auth_request(g_sendbuf, &auth);
            break;
        case CLIENT_CONNECT:
            strncpy(connect.username, g_username, USERNAME_LENGTH);
            connect.ipaddr = ntohl(inet_addr(g_trustedip));
            connect.srvip = ntohl(inet_addr(g_localip));
            connect.netpasip = ntohl(inet_addr(g_netpasip));
            g_sendlen = build_connect_info(g_sendbuf, &connect);
            break;
        case CLIENT_DISCONNECT:
            strncpy(disconnect.username, g_username, USERNAME_LENGTH);
            disconnect.in = g_inbytes;
            disconnect.out = g_outbytes;
            disconnect.netpasip = ntohl(inet_addr(g_netpasip));
            g_sendlen = build_disconnect_info(g_sendbuf, &disconnect);
            break;
        default:
            close (g_socket);
            exit (-1);
            break;
    }

    add_msg_ver(g_sendbuf, CURRENT_MSG_VER);
}

/**
 *@brief 发送消息
 *@param [in] void
 *@return none
 */
static void netpas_send()
{
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    struct timeval tv;
    int count = 0;
    fd_set readset;
    int recvmsglen;
    message_head msghead;

#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter netpas_send()");
#endif

    bzero(&addr, sizeof(addr));

    g_recvlen = 0;
    while (count < (g_server_ip_count*SEND_RETRY))
    {
        if((count != 0)) {
            init_srvaddr ();
        }
        count++;
        if(g_sendlen == 0)
            break;
        if(sendto(g_socket, g_sendbuf, g_sendlen, 0, (struct sockaddr*)&g_srvaddr, sizeof(g_srvaddr)) < 0)
        {
            continue;
        }
        tv.tv_sec = SEND_TIMEOUT;
        tv.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(g_socket, &readset);

        if(select(g_socket+1, &readset, NULL, NULL, &tv) < 0)
        {
            continue;
        }

        if (FD_ISSET(g_socket, &readset))
        {
            if((recvmsglen = recvfrom (g_socket, g_recvbuf, RECV_BUFFER_SIZE, 0, (struct sockaddr*)&addr, (socklen_t *)&addrlen)) < 0)
            {
                continue;
            }

            if(recvmsglen <= 0 || recvmsglen > RECV_BUFFER_SIZE)
                continue;

            g_recvbuf[recvmsglen] = '\0';
            if(check_msg_head (g_recvbuf, recvmsglen, &msghead) < 0)
                continue;
            if(check_message(msghead.msgcode) < 0)
                continue;

            g_recvlen = recvmsglen;
            break;
        }
    }

    close(g_socket);
    g_sendlen = 0;
    FD_ZERO(&readset);
    if(g_recvlen == 0) exit(-1);
}

/**
 *@brief 消息处理
 *@param [in] unsigned short msgcode 消息检查码
 *@return none
 */
static int check_message (unsigned short msgcode)
{
    char username[USERNAME_LENGTH] = "";

#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter check_message()");
#endif

    switch(g_opertype)
    {
        case USER_PASS_VERIFY:
            if(msgcode != AUTH_REPLY) return (-1);
            read_auth_reply(g_recvbuf, &g_authreply);
            if(strncmp(g_username, g_authreply.username, sizeof(g_username)) != 0) return (-1);
            break;
        case CLIENT_CONNECT:
        case CLIENT_DISCONNECT:
            if(msgcode != INFO_CONFIRM) return(-1);
            read_info_confirm(g_recvbuf, username);
            if(strncmp(g_username, username, sizeof(g_username)) != 0) return (-1);
            break;
        default:
            exit (-1);
            break;
    }
    return (1);
}

/**
 *@brief 对收到的消息进行其它处理
 *@param [in] void
 *@return none
 */
static void post_send()
{
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter post_send()");
#endif

    switch(g_opertype)
    {
        case USER_PASS_VERIFY:
            process_auth_post();
            break;
        case CLIENT_CONNECT:
            break;
        case CLIENT_DISCONNECT:
            break;
            process_disconnect_post();
        default:
            close (g_socket);
            exit (-1);
            break;
    }
}

/**
 *@brief 完成断开连接的最后处理
 *@param [in] void
 *@return none
 */
 static void process_disconnect_post()
 {
    char filename[MAX_FILENAME_LENGTH];

    sprintf(filename, "%s/%s", g_clientdir, g_username);
    unlink(filename);
}

/**
 *@brief 完成认证过程的最后处理，通知服务认证结果
 *@param [in] void
 *@return none
 */
 static void process_auth_post()
 {
    FILE *pf, *pf1;
    char buf[MAX_FILELINE_LENGTH];
    char filename[MAX_FILENAME_LENGTH];
    char tmpfile[MAX_FILENAME_LENGTH];
    char line[MAX_FILELINE_LENGTH];

#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "Enter process_auth_post()");
#endif

    switch(g_authreply.status)
    {
        case AUTH_SUCCESS:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_OK, g_untrustedip, g_untrustedport);
            break;
        case AUTH_UNKNOWN_USER:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_ERRUSER, g_untrustedip, g_untrustedport);
            break;
        case AUTH_EXPIRE:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_EXPIRE, g_untrustedip, g_untrustedport);
            break;
        case AUTH_PASSWD_ERROR:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_ERRPASS, g_untrustedip, g_untrustedport);
            break;
        case AUTH_DUP_USER:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_DUPUSER, g_untrustedip, g_untrustedport);
            break;
        case AUTH_NO_ACT:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_NOACT, g_untrustedip, g_untrustedport);
            break;
        case AUTH_FREEZE:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_FREEZE, g_untrustedip, g_untrustedport);
            break;
        case AUTH_NOFREE:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_NOFREE, g_untrustedip, g_untrustedport);
            break;
        case AUTH_SVC_WARN:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_SVCWARN, g_untrustedip, g_untrustedport);
            break;
        case AUTH_UNKNOWN:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_FAILED, g_untrustedip, g_untrustedport);
            break;
        default:
            sprintf(buf, "%s %d %s %d", g_username, NETPAS_AUTH_FAILED, g_untrustedip, g_untrustedport);
            break;
    }
    pf = fopen(g_pipename, "a");
    if(pf == NULL)
    {
        exit (-1);
    }
    fprintf(pf, "%s\n", buf);
    fclose (pf);

    if(g_authreply.status != AUTH_SUCCESS) return;

    sprintf(filename, "%s/%lu.rl", g_routedir, g_authreply.routetable);
    if(g_named_rl != 0) {
        sprintf(filename, "%s/%u.rl", g_routedir, g_named_rl);
    }
//    sprintf(filename, "%s/1.rl", g_routedir);
//    sprintf(filename, "%s/327695.rl", g_routedir);
//    sprintf(filename, "%s/1572872.rl", g_routedir);
//    sprintf(filename, "%s/1966184.rl", g_routedir);
//    sprintf(filename, "%s/328263.rl", g_routedir);
//    sprintf(filename, "%s/983043.rl", g_routedir);
//    sprintf(filename, "%s/1114120.rl", g_routedir);
    sprintf(tmpfile, "%s/%s", g_clientdir, g_username);
#ifdef _DEBUG_
    netpas_debug(g_logfile, DEBUG, "filename: %s %s", filename, tmpfile);
#endif
    unlink(tmpfile);
//    symlink(filename, tmpfile);

    pf = fopen(tmpfile, "w");
    if(pf == NULL)
    {
        netpas_debug(g_logfile, ERROR, "failed to open %s", tmpfile);
        exit (-1);
    }
    fprintf(pf, "push \"band %u\"\n", g_authreply.band*1024);
    fprintf(pf, "push \"u %lu %hu %s %hu\"\n", g_authreply.regid, g_authreply.regstat, g_authreply.enddate, g_authreply.endtime);
    if(g_named_dns[0] != '\0') {
        fprintf(pf, "push \"dns %s\"\n", g_named_dns);
    }
    if(g_authreply.regstat == 0)
        netpas_debug(g_logfile, ERROR, "push \"u %lu %hu %s %hu\"", g_authreply.regid, g_authreply.regstat, g_authreply.enddate, g_authreply.endtime);

    pf1 = fopen(filename, "r");
    if(pf1 == NULL)
    {
        exit (-1);
    }
    
    while (fgets(line, MAX_FILELINE_LENGTH, pf1) != NULL)
    {
        fprintf(pf, "%s", line);
    }
    
    fclose(pf1);
    fclose(pf);
}

/* End Of File */

