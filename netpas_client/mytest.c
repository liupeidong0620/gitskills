/*-----------------------------------------------
 * @Description 程序主流程 c 文件
 * @author chejianwen <chejianwen@netpas.cc>
 * @version 
 * @date netpas_client.c 153 2014-03-04 11:08:24Z chejianwen 增加文件头
 * @date netpas_client.c 179 2014-05-20 12:50:06Z chejianwen 配置文件中增加 named_rl、named_dns 参数
 * @date $Id$ traffic_info 消息增加 netpasip
 *-----------------------------------------------*/

#include "netpas_client.h"
#define CLIENT_INFO 4

int main(int argc, char **argv)
{
    sprintf(g_username, "bj2008");
    sprintf(g_password, "b223b763f2107ac1ba40b8fb056c90a8");
    g_inbytes = 2800;
    g_outbytes = 3400;

    sscanf(argv[1], "%hu", &g_opertype);
    sprintf(g_localip, "127.0.0.1");
    sprintf(g_untrustedip, "192.168.8.2");
    g_untrustedport = 4444;
    sprintf(g_trustedip, "192.168.8.2");
    sprintf(g_netpasip, "10.99.30.6");
    g_trustedport = 4444;
    sprintf(g_pipename, "/tmp/chetest");
    g_srvipaddress = htonl(2130706433);
    g_srvport = 88;
    sprintf(g_loipaddress, "127.0.0.1");

    g_socket = init_socket (g_loipaddress);

    make_message();

    netpas_send();

    post_send();

    exit(0);
}

/*--------------------------------------------------*
 * init_socket - 初始化socket接口
 *--------------------------------------------------*/
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

    addr.sin_family = AF_INET;
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

    return (s);
}

/*--------------------------------------------------*
 * make_message - 创建消息
 *--------------------------------------------------*/
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
        case CLIENT_INFO:
            strncpy(disconnect.username, g_username, USERNAME_LENGTH);
            disconnect.in = g_inbytes;
            disconnect.out = g_outbytes;
            disconnect.netpasip = ntohl(inet_addr(g_netpasip));
            g_sendlen = build_traffic_info(g_sendbuf, &disconnect);
            break;
        default:
            close (g_socket);
            exit (-1);
            break;
    }

    add_msg_ver(g_sendbuf, CURRENT_MSG_VER);
}

/*--------------------------------------------------*
 * netpas_send - 发送消息
 *--------------------------------------------------*/
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
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_srvport);
    addr.sin_addr.s_addr = g_srvipaddress;

    g_recvlen = 0;
    while (count < SEND_RETRY)
    {
        count++;
        if(count >= 2)
        {
            if(g_srv1port != 0 && g_srv1ipaddress != 0)
            {
                addr.sin_port = htons(g_srv1port);
                addr.sin_addr.s_addr = g_srv1ipaddress;
            }
        }
        if(g_sendlen == 0)
            break;
printf("send\n");
        if(sendto(g_socket, g_sendbuf, g_sendlen, 0, (struct sockaddr*)&addr, addrlen) < 0)
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
printf("recv %d\n", recvmsglen);

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

/*--------------------------------------------------*
 * check_message - 消息处理
 *--------------------------------------------------*/
static int check_message (unsigned short msgcode)
{
    char username[USERNAME_LENGTH] = "";
    connect_stat info_rep;

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
printf("info username: %s\n", username);
            if(strncmp(g_username, username, sizeof(g_username)) != 0) return (-1);
            break;
        case CLIENT_INFO:
            if(msgcode != TRAFFIC_REPONSE) return(-1);
            read_traffic_reply(g_recvbuf, &info_rep);
printf("info username: %s, status:%d\n", info_rep.username, info_rep.status);
            break;
        default:
            exit (-1);
            break;
    }
    return (1);
}

/*--------------------------------------------------*
 * post_send - 对收到的消息进行其它处理
 *--------------------------------------------------*/
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
            printf("connected\n");
            break;
        case CLIENT_DISCONNECT:
            printf("disconnected\n");
            break;
        case CLIENT_INFO:
            printf("informed\n");
        default:
            close (g_socket);
            exit (-1);
            break;
    }
}

/*--------------------------------------------------*
 * process_disconnect_post - 完成断开连接的最后处理
 *--------------------------------------------------*/
 static void process_disconnect_post()
 {
    char filename[MAX_FILENAME_LENGTH];

    sprintf(filename, "%s/%s", g_clientdir, g_username);
    unlink(filename);
}

/*--------------------------------------------------*
 * process_auth_post - 完成认证过程的最后处理，通知服务认证结果
 *--------------------------------------------------*/
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
            sprintf(buf, "%s %d %s %d OK", g_username, NETPAS_AUTH_OK, g_untrustedip, g_untrustedport);
            break;
        case AUTH_UNKNOW_USER:
            sprintf(buf, "%s %d %s %d ERRUSER", g_username, NETPAS_AUTH_ERRUSER, g_untrustedip, g_untrustedport);
            break;
        case AUTH_EXPIRE:
            sprintf(buf, "%s %d %s %d EXPIRE", g_username, NETPAS_AUTH_EXPIRE, g_untrustedip, g_untrustedport);
            break;
        case AUTH_PASSWD_ERROR:
            sprintf(buf, "%s %d %s %d ERRPASS", g_username, NETPAS_AUTH_ERRPASS, g_untrustedip, g_untrustedport);
            break;
        case AUTH_DUP_USER:
            sprintf(buf, "%s %d %s %d DUPUSER", g_username, NETPAS_AUTH_DUPUSER, g_untrustedip, g_untrustedport);
            break;
        case AUTH_NO_ACT:
            sprintf(buf, "%s %d %s %d NOACT", g_username, NETPAS_AUTH_NOACT, g_untrustedip, g_untrustedport);
            break;
        case AUTH_FREEZE:
            sprintf(buf, "%s %d %s %d FREEZE", g_username, NETPAS_AUTH_FREEZE, g_untrustedip, g_untrustedport);
            break;
        case AUTH_NOFREE:
            sprintf(buf, "%s %d %s %d NOFREE", g_username, NETPAS_AUTH_NOFREE, g_untrustedip, g_untrustedport);
            break;
        case AUTH_SVC_WARN:
            sprintf(buf, "%s %d %s %d SVCWARN", g_username, NETPAS_AUTH_SVCWARN, g_untrustedip, g_untrustedport);
            break;
        case AUTH_UNKNOW:
            sprintf(buf, "%s %d %s %d UNKNOW", g_username, NETPAS_AUTH_FAILED, g_untrustedip, g_untrustedport);
            break;
        default:
            sprintf(buf, "%s %d %s %d FAILED", g_username, NETPAS_AUTH_FAILED, g_untrustedip, g_untrustedport);
            break;
    }
    printf("%s\n", buf);

    if(g_authreply.status != AUTH_SUCCESS) return;

    printf("push \"band %u\"\n", g_authreply.band*1024);
    printf("push \"u %lu %hu %s %hu\"\n", g_authreply.regid, g_authreply.regstat, g_authreply.enddate, g_authreply.endtime);
}

/* End Of File */

