#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <limits.h>
#include <errno.h>

#include "traffic-st-tool.h"

int traffic_st_fd;

void usage(char *progname)
{
    printf("Usage: %s\n", progname);
    printf("\t-a <ip:port>    add service by ip:port\n");
    printf("\t-d <ip:port>    del service  by ip:port\n");
    printf("\t-D <ip:port>    destory user in ip:port\n");
    printf("\t-l              list all service\n");
    printf("\t-s <ip:port>    show user in this service\n");
}

int open_chardev(void)
{
    char cmd[128];  
    if (access(TRAFFIC_ST_DEV, F_OK) < 0) {
        snprintf(cmd, 128, "mknod %s c %d 0", TRAFFIC_ST_DEV, TRAFFIC_ST_MAJOR);
        system(cmd);
    }
    
    traffic_st_fd = open(TRAFFIC_ST_DEV, O_RDWR);
    if(traffic_st_fd < 0) {
        printf("open %s failed.\n", TRAFFIC_ST_DEV);
        return -1;
    }

    return 0;
}

int paser_ip_port(char *ip_port, unsigned int *ip, unsigned short int *port)
{
    char *token = NULL;
    char arg[2][128] = {0};
    int cnt = 0;
    char *endptr = NULL;
    long int val = 0;

    if(!strstr(ip_port, ":")) {
        printf("ip_port %s format invalid.\n", ip_port);
        return -1;
    }

    token = strtok(ip_port,":");
    while(token!=NULL){
        if(cnt >= 2) {
            break;
        }
        strncpy(arg[cnt], token, 128);
        cnt += 1;
        token=strtok(NULL,",");
    }
    
    if(inet_pton(AF_INET, arg[0], ip) <= 0) {
        printf("ip %s format invalid.\n", arg[0]);
        return -1;
    }

    errno = 0;
    val = strtol(arg[1], &endptr, 10);
    if((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) 
        || (errno != 0 && val == 0)
        || val < 0 || val > 65536) {
        printf("port %s invalid.\n", arg[1]);
        return -1;
    }
    *port = val;

    return 0;
}

int main(int argc, char **argv)
{
    struct traffic_st_msg *mesg  = NULL;
    struct service_info_st *service_info = NULL;
    struct user_info_st *user_info = NULL;
    int opt, ret, i;
    static const char * short_opt = "a:d:ls:D:h";
    struct traffic_st_msg mesg_lock;
    char ip[64], ip1[64];

    if(argc < 2) {
        usage(argv[0]);
        return 0;
    }

    if(open_chardev() < 0) {
        return -1;
    }

    mesg_lock.cmd = TRAFFIC_ST_CONFIG_LOCK_SET;
    ret = ioctl(traffic_st_fd, 1, &mesg_lock);
    if(ret < 0) {
        printf("traffic_st config is locked.\n");
        return -1;
    }
    
    while ((opt = getopt(argc, argv, short_opt)) != -1) {
        switch (opt) {
            case 'a':
                mesg = malloc(sizeof(*mesg));
                memset(mesg, 0, sizeof(*mesg));
                mesg->cmd = TRAFFIC_ST_ADD_SERVICE;
                if(paser_ip_port(optarg, &mesg->ip, &mesg->port) < 0) {
                    ret = -1;
                    goto err;
                }
                break;
            case 'd':
                mesg = malloc(sizeof(*mesg));
                memset(mesg, 0, sizeof(*mesg));
                mesg->cmd = TRAFFIC_ST_DEL_SERVICE;
                if(paser_ip_port(optarg, &mesg->ip, &mesg->port) < 0) {
                    ret = -1;
                    goto err;
                }
                break;
            case 'l':
                mesg = malloc(sizeof(*mesg));
                memset(mesg, 0, sizeof(*mesg));
                mesg->cmd = TRAFFIC_ST_SERVICE_CNT;
                ret = ioctl(traffic_st_fd, 1, mesg);
                if(ret < 0) {
                    printf("ioctl failed: cmdid: %d ret %d\n", mesg->cmd, ret);
                    goto err;
                }
                
                mesg->cmd = TRAFFIC_ST_LIST_SERVICE;
                mesg->curr_cnt = 0;
                mesg->len = 0;
                mesg->data = malloc(sizeof(struct service_info_st) * 2048);
                memset((char *)mesg->data, 0, sizeof(struct service_info_st) * 2048);
                
                while(mesg->curr_cnt < mesg->total_cnt) {
                    ret = ioctl(traffic_st_fd, 1, mesg);
                    if(ret < 0) {
                        printf("ioctl failed: cmdid: %d ret %d\n", mesg->cmd, ret);
                        goto err;
                    }
                    
                    for(i = 0; i < mesg->len; i ++) {
                        service_info = &((struct service_info_st *)mesg->data)[i];
                        printf("ip: %s:%d\tuser_cnt: %d\n", inet_ntoa(*(struct in_addr *)&service_info->ip), service_info->port, service_info->user_cnt);
                    }

                    mesg->curr_cnt += mesg->len;
                    mesg->len = 0;
                    memset(mesg->data, 0, sizeof(struct service_info_st) * 2048);
                }
                goto err;
                break;
            case 's':
                mesg = malloc(sizeof(*mesg));
                memset(mesg, 0, sizeof(*mesg));
                mesg->cmd = TRAFFIC_ST_USER_CNT;
                if(paser_ip_port(optarg, &mesg->ip, &mesg->port) < 0) {
                    ret = -1;
                    goto err;
                }
                mesg->cmd = TRAFFIC_ST_USER_CNT;
                ret = ioctl(traffic_st_fd, 1, mesg);
                if(ret < 0) {
                    printf("ioctl failed: cmdid: %d ret %d\n", mesg->cmd, ret);
                    goto err;
                }
                
                mesg->cmd = TRAFFIC_ST_SHOW_USER_ACCOUNT;
                mesg->curr_cnt = 0;
                mesg->len = 0;
                mesg->data = malloc(sizeof(struct user_info_st) * 512);
                memset((char *)mesg->data, 0, sizeof(struct user_info_st) * 512);
                
                while(mesg->curr_cnt < mesg->total_cnt) {
                    ret = ioctl(traffic_st_fd, 1, mesg);
                    if(ret < 0) {
                        printf("ioctl failed: cmdid: %d ret %d\n", mesg->cmd, ret);
                        goto err;
                    }
                    for(i = 0; i < mesg->len; i ++) {
                        user_info = &((struct user_info_st *)mesg->data)[i];
                        printf("%s ---> %s:%d\n    rx: %lu bps/%lu pps\n    tx: %lu bps/%lu pps\n", inet_ntop(AF_INET, &user_info->ip, ip, 64), inet_ntop(AF_INET, &mesg->ip, ip1, 64), mesg->port, user_info->rx_bps, user_info->rx_pps, user_info->tx_bps, user_info->tx_pps);
                    }
                    mesg->curr_cnt += mesg->len;
                    mesg->len = 0;
                    memset(mesg->data, 0, sizeof(struct user_info_st) * 512);
                }
                
                break;
            case 'D':
                mesg = malloc(sizeof(*mesg));
                memset(mesg, 0, sizeof(*mesg));
                mesg->cmd = TRAFFIC_ST_DESTORY_USER;
                if(paser_ip_port(optarg, &mesg->ip, &mesg->port) < 0) {
                    ret = -1;
                    goto err;
                }
                break;
            case 'h':
                usage(argv[0]);
                ret = 0;
                goto err;
                break;
            default:
                printf("%s: opt %c is invalid.\n", argv[0], opt);
                ret = 0;
                goto err;
        }
    }

    if(mesg && mesg->cmd != 0) {
        ret = ioctl(traffic_st_fd, 1, mesg);
        if(ret < 0) {
            printf("ioctl failed: cmdid: %d ret %d\n", mesg->cmd, ret);
            goto err;
        }
    }
    
err:
    if(mesg) {
        if(mesg->data) {
            free(mesg->data);
        }
        free(mesg);
        mesg = NULL;
    }
    mesg_lock.cmd = TRAFFIC_ST_CONFIG_LOCK_CLEAN;
    ioctl(traffic_st_fd, 1, &mesg_lock);
    close(traffic_st_fd);
    return ret;
}
