#ifndef __TRAFFIC_ST_TOOL__
#define __TRAFFIC_ST_TOOL__

#define TRAFFIC_ST_DEV "/dev/traffic_st"
#define TRAFFIC_ST_MAJOR    222

#define TRAFFIC_ST_ADD_SERVICE 0x1
#define TRAFFIC_ST_DEL_SERVICE 0x2
#define TRAFFIC_ST_LIST_SERVICE    0x4
#define TRAFFIC_ST_SHOW_USER_ACCOUNT    0x8
#define TRAFFIC_ST_DESTORY_USER 0x10
#define TRAFFIC_ST_SERVICE_CNT 0x20
#define TRAFFIC_ST_USER_CNT 0x40
#define TRAFFIC_ST_CONFIG_LOCK_SET 0x80
#define TRAFFIC_ST_CONFIG_LOCK_CLEAN 0x100

struct traffic_st_msg {
    int cmd;
    unsigned int ip; 
    unsigned short int port;
    unsigned int len;
    unsigned int total_cnt;
    unsigned int curr_cnt;
    void *data;
};

struct service_info_st {
    unsigned int ip;
    unsigned short int port;
    unsigned int user_cnt;
};

struct user_info_st {
    unsigned  int ip;
    unsigned long int rx_pps;
    unsigned long int rx_bps;
    unsigned long int tx_pps;
    unsigned long int tx_bps;
};

#endif  /*__TRAFFIC_ST_TOOL__*/
