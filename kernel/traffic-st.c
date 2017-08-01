#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/cdev.h>
#include <asm/uaccess.h> 
#include <linux/list.h>
#include <linux/spinlock.h>
#include "traffic-st.h"
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>

LIST_HEAD(service_list);
DEFINE_SPINLOCK(service_list_lock);
atomic_t service_list_cnt = ATOMIC_INIT(0);
atomic_t config_lock = ATOMIC_INIT(0);

struct service_mgt_st *lookup_service(unsigned ip, unsigned short int port);

struct user_mgt_st *lookup_user(struct service_mgt_st *server, unsigned int ip)
{
    struct user_mgt_st *tmp = NULL;
    
    list_for_each_entry(tmp, &server->user_head, list) {
        if(tmp->ip == ip) {
            return tmp;
        }
    }

    return NULL;
}

static unsigned int
traffic_st_post_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int af = 0;
    struct iphdr *iph;
    struct tcphdr tcph, *tcphp;
    struct service_mgt_st *service_mgt = NULL;
    struct user_mgt_st *user_mgt = NULL;
    int ip_payload_len = 0;

    af = (skb->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;
    if(af == AF_INET6) {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if(iph->protocol != 6) { //!TCP
        return NF_ACCEPT;
    }

    tcphp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(tcph), &tcph);
    
    //ip_payload_len = (ntohs(iph->tot_len) - iph->ihl * 4 - tcphp->doff * 4) * 8;
    ip_payload_len = ntohs(iph->tot_len) * 8;
    spin_lock_bh(&service_list_lock);
    service_mgt = lookup_service(iph->saddr, ntohs(tcphp->source));
    if(!service_mgt) {
        spin_unlock_bh(&service_list_lock);
        return NF_ACCEPT;
    }
    spin_lock(&service_mgt->lock);
    user_mgt = lookup_user(service_mgt, iph->daddr);
    if(!user_mgt) {
        spin_unlock(&service_mgt->lock);
        spin_unlock_bh(&service_list_lock);
        return NF_ACCEPT;
    }else {
        atomic64_inc(&user_mgt->tx_pps);
        atomic64_add(ip_payload_len, &user_mgt->tx_bps);
    }

    spin_unlock(&service_mgt->lock);
    spin_unlock_bh(&service_list_lock);

    return NF_ACCEPT;
}

static unsigned int 
traffic_st_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    int af = 0;
    struct iphdr *iph;
    struct tcphdr tcph, *tcphp;
    struct service_mgt_st *service_mgt = NULL;
    struct user_mgt_st *user_mgt = NULL;
    int ip_payload_len = 0;

    af = (skb->protocol == htons(ETH_P_IP)) ? AF_INET : AF_INET6;

    if(af == AF_INET6) {
        return NF_ACCEPT;
    }
    
    iph = ip_hdr(skb);
    
    if(iph->protocol != 6) { //!TCP
        return NF_ACCEPT;
    }
    
    tcphp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(tcph), &tcph);
    
    //ip_payload_len = (ntohs(iph->tot_len) - iph->ihl * 4 - tcphp->doff * 4) * 8;
    ip_payload_len = ntohs(iph->tot_len) * 8;
    //pr_err("src: %08x:%d  dip:%08x:%d\n", iph->saddr, ntohs(tcphp->source), iph->daddr, ntohs(tcphp->dest));
   
    spin_lock_bh(&service_list_lock);
    service_mgt = lookup_service(iph->daddr, ntohs(tcphp->dest));
    if(!service_mgt) {
        spin_unlock_bh(&service_list_lock);
        return NF_ACCEPT;
    }
    
    spin_lock(&service_mgt->lock);
    user_mgt = lookup_user(service_mgt, iph->saddr);
    if(!user_mgt) {
        user_mgt = kmalloc(sizeof(*user_mgt), GFP_KERNEL);
        if(!user_mgt) {
            spin_unlock(&service_mgt->lock);
            spin_unlock_bh(&service_list_lock);
            return NF_ACCEPT;
        }
        memset(user_mgt, 0, sizeof(*user_mgt));
        user_mgt->ip = iph->saddr;
        atomic64_inc(&user_mgt->rx_pps);
        atomic64_add(ip_payload_len, &user_mgt->rx_bps);
        atomic_inc(&service_mgt->user_cnt);

        list_add(&user_mgt->list, &service_mgt->user_head);
        pr_err("create user sip %pI4 \n", &user_mgt->ip);
    }else {
        atomic64_inc(&user_mgt->rx_pps);
        atomic64_add(ip_payload_len, &user_mgt->rx_bps);
    }
    
    spin_unlock(&service_mgt->lock);
    spin_unlock_bh(&service_list_lock);

    return NF_ACCEPT;
}

static struct nf_hook_ops traffic_st_ops[] = {
    {
        .hook = traffic_st_pre_routing,
        .pf = PF_INET,
        .hooknum = 0,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = traffic_st_post_routing,
        .pf = PF_INET,
        .hooknum = 4,
        .priority = NF_IP_PRI_FIRST,
    },

};

struct service_mgt_st *lookup_service(unsigned ip, unsigned short int port)
{
    struct service_mgt_st *tmp = NULL;
    list_for_each_entry(tmp, &service_list, list) {
        if(tmp->ip == ip && tmp->port == port) {
            return tmp;
        }
    }

    return NULL;
}

int add_service(struct traffic_st_msg *msg)
{
    struct service_mgt_st *tmp = NULL;

    spin_lock_bh(&service_list_lock);
    if(lookup_service(msg->ip, msg->port)) {
        spin_unlock_bh(&service_list_lock);
        return -EEXIST;
    }
    
    tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
    if(!tmp) {
        spin_unlock_bh(&service_list_lock);
        return -ENOSPC;
    }
    
    memset(tmp, 0, sizeof(*tmp));
    tmp->ip = msg->ip;
    tmp->port = msg->port;
    INIT_LIST_HEAD(&tmp->user_head);
    atomic_set(&tmp->user_cnt, 0); 
    spin_lock_init(&tmp->lock);
    list_add(&tmp->list, &service_list);
    atomic_inc(&service_list_cnt);
    spin_unlock_bh(&service_list_lock);
    
    return 0;
}

int del_service(struct traffic_st_msg *msg)
{
    struct service_mgt_st *tmp = NULL;
    struct user_mgt_st *tmp_user = NULL;
    struct list_head *p = NULL;

    spin_lock_bh(&service_list_lock);
    tmp = lookup_service(msg->ip, msg->port);
    if(!tmp) {
        spin_unlock_bh(&service_list_lock);
        return -ENOENT;
    }
    
    spin_lock(&tmp->lock);
    p = tmp->user_head.next;
    while(p != &tmp->user_head) {
        tmp_user = list_entry(p, struct user_mgt_st, list);
        p = p->next;
        list_del(&tmp_user->list);
        kfree(tmp_user);
    }
    spin_unlock(&tmp->lock);

    list_del(&tmp->list);
    kfree(tmp);
    spin_unlock_bh(&service_list_lock);
    
    atomic_dec(&service_list_cnt);
    return 0;
}

static long traffic_st_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct traffic_st_msg *mesg = NULL;
    struct traffic_st_msg kmesg;
    int ret = 0, tmp = 0, cnt = 0;
    struct service_info_st *service_info = NULL;
    struct service_mgt_st *service_mgt = NULL;
    struct user_info_st *user_info = NULL;
    struct user_mgt_st *user_mgt = NULL;
    struct user_mgt_st *tmp_user = NULL;
    struct list_head *p = NULL;

    mesg = (struct traffic_st_msg *)arg;
    ret = copy_from_user(&kmesg, mesg, sizeof(*mesg));
    if(ret < 0) {
        pr_err("chardev ioctl copy from user failed.\n");
        return ret;
    }
    
    switch(kmesg.cmd) {
        case TRAFFIC_ST_ADD_SERVICE:
            ret = add_service(&kmesg);
            if(ret < 0) {
                return ret;
            }
            break;
        case TRAFFIC_ST_DEL_SERVICE:
            ret = del_service(&kmesg);
            if(ret < 0) {
                return ret;
            }
            break;
        case TRAFFIC_ST_SERVICE_CNT:
            tmp = atomic_read(&service_list_cnt);
            ret = copy_to_user(&mesg->total_cnt, &tmp, sizeof(unsigned int));
            if(ret < 0) {
                return ret;
            }
            break;
        case TRAFFIC_ST_LIST_SERVICE:
            tmp = 0;
            service_info = kmalloc(sizeof(struct service_info_st) * 2048, GFP_KERNEL);
            if(!service_info) {
                return -1;
            }
            spin_lock_bh(&service_list_lock);
            list_for_each_entry(service_mgt, &service_list, list) {
                cnt += 1;
                if(cnt < kmesg.curr_cnt) {
                    continue;
                }
                service_info[tmp].ip = service_mgt->ip;
                service_info[tmp].port = service_mgt->port;
                service_info[tmp].user_cnt = atomic_read(&service_mgt->user_cnt);
                tmp ++;
                if(tmp > 2048) {
                    break;
                }
            }
            spin_unlock_bh(&service_list_lock);
            ret = copy_to_user((char *)kmesg.data, (char *)service_info, sizeof(struct service_info_st) * 2048);
            if(ret < 0) {
                return ret;
            }
            ret = copy_to_user(&mesg->len, &tmp, sizeof(unsigned int));
            if(ret < 0) {
                kfree(service_info);
                return ret;
            }
            kfree(service_info);
            break;
        case TRAFFIC_ST_USER_CNT:
            spin_lock_bh(&service_list_lock);
            service_mgt = lookup_service(kmesg.ip, kmesg.port);
            if(service_mgt == NULL) {
                spin_unlock_bh(&service_list_lock);
                return -1;
            }
            tmp = atomic_read(&service_mgt->user_cnt);
            spin_unlock_bh(&service_list_lock);
            ret = copy_to_user(&mesg->total_cnt, &tmp, sizeof(unsigned int));
            if(ret < 0) {
                return -1;
            }
            break;
        case TRAFFIC_ST_SHOW_USER_ACCOUNT:
            tmp = 0;
            spin_lock_bh(&service_list_lock);
            service_mgt = lookup_service(kmesg.ip, kmesg.port);
            if(!service_mgt) {
                spin_unlock_bh(&service_list_lock);
                return -1;
            }
            user_info = kmalloc(sizeof(struct user_info_st) * 512, GFP_KERNEL);
            if(!user_info) {
                spin_unlock_bh(&service_list_lock);
                return -1;
            }
            spin_lock_bh(&service_mgt->lock);
            list_for_each_entry(user_mgt, &service_mgt->user_head, list) {
                cnt += 1;
                if(cnt < kmesg.curr_cnt) {
                    continue;
                }
                user_info[tmp].ip = user_mgt->ip;
                user_info[tmp].rx_pps = atomic64_read(&user_mgt->rx_pps);
                user_info[tmp].rx_bps = atomic64_read(&user_mgt->rx_bps);
                user_info[tmp].tx_pps = atomic64_read(&user_mgt->tx_pps);
                user_info[tmp].tx_bps = atomic64_read(&user_mgt->tx_bps);
                tmp ++;
                if(tmp > 512) {
                    break;
                }
            }
            spin_unlock_bh(&service_mgt->lock);
            spin_unlock_bh(&service_list_lock);
            ret = copy_to_user((char *)kmesg.data, (char *)user_info, sizeof(struct user_info_st) * 512);
            if(ret < 0) {
                return ret;
            }
            ret = copy_to_user(&mesg->len, &tmp, sizeof(unsigned int));
            if(ret < 0) {
                kfree(user_info);
                return ret;
            }
            kfree(user_info);
            break;
        case TRAFFIC_ST_DESTORY_USER:
            spin_lock_bh(&service_list_lock);
            service_mgt = lookup_service(kmesg.ip, kmesg.port);
            if(service_mgt == NULL) {
                spin_unlock_bh(&service_list_lock);
                return -1;
            }
            
            spin_lock(&service_mgt->lock);
            p = service_mgt->user_head.next;
            while(p != &service_mgt->user_head) {
                tmp_user = list_entry(p, struct user_mgt_st, list);
                p = p->next;
                list_del(&tmp_user->list);
                atomic_dec(&service_mgt->user_cnt); 
                kfree(tmp_user);
            }
            spin_unlock(&service_mgt->lock);
            spin_unlock_bh(&service_list_lock);
            break;
        case TRAFFIC_ST_CONFIG_LOCK_SET:
            if(atomic_cmpxchg(&config_lock, 0, 1) == 0) {
                return 0;
            }else {
                return -1;
            }
           break;
        case TRAFFIC_ST_CONFIG_LOCK_CLEAN:
            atomic_cmpxchg(&config_lock, 1, 0);
        default:
            pr_err("traffic_st_ioctl cmd %d invalid.\n", kmesg.cmd);
            return -1;
    }

    return 0;
}

static struct file_operations chardev_ops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = traffic_st_ioctl,
};

static struct cdev chardev = {
    .kobj = {.name = "traffic_st",},
    .owner = THIS_MODULE,
};

int chardev_init(void)
{
    int ret = 0;
    dev_t dev;
    
    dev = MKDEV(TRAFFIC_ST_MAJOR, 0);
    
    ret = register_chrdev_region(dev, 1, "traffic_st");
    if(ret < 0) {
        pr_err("traffic_st chardev register_chrdev_region failed.\n");
        return -1;
    }
    
    cdev_init(&chardev, &chardev_ops);
    ret = cdev_add(&chardev, dev, 1);
    if(ret < 0) {
        pr_err("cdev add failed.");
        goto err;
    }
    
    return 0;
err:
    unregister_chrdev_region(dev, 1);
    return -1;
}

static int __init traffic_st_init(void)
{
    if(nf_register_hooks(traffic_st_ops, ARRAY_SIZE(traffic_st_ops))  < 0) {
        pr_err("%s %d: nf register hook failed.\n", __func__, __LINE__);
        return -1;
    }

    if(chardev_init() < 0) {
        pr_err("%s %d: chardev init failed.\n", __func__, __LINE__);
        goto err;
    }
    
    pr_info("%s %d: load traffic statistics success.\n", __func__, __LINE__);
    return 0;
    
err:
    nf_unregister_hooks(traffic_st_ops, ARRAY_SIZE(traffic_st_ops));
    pr_info("%s %d: load traffic statistics failed.\n", __func__, __LINE__);
    return -1;
}

void del_all_service_and_user(void)
{
    struct service_mgt_st *tmp_service = NULL;
    struct user_mgt_st *tmp_user = NULL;
    struct list_head *p = NULL, *q = NULL;

    spin_lock_bh(&service_list_lock);
    p = service_list.next;
    while(p != &service_list) {
        tmp_service = list_entry(p, struct service_mgt_st, list);
        p = p->next;
        list_del(&tmp_service->list);
        spin_lock(&tmp_service->lock);
        q = tmp_service->user_head.next;
        while(q != &tmp_service->user_head) {
            tmp_user = list_entry(q, struct user_mgt_st, list);
            q = q->next;
            list_del(&tmp_user->list);
            pr_err("del srcip %pI4 ---> Service %pI4:%d\n", &tmp_user->ip, &tmp_service->ip, tmp_service->port);
            kfree(tmp_user);
        }
        spin_unlock(&tmp_service->lock);

        kfree(tmp_service);
    }

    spin_unlock_bh(&service_list_lock);
}

static void __exit traffic_st_exit(void)
{

    cdev_del(&chardev);
    unregister_chrdev_region(MKDEV(TRAFFIC_ST_MAJOR, 0), 1);

    nf_unregister_hooks(traffic_st_ops, ARRAY_SIZE(traffic_st_ops));
    
    del_all_service_and_user();
    
    pr_info("%s %d: unload traffic statistics success.\n", __func__, __LINE__);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lujh");
MODULE_DESCRIPTION("traffic statistics");
module_init(traffic_st_init);
module_exit(traffic_st_exit);
