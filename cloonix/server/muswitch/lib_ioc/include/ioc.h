/****************************************************************************/
/* Copyright (C) 2006-2017 Cloonix <clownix@clownix.net>  License GPL-3.0+  */
/****************************************************************************/
/*                                                                          */
/*   This program is free software: you can redistribute it and/or modify   */
/*   it under the terms of the GNU General Public License as published by   */
/*   the Free Software Foundation, either version 3 of the License, or      */
/*   (at your option) any later version.                                    */
/*                                                                          */
/*   This program is distributed in the hope that it will be useful,        */
/*   but WITHOUT ANY WARRANTY; without even the implied warranty of         */
/*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          */
/*   GNU General Public License for more details.                           */
/*                                                                          */
/*   You should have received a copy of the GNU General Public License      */
/*   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */
/*                                                                          */
/****************************************************************************/
#ifndef _IO_CLOWNIX_H
#define _IO_CLOWNIX_H

#include <stdio.h>
#include <asm/types.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/time.h>
#include "ioc_top.h"

#define MAX_MUTXT_LEN      2500
#define IO_MAX_BUF_LEN 50000
#define MAX_SIZE_BIGGEST_MSG 100000
#define MAX_TYPE_CB 10
#define MAX_ERR_LEN 400
#define MAX_RESP_LEN 500
#define MASK_ASYNC_TX_POOL 0x7FF
#define MAX_USOCK_RANKS 200 
/*--------------------------------------------------------------------------*/
struct t_all_ctx;
/*--------------------------------------------------------------------------*/
typedef struct t_tx_sock_async_pool
{
  uint32_t volatile pool_lock;
  int pool_put;
  int pool_get;
  int pool_qty;
  int total_elem_len;
  void *elem[MASK_ASYNC_TX_POOL + 1];
  int elem_len[MASK_ASYNC_TX_POOL + 1];
} t_tx_sock_async_pool;
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
typedef struct t_traf_sat
{
  char path_traf[MAX_PATH_LEN];
  int  llid_traf;
  int  llid_lan;
  char con_name[MAX_NAME_LEN];
  int  con_llid;
  int  con_tid;
  int  timeout_mulan_id;
  int  nb_pkt_tx;
  int  nb_bytes_tx;
  int  nb_pkt_rx;
  int  nb_bytes_rx;
} t_traf_sat;
/*---------------------------------------------------------------------------*/


typedef void (*t_fct_real_timeout)(long delta_ns, void *data);
int  clownix_real_timeout_add(int nb_us, t_fct_real_timeout cb, 
                              void *data, long long *date_us);
int clownix_real_timeout_exists(long long date_us, void **data);
int  clownix_real_timeout_del(long long date_us, void **data);
void clownix_real_timer_end(void);
void clownix_real_timer_init(struct t_all_ctx *all_ctx);
/*--------------------------------------------------------------------------*/


/****************************************************************************/
typedef void (*t_client_cmd)(struct t_all_ctx *all_ctx, int llid,
                             char *req, char *resp);
typedef void (*t_client_hop_dialog)(struct t_all_ctx *all_ctx, char *name,
                                    char *req,char *resp);
typedef void (*t_prepare_rx_packet)(struct t_all_ctx *all_ctx, int *can_rx_nb); 
typedef void (*t_rx_packet)(struct t_all_ctx *all_ctx, uint64_t usec, 
                                   uint32_t len, uint8_t *data);
typedef void (*t_collect_eventfull)(struct t_all_ctx *all_ctx, int *eth,
                                    int *nb_pkt_tx, int *nb_bytes_tx,
                                    int *nb_pkt_rx, int *nb_bytes_rx);

/*--------------------------------------------------------------------------*/
typedef t_blkd_chain *(*t_get_blkd_from_elem)(struct t_all_ctx *ctx,
                                              void *ptrelem); 
/****************************************************************************/
typedef void (*t_wake_out_epoll)(struct t_all_ctx *all_ctx);


typedef struct t_all_ctx
{
  t_all_ctx_head ctx_head;
  int volatile g_lock_handle_tx;
  int volatile g_lock_timer_tx;
  int volatile g_lock_handle_rx;
  int volatile g_lock_thread_rx;
  int g_out_evt_fd;
  int g_nb_elem_rx_ready;
  t_wake_out_epoll g_cb[MAX_TYPE_CB];

  char g_net_name[MAX_NAME_LEN];
  char g_name[MAX_NAME_LEN];
  char g_path[MAX_PATH_LEN];
  char g_addr_port[MAX_NAME_LEN];
  int  g_fd_tcp;
  int  g_llid_tcp;
  int  g_self_destroy_requested;
  char g_listen_traf_path[MAX_PATH_LEN];
  int  g_llid_listen_traf;

  t_traf_sat g_traf[2];

  t_tx_sock_async_pool tx_pool;
  void *qemu_mueth_state;
  int qemu_guest_hdr_len;

  int  g_tx_queue_len_unix_sock;
  int g_cloonix_net_status_ok;
  int g_qemu_net_status_ok;
  t_client_cmd g_cb_client_cmd;
  t_get_blkd_from_elem get_blkd_from_elem;
  t_prepare_rx_packet g_cb_prepare_rx_packet;
  t_rx_packet g_cb_rx_packet;
  t_collect_eventfull cb_collect_eventfull;


} t_all_ctx;

void nonblock_fd(int fd);


int test_file_is_socket(char *path);
typedef void (*t_fct_timeout)(t_all_ctx *all_ctx, void *data);
void clownix_timeout_add(t_all_ctx *all_ctx, int nb_beats, t_fct_timeout cb, 
                         void *data, long long *abs_beat, int *ref);
int clownix_timeout_exists(t_all_ctx *all_ctx, long long abs_beat, int ref);
void *clownix_timeout_del(t_all_ctx *all_ctx, long long abs_beat, int ref,
                          const char *file, int line);
void clownix_timeout_del_all(t_all_ctx *all_ctx);
char *get_bigbuf(t_all_ctx *all_ctx);

/****************************************************************************/

/****************************************************************************/
typedef void (*t_msg_rx_cb)(t_all_ctx *all_ctx, int llid,int len,char *str_rx); 
typedef void (*t_heartbeat_cb)(t_all_ctx *all_ctx, int delta);
/*---------------------------------------------------------------------------*/

/****************************************************************************/
t_all_ctx *msg_mngt_init (char *name, int offset, int max_len_per_read);
int msg_exist_channel(t_all_ctx *all_ctx, int llid, 
                      int *is_blkd, const char *fct);
void msg_delete_channel(t_all_ctx *all_ctx, int llid);
void msg_mngt_heartbeat_init (t_all_ctx *all_ctx, t_heartbeat_cb heartbeat);
void msg_mngt_set_callbacks (t_all_ctx *all_ctx, int llid, t_fd_error err_cb,
                             t_msg_rx_cb rx_cb);
void string_tx(t_all_ctx *all_ctx, int llid, int len, char *tx);
int  string_client_unix (t_all_ctx *all_ctx, char *pname, 
                         t_fd_error err_cb, t_msg_rx_cb rx_cb);
int string_server_unix(t_all_ctx *all_ctx, char *pname,t_fd_connect connect_cb); 
int rawdata_server_unix(t_all_ctx *all_ctx, char *pname,
                        t_fd_connect connect_cb);
void msg_mngt_loop(t_all_ctx *all_ctx);

int msg_watch_fd(t_all_ctx *all_ctx,int fd,t_fd_event rx_data,t_fd_error err);
void data_tx(t_all_ctx *all_ctx, int llid, int len, char *str_tx);


void wake_out_epoll(t_all_ctx *all_ctx, uint8_t nb, t_wake_out_epoll cb);
void red_light_for_rx(t_all_ctx *all_ctx);
void green_light_for_rx(t_all_ctx *all_ctx);
/*****************************************************************************/
int channel_get_tx_queue_len(t_all_ctx *all_ctx, int llid,
                             int *tx_queued, int *rx_queued);
/*---------------------------------------------------------------------------*/
void setup_global_second_offset(int second_offset);
/*---------------------------------------------------------------------------*/
void channel_sync(void *ptr, int llid);
/*---------------------------------------------------------------------------*/
int msg_mngt_get_tx_queue_len(t_all_ctx *all_ctx, int llid);
/*---------------------------------------------------------------------------*/
void channel_set_red_to_stop_reading(t_all_ctx *all_ctx, int llid);
void channel_unset_red_to_stop_reading(t_all_ctx *all_ctx, int llid);
/*---------------------------------------------------------------------------*/
int get_fd_with_llid(t_all_ctx *all_ctx, int llid);
/*---------------------------------------------------------------------------*/





#endif /* _IO_CLOWNIX_H */

