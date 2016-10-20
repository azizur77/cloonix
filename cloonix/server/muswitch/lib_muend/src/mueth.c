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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <signal.h>

#include "ioc.h"
#include "sock_fd.h"
#include "mueth.h"



/*****************************************************************************/
static void epoll_context_rx_activate(t_all_ctx *all_ctx)
{
  int llid = all_ctx->g_traf[0].llid_traf;
  rx0_blkd_sock_cb((void *) all_ctx, llid);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void unix_sock_rx_activate(t_all_ctx *all_ctx)
{
  wake_out_epoll(all_ctx, 1, epoll_context_rx_activate);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void pool_tx_init(t_tx_sock_async_pool *pool_tx)
{
  int i;
  for(i = 0; i < MASK_ASYNC_TX_POOL + 1; i++)
    pool_tx->elem[i] = NULL;
  pool_tx->pool_put = 0;
  pool_tx->pool_get = MASK_ASYNC_TX_POOL;
  pool_tx->pool_qty = 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void pool_tx_put(t_tx_sock_async_pool *pool_tx, void *elem, int len)
{
  while (__sync_lock_test_and_set(&(pool_tx->pool_lock), 1));
  if(pool_tx->pool_put == pool_tx->pool_get)
    KOUT(" ");
  if (pool_tx->elem[pool_tx->pool_put])
    KOUT(" ");
  pool_tx->elem[pool_tx->pool_put] = elem;
  pool_tx->elem_len[pool_tx->pool_put] = len;
  pool_tx->total_elem_len += len;
  pool_tx->pool_put = (pool_tx->pool_put + 1) & MASK_ASYNC_TX_POOL;
  pool_tx->pool_qty += 1;
  __sync_lock_release(&(pool_tx->pool_lock));
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void *pool_tx_get(t_tx_sock_async_pool *pool_tx)
{
  void *elem = NULL;
  while (__sync_lock_test_and_set(&(pool_tx->pool_lock), 1));
  if (pool_tx->pool_qty > 0)
    {
    pool_tx->pool_get = (pool_tx->pool_get + 1) & MASK_ASYNC_TX_POOL;
    elem = pool_tx->elem[pool_tx->pool_get];
    if (!elem)
      KOUT(" ");
    pool_tx->total_elem_len -= pool_tx->elem_len[pool_tx->pool_get];
    pool_tx->elem[pool_tx->pool_get] = NULL;
    pool_tx->elem_len[pool_tx->pool_get] = 0;
    pool_tx->pool_qty -= 1;
    }
  __sync_lock_release(&(pool_tx->pool_lock));
  return (elem);
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
static void tx_all_chain(t_all_ctx *all_ctx, t_blkd_chain *cur, int llid)
{
  t_blkd_chain *next;
  while(cur)
    {
    next = cur->next; 
    blkd_put_tx((void *) all_ctx, 1, &llid, cur->blkd);
    free(cur);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void epoll_context_tx_activate(t_all_ctx *all_ctx)
{
  int llid = all_ctx->g_traf[0].llid_traf;
  void *elem = pool_tx_get(&(all_ctx->tx_pool));
  t_blkd_chain *cur;
  while (elem)
    {
    cur = all_ctx->get_blkd_from_elem(all_ctx, elem);
    tx_all_chain(all_ctx, cur, llid);
    elem = pool_tx_get(&(all_ctx->tx_pool));
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int tx_queue_len_unix_sock(t_all_ctx *all_ctx)
{
  return (all_ctx->g_tx_queue_len_unix_sock);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void tx_unix_sock(t_all_ctx *all_ctx, void *elem, int len)
{
  pool_tx_put(&(all_ctx->tx_pool), elem, len);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int tx_unix_sock_pool_len(t_all_ctx *all_ctx)
{ 
  return (all_ctx->tx_pool.total_elem_len);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void tx_unix_sock_end(t_all_ctx *all_ctx)
{
  wake_out_epoll(all_ctx, 2, epoll_context_tx_activate);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void stop_tx_counter_increment(t_all_ctx *all_ctx)
{
  blkd_stop_tx_counter_increment((void *) all_ctx, all_ctx->g_traf[0].llid_traf);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void mueth_main_endless_loop(t_all_ctx *all_ctx, char *net_name, 
                             char *name, char *serv_path,
                             t_client_cmd cb_client_cmd,
                             t_prepare_rx_packet cb_prepare_rx_packet,
                             t_rx_packet cb_rx_packet,
                             t_collect_eventfull cb_collect,
                             t_get_blkd_from_elem get_blkd_from_elem)
{
  blkd_set_our_mutype((void *) all_ctx, musat_type_eth);
  all_ctx->g_cb_client_cmd = cb_client_cmd;
  all_ctx->g_cb_prepare_rx_packet = cb_prepare_rx_packet;
  all_ctx->g_cb_rx_packet = cb_rx_packet;
  all_ctx->cb_collect_eventfull = cb_collect;
  all_ctx->get_blkd_from_elem = get_blkd_from_elem;
  strncpy(all_ctx->g_net_name, net_name, MAX_NAME_LEN-1);
  strncpy(all_ctx->g_name, name, MAX_NAME_LEN-1);
  strncpy(all_ctx->g_path, serv_path, MAX_PATH_LEN-1);
  sock_fd_init(all_ctx);
  msg_mngt_loop(all_ctx);
}
/*--------------------------------------------------------------------------*/

