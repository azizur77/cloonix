/*****************************************************************************/
/*    Copyright (C) 2006-2017 cloonix@cloonix.net License AGPL-3             */
/*                                                                           */
/*  This program is free software: you can redistribute it and/or modify     */
/*  it under the terms of the GNU Affero General Public License as           */
/*  published by the Free Software Foundation, either version 3 of the       */
/*  License, or (at your option) any later version.                          */
/*                                                                           */
/*  This program is distributed in the hope that it will be useful,          */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of           */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            */
/*  GNU Affero General Public License for more details.a                     */
/*                                                                           */
/*  You should have received a copy of the GNU Affero General Public License */
/*  along with this program.  If not, see <http://www.gnu.org/licenses/>.    */
/*                                                                           */
/*****************************************************************************/
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
  int i, llid;
  for (i=0; i<MAX_TRAF_ENDPOINT; i++)
    {
    llid = all_ctx->g_traf_endp[i].llid_traf;
    if (llid)
      rx_blkd_sock_cb((void *) all_ctx, llid);
    }
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
static void tx_all_chain(t_all_ctx *all_ctx, t_blkd_chain *cur)
{
  t_blkd_chain *next;
  while(cur)
    {
    next = cur->next; 
    sock_fd_tx(all_ctx, cur->blkd);
    free(cur);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void epoll_context_tx_activate(t_all_ctx *all_ctx)
{
  void *elem = pool_tx_get(&(all_ctx->tx_pool));
  t_blkd_chain *cur;
  while (elem)
    {
    cur = all_ctx->get_blkd_from_elem(all_ctx, elem);
    tx_all_chain(all_ctx, cur);
    elem = pool_tx_get(&(all_ctx->tx_pool));
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void tx_unix_sock(t_all_ctx *all_ctx, void *elem, int len)
{
  int i, j, ms, idx, zero_idx;
  ms = cloonix_get_msec();
  idx = ms % MAX_PERSEC_ELEMS;
  zero_idx = (ms - 1100) % MAX_PERSEC_ELEMS;
  for (i=0; i<100; i++)
    {
    j = zero_idx + i;
    if (j >= MAX_PERSEC_ELEMS)
      j -= MAX_PERSEC_ELEMS; 
    all_ctx->bytes_persec_cur -= all_ctx->bytes_persec_tab[j];
    all_ctx->bytes_persec_tab[j] = 0;  
    }
  all_ctx->bytes_persec_tab[idx] += len;
  all_ctx->bytes_persec_cur += len;
  pool_tx_put(&(all_ctx->tx_pool), elem, len);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void tx_unix_sock_shaping_timer(t_all_ctx *all_ctx)
{
  static int last_process_ms = 0;
  int i, j, ms, zero_idx;
  ms = cloonix_get_msec();
  if ((ms - last_process_ms) > 100)
    {
    zero_idx = (ms + 100) % MAX_PERSEC_ELEMS;
    for (i=0; i<850; i++)
      {
      j = zero_idx + i;
      if (j >= MAX_PERSEC_ELEMS)
        j -= MAX_PERSEC_ELEMS; 
      if (all_ctx->bytes_persec_tab[j])
        {
        all_ctx->bytes_persec_cur -= all_ctx->bytes_persec_tab[j];
        all_ctx->bytes_persec_tab[j] = 0;  
        }
      }
    last_process_ms = ms;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void tx_unix_sock_shaping_value(t_all_ctx *all_ctx, int kbytes_persec)
{
  all_ctx->bytes_persec_max = (long long int) kbytes_persec;
  all_ctx->bytes_persec_max *= 1000;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int tx_unix_sock_shaping_overload(t_all_ctx *all_ctx)
{
  int k, i, j, topms, lap[4], idx[4], ms[4], result = 0;
  long long int val[4], ref[4], max_ajusted;
  topms = cloonix_get_msec();
  ref[0] = (all_ctx->bytes_persec_max / 400);
  ref[1] = (all_ctx->bytes_persec_max / 17);
  ref[2] = (all_ctx->bytes_persec_max / 9);
  ref[3] = (all_ctx->bytes_persec_max / 4);
  lap[0] = 2;
  lap[1] = 5;
  lap[2] = 10;
  lap[3] = 20;
  for (k=0; k<4; k++)
    {
    ms[k]  = topms - lap[k];
    idx[k] = ms[k] % MAX_PERSEC_ELEMS;
    val[k] = 0;
    for (i=0; i<lap[k]; i++)
      {
      j = idx[k] + i;
      if (j >= MAX_PERSEC_ELEMS)
        j -= MAX_PERSEC_ELEMS;
      val[k] += all_ctx->bytes_persec_tab[j];
      }
    if (val[k] > ref[k])
      {
      KERR("%d %d %d", k, val[k], ref[k]);
      result = 1;
      break;
      }
    }
  if (!result)
    {
    max_ajusted = all_ctx->bytes_persec_max + (all_ctx->bytes_persec_max/10);
    if (all_ctx->bytes_persec_cur > max_ajusted)
      {
      KERR("%lld %lld", all_ctx->bytes_persec_cur,  all_ctx->bytes_persec_max);
      result = 1;
      }
    }
  return result;
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
void stop_tx_counter_increment(t_all_ctx *all_ctx, int idx)
{
  blkd_stop_tx_counter_increment((void *) all_ctx, 
                                 all_ctx->g_traf_endp[idx].llid_traf);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void mueth_main_endless_loop(t_all_ctx *all_ctx, char *net_name, 
                             char *name, int num, char *serv_path,
                             t_get_blkd_from_elem get_blkd_from_elem)
{
  blkd_set_our_mutype((void *) all_ctx, endp_type_kvm);
  all_ctx->get_blkd_from_elem = get_blkd_from_elem;
  strncpy(all_ctx->g_net_name, net_name, MAX_NAME_LEN-1);
  strncpy(all_ctx->g_name, name, MAX_NAME_LEN-1);
  all_ctx->g_num = num;
  strncpy(all_ctx->g_path, serv_path, MAX_PATH_LEN-1);
  sock_fd_init(all_ctx);
  all_ctx->bytes_persec_max = 1000*1000;
  all_ctx->bytes_persec_max *= 10000;
  msg_mngt_loop(all_ctx);
}
/*--------------------------------------------------------------------------*/

