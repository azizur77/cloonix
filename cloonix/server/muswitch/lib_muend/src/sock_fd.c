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
static void collect_eventfull(t_all_ctx *all_ctx, int idx, 
                              int *nb_pkt_tx, int *nb_bytes_tx,
                              int *nb_pkt_rx, int *nb_bytes_rx)
{
  *nb_pkt_tx = all_ctx->g_traf[idx].nb_pkt_tx;
  *nb_bytes_tx = all_ctx->g_traf[idx].nb_bytes_tx;
  *nb_pkt_rx = all_ctx->g_traf[idx].nb_pkt_rx;
  *nb_bytes_rx = all_ctx->g_traf[idx].nb_bytes_rx;
  all_ctx->g_traf[idx].nb_pkt_tx = 0;
  all_ctx->g_traf[idx].nb_bytes_tx = 0;
  all_ctx->g_traf[idx].nb_pkt_rx = 0;
  all_ctx->g_traf[idx].nb_bytes_rx = 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void eventfull_sat(t_all_ctx *all_ctx, int cloonix_llid, int idx)
{
  int nb_pkt_tx, nb_pkt_rx, nb_bytes_tx, nb_bytes_rx;
  char txt[2*MAX_NAME_LEN];
  collect_eventfull(all_ctx, idx, &nb_pkt_tx, &nb_bytes_tx, 
                                  &nb_pkt_rx, &nb_bytes_rx);
  if (nb_pkt_tx)
    {
    memset(txt, 0, 2*MAX_NAME_LEN);
    snprintf(txt, (2*MAX_NAME_LEN) - 1, "musat_eventfull_tx %u %d %d %d",
             cloonix_get_msec(), idx, nb_pkt_tx, nb_bytes_tx);
    rpct_send_evt_msg(all_ctx, cloonix_llid, 0, txt);
    }
  if (nb_pkt_rx)
    {
    memset(txt, 0, 2*MAX_NAME_LEN);
    snprintf(txt, (2*MAX_NAME_LEN) - 1, "musat_eventfull_rx %u %d %d %d",
             cloonix_get_msec(), idx, nb_pkt_rx, nb_bytes_rx);
    rpct_send_evt_msg(all_ctx, cloonix_llid, 0, txt);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void eventfull_qemu(t_all_ctx *all_ctx, int cloonix_llid)
{
  int eth, nb_pkt_tx, nb_pkt_rx, nb_bytes_tx, nb_bytes_rx;
  char txt[2*MAX_NAME_LEN];
  all_ctx->cb_collect_eventfull(all_ctx, &eth,
                                &nb_pkt_tx, &nb_bytes_tx,
                                &nb_pkt_rx, &nb_bytes_rx);
  if (nb_pkt_tx)
    {
    memset(txt, 0, 2*MAX_NAME_LEN);
    snprintf(txt, (2*MAX_NAME_LEN) - 1, "mueth_eventfull_tx %u %d %d %d",
             cloonix_get_msec(), eth, nb_pkt_tx, nb_bytes_tx);
    rpct_send_evt_msg(all_ctx, cloonix_llid, 0, txt);
    }
  if (nb_pkt_rx)
    {
    memset(txt, 0, 2*MAX_NAME_LEN);
    snprintf(txt, (2*MAX_NAME_LEN) - 1, "mueth_eventfull_rx %u %d %d %d",
             cloonix_get_msec(), eth, nb_pkt_rx, nb_bytes_rx);
    rpct_send_evt_msg(all_ctx, cloonix_llid, 0, txt);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void eventfull_can_be_sent(t_all_ctx *all_ctx, void *data)
{
  int i, llid = blkd_get_cloonix_llid((void *) all_ctx);
  int is_blkd, cidx = msg_exist_channel(all_ctx, llid, &is_blkd, __FUNCTION__);
  if (cidx)
    {
    if (all_ctx->qemu_mueth_state)
      {
      if ((all_ctx->g_traf[0].nb_pkt_tx) || (all_ctx->g_traf[0].nb_pkt_rx))
        eventfull_qemu(all_ctx, llid);
      }
    else
      {
      for (i=0; i<2; i++)
        {
        if ((all_ctx->g_traf[i].nb_pkt_tx) || (all_ctx->g_traf[i].nb_pkt_rx))
          eventfull_sat(all_ctx, llid, i);
        }
      }
    }
  clownix_timeout_add(all_ctx, 5, eventfull_can_be_sent, NULL, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void main_tx_arrival(t_all_ctx *all_ctx, int idx, int nb_pkt, int nb_bytes)
{
  all_ctx->g_traf[idx].nb_pkt_tx += nb_pkt;
  all_ctx->g_traf[idx].nb_bytes_tx += nb_bytes;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void main_rx_arrival(t_all_ctx *all_ctx, int idx, int nb_pkt, int nb_bytes)
{
  all_ctx->g_traf[idx].nb_pkt_rx += nb_pkt;
  all_ctx->g_traf[idx].nb_bytes_rx += nb_bytes;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void rx0_blkd_sock_cb(void *ptr, int llid)
{
  t_all_ctx *all_ctx = (t_all_ctx *) ptr;
  t_blkd *blkd;
  if (all_ctx->qemu_mueth_state)
    {
    if (all_ctx->g_nb_elem_rx_ready == 0)
      all_ctx->g_cb_prepare_rx_packet(all_ctx, &all_ctx->g_nb_elem_rx_ready);
    if (all_ctx->g_nb_elem_rx_ready)
      {
      blkd = blkd_get_rx(ptr, llid);
      while(blkd)
        {
        all_ctx->g_cb_rx_packet(all_ctx, 0,
                                  (uint32_t) blkd->payload_len,
                                  (uint8_t *) blkd->payload_blkd);
        all_ctx->g_nb_elem_rx_ready -= 1;
        blkd_free(ptr, blkd);
        blkd = NULL;
        if (!all_ctx->g_nb_elem_rx_ready)
          all_ctx->g_cb_prepare_rx_packet(all_ctx,&all_ctx->g_nb_elem_rx_ready);
        if (all_ctx->g_nb_elem_rx_ready)
          blkd = blkd_get_rx(ptr, llid);
        }
      }
    }
  else
    {  
    blkd = blkd_get_rx(ptr, llid);
    if (!blkd)
      KERR(" ");
    else
      {
      while(blkd)
        {
        main_rx_arrival(all_ctx, 0, 1, blkd->payload_len);
        rx_from_traffic_sock(all_ctx, 0, blkd);
        blkd = blkd_get_rx(ptr, llid);
        }
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void rx1_blkd_sock_cb(void *ptr, int llid)
{
  t_all_ctx *all_ctx = (t_all_ctx *) ptr;
  t_blkd *blkd = blkd_get_rx(ptr, llid);
  if (!blkd)
    KERR(" ");
  else
    {
    while(blkd)
      {
      main_rx_arrival(all_ctx, 1, 1, blkd->payload_len);
      rx_from_traffic_sock(all_ctx, 1, blkd);
      blkd = blkd_get_rx(ptr, llid);
      }
    }
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static void err0_sock_cb(void *ptr, int llid, int err, int from)
{
  sock_fd_finish((t_all_ctx *) ptr, 0);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void err1_sock_cb(void *ptr, int llid, int err, int from)
{
  sock_fd_finish((t_all_ctx *) ptr, 1);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void sock_fd_tx(t_all_ctx *all_ctx, int idx, t_blkd *blkd)
{ 
  int tx_queued, rx_queued;
  int llid = all_ctx->g_traf[idx].llid_traf;
  int is_blkd, cidx = msg_exist_channel(all_ctx, llid, &is_blkd, __FUNCTION__);
  if (cidx)
    {
    if ((blkd->payload_len >= PAYLOAD_BLKD_SIZE) ||
        (blkd->payload_len <=0))
      {
      KERR("%d %d", (int) PAYLOAD_BLKD_SIZE, blkd->payload_len);
      blkd_free((void *) all_ctx, blkd);
      }
    else
      {
      main_tx_arrival(all_ctx, idx, 1, blkd->payload_len);
      blkd_put_tx((void *) all_ctx, 1, &llid, blkd);
      }
    if (idx == 0)
      {
      blkd_get_tx_rx_queues((void *) all_ctx, llid, &tx_queued, &rx_queued);
      all_ctx->g_tx_queue_len_unix_sock = tx_queued;
      }
    }
  else
    blkd_free((void *) all_ctx, blkd);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int sock_fd_open(t_all_ctx *all_ctx, char *lan, int idx, char *path)
{
  int llid, result = -1;

  if (all_ctx->qemu_mueth_state)
    pool_tx_init(&(all_ctx->tx_pool));
  if (idx == 0)
    llid = blkd_client_connect((void *) all_ctx, lan, path, rx0_blkd_sock_cb, 
                                                             err0_sock_cb);
  else
    llid = blkd_client_connect((void *) all_ctx, lan, path, rx1_blkd_sock_cb, 
                                                             err1_sock_cb);
  if (llid <= 0)
    KERR("Bad connection to %s", path);
  else
    {
    all_ctx->g_traf[idx].llid_traf = llid;
    result = 0;
    if (all_ctx->g_cb_client_cmd)
      all_ctx->g_cb_client_cmd(all_ctx, 0,
                                "local_command_connection_eth_req", NULL);
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sock_fd_finish(t_all_ctx *all_ctx, int idx)
{
  t_traf_sat *traf = &(all_ctx->g_traf[idx]);
  int is_blkd, cidx, llid;
  llid = traf->llid_traf;
  if (llid)
    {
    cidx = msg_exist_channel(all_ctx, llid, &is_blkd, __FUNCTION__);
    if (cidx)
      msg_delete_channel(all_ctx, llid);
     }
  traf->llid_traf = 0;
  llid = traf->llid_lan;
  if (llid)
    {
    cidx = msg_exist_channel(all_ctx, llid, &is_blkd, __FUNCTION__);
    if (cidx)
      msg_delete_channel(all_ctx, llid);
    }
  traf->llid_lan = 0;
  if (all_ctx->g_cb_client_cmd)
    {
    all_ctx->g_cb_client_cmd(all_ctx, 0,
                           "local_command_disconnection_eth_req", NULL);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void rx_cloonix_cb(t_all_ctx *all_ctx, int llid, int len, char *buf)
{
  if (rpct_decoder(all_ctx, llid, len, buf))
    {
    KOUT("%s", buf);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void cloonix_err_cb(void *ptr, int llid, int err, int from)
{
  exit(0);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void cloonix_connect(void *ptr, int llid, int llid_new)
{
  t_all_ctx *all_ctx = (t_all_ctx *) ptr;
  int cloonix_llid = blkd_get_cloonix_llid(ptr);
  if (!cloonix_llid)
    blkd_set_cloonix_llid(ptr, llid_new);
  msg_mngt_set_callbacks (all_ctx, llid_new, cloonix_err_cb, rx_cloonix_cb);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timeout_rpct_heartbeat(t_all_ctx *all_ctx, void *data)
{
  rpct_heartbeat((void *) all_ctx);
  clownix_timeout_add(all_ctx, 100, timeout_rpct_heartbeat, NULL, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timeout_blkd_heartbeat(t_all_ctx *all_ctx, void *data)
{
  blkd_heartbeat((void *) all_ctx);
  clownix_timeout_add(all_ctx, 1, timeout_blkd_heartbeat, NULL, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sock_fd_local_flow_control(t_all_ctx *all_ctx, int stop)
{
  t_traf_sat *traf0 = &(all_ctx->g_traf[0]);
  t_traf_sat *traf1 = &(all_ctx->g_traf[1]);
  if ((traf0->llid_traf) && (!traf1->llid_traf))
    blkd_rx_local_flow_control((void *) all_ctx, traf0->llid_traf, stop);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sock_fd_init(t_all_ctx *all_ctx)
{
  if (string_server_unix(all_ctx, all_ctx->g_path, cloonix_connect) == 0)
    KOUT("PROBLEM WITH: %s", all_ctx->g_path);
  clownix_timeout_add(all_ctx, 500, eventfull_can_be_sent, NULL, NULL, NULL);
  clownix_timeout_add(all_ctx, 100, timeout_rpct_heartbeat, NULL, NULL, NULL);
  clownix_timeout_add(all_ctx, 100, timeout_blkd_heartbeat, NULL, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

