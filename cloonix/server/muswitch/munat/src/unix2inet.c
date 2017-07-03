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
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>


#include "ioc.h"
#include "clo_tcp.h"
#include "main.h"
#include "machine.h"
#include "utils.h"
#include "packets_io.h"

#define OFFSET_PORT 30000
#define MAX_INFO_LEN 200

enum {
  state_none = 0,
  state_wait_info,
  state_wait_arp_resp,
  state_wait_syn_ack,
  state_running,
};

typedef struct t_ctx_unix2inet
{
  int state;
  t_all_ctx *all_ctx;
  char remote_user[MAX_NAME_LEN];
  char remote_ip[MAX_NAME_LEN];
  uint16_t remote_port;
  int payload_len;
  u8_t payload[TCP_MAX_SIZE];
  long long timeout_abs_beat;
  int timeout_ref;
  t_tcp_id tcpid;
} t_ctx_unix2inet;

static t_ctx_unix2inet *llid_to_ctx[CLOWNIX_MAX_CHANNELS];

typedef struct t_waiting_for_arp
{
  char ip[MAX_NAME_LEN];
  int llid;
  uint16_t port;
  struct t_waiting_for_arp *prev;
  struct t_waiting_for_arp *next;
} t_waiting_for_arp;

typedef struct t_timeout_info
{
  int llid;
  char ip[MAX_NAME_LEN];
} t_timeout_info;

static t_waiting_for_arp *g_head_waiting_for_arp;
static int free_ctx_waiting_for_arp_resp(char *ip, int *llid, uint16_t *port);
static t_ctx_unix2inet *find_ctx(int llid);
static void free_ctx(t_all_ctx *all_ctx, int llid);


/*****************************************************************************/
static void timeout_waiting_for_arp(t_all_ctx *all_ctx, void *data)
{
  t_timeout_info *ti = (t_timeout_info *) data;
  t_ctx_unix2inet *ctx;
  int llid;
  uint16_t port;
  if (free_ctx_waiting_for_arp_resp(ti->ip, &llid, &port))
    KERR("%s", ti->ip);
  else
    {
    KERR("TIMEOUT WAIT ARP %s %d", ti->ip, port);
    ctx = find_ctx(ti->llid);
    if (!ctx)
      KERR("%s %d", ti->ip, port);
    else
      free_ctx(all_ctx, ti->llid);
    }
  free(ti);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int arm_timeout_waiting_for_arp(t_all_ctx *all_ctx, 
                                       t_ctx_unix2inet *ctx, int llid)
{
  int result = -1;
  t_timeout_info *ti;
  if ((ctx->timeout_abs_beat == 0) && (ctx->timeout_ref == 0)) 
    {
    ti = (t_timeout_info *) malloc(sizeof(t_timeout_info));
    memset(ti, 0, sizeof(t_timeout_info));
    ti->llid = llid;
    strncpy(ti->ip, ctx->remote_ip, MAX_NAME_LEN);
    clownix_timeout_add(all_ctx, 50, timeout_waiting_for_arp, (void *) ti,
                        &(ctx->timeout_abs_beat), &(ctx->timeout_ref));
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/



/*****************************************************************************/
static int alloc_ctx_waiting_for_arp(t_all_ctx *all_ctx, 
                                     t_ctx_unix2inet *ctx, int llid)
{
  int result = -1;
  t_waiting_for_arp *cur;
  if (!arm_timeout_waiting_for_arp(all_ctx, ctx, llid))
    {
    cur = (t_waiting_for_arp *) malloc(sizeof(t_waiting_for_arp));
    memset(cur, 0, sizeof(t_waiting_for_arp));
    strncpy(cur->ip, ctx->remote_ip, MAX_NAME_LEN-1);
    cur->llid = llid;
    cur->port = ctx->remote_port;
    cur->next = g_head_waiting_for_arp;
    if (g_head_waiting_for_arp)
      g_head_waiting_for_arp->prev = cur;
    g_head_waiting_for_arp = cur;
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int free_ctx_waiting_for_arp_resp(char *ip, int *llid, uint16_t *port)
{
  int result = -1;
  t_waiting_for_arp *cur = g_head_waiting_for_arp;
  while(cur)
    {
    if (!strcmp(cur->ip, ip))
      break;
    cur = cur->next;
    } 
  if (cur)
    {
    *llid = cur->llid;
    *port = cur->port;
    result = 0;
    if (cur->prev)
      cur->prev->next = cur->next;
    if (cur->next)
      cur->next->prev = cur->prev;
    if (cur == g_head_waiting_for_arp)
      g_head_waiting_for_arp = cur->next;
    free(cur);
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_ctx_unix2inet *find_ctx(int llid)
{
  if ((llid <= 0) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  return (llid_to_ctx[llid]);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_ctx_unix2inet *alloc_ctx(t_all_ctx *all_ctx, int llid)
{
  t_ctx_unix2inet *ctx = (t_ctx_unix2inet *) malloc(sizeof(t_ctx_unix2inet));
  if ((llid <= 0) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  KERR("%s %d", __FUNCTION__, llid);
  memset(ctx, 0, sizeof(t_ctx_unix2inet));
  ctx->all_ctx = all_ctx;
  llid_to_ctx[llid] = ctx;
  return ctx;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void free_ctx(t_all_ctx *all_ctx, int llid)
{
  t_ctx_unix2inet *ctx = find_ctx(llid);
  int is_blkd;
  if ((llid <= 0) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  KERR("%s %d", __FUNCTION__, llid);
  if (!ctx)
    KERR("%d", llid);
  else
    {
    free(ctx);
    llid_to_ctx[llid] = 0;
    }
  if (msg_exist_channel(all_ctx, llid, &is_blkd, __FUNCTION__))
    msg_delete_channel(all_ctx, llid);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void change_state(t_ctx_unix2inet *ctx, int state)
{
  KERR("STATE: %d -> %d", ctx->state, state);
  ctx->state = state;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int tcpid_are_the_same(t_tcp_id *id1, t_tcp_id *id2)
{
  int i, result = 1;
  for (i=0; i<MAC_ADDR_LEN; i++)
    {
    if ((((int) id1->local_mac[i]) & 0xFF) != (id2->local_mac[i] & 0xFF))
      result = 0;
    if ((((int) id1->remote_mac[i]) & 0xFF) != (id2->remote_mac[i] & 0xFF))
      result = 0;
    }
  if ((id1->local_ip    != id2->local_ip)   ||
      (id1->remote_ip   != id2->remote_ip)  ||
      (id1->local_port  != id2->local_port) ||
      (id1->remote_port != id2->remote_port))
    result = 0;
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void unix2inet_init_tcp_id(t_tcp_id *tcpid, 
                              char *remote_mac_ascii, char *remote_ip, 
                              int llid, uint16_t remote_port)
{
  int i;
  int local_mac[MAC_ADDR_LEN];
  int remote_mac[MAC_ADDR_LEN];
  memset(tcpid, 0, sizeof(t_tcp_id));
  if (sscanf(OUR_MAC_CISCO, "%02X:%02X:%02X:%02X:%02X:%02X",
             &(local_mac[0]), &(local_mac[1]),
             &(local_mac[2]), &(local_mac[3]),
             &(local_mac[4]), &(local_mac[5])) != 6)
    KOUT(" ");
  if (sscanf(remote_mac_ascii, "%02X:%02X:%02X:%02X:%02X:%02X",
             &(remote_mac[0]), &(remote_mac[1]),
             &(remote_mac[2]), &(remote_mac[3]),
             &(remote_mac[4]), &(remote_mac[5])) != 6)
    KOUT(" ");
  if (ip_string_to_int (&(tcpid->local_ip), get_unix2inet_ip()))
    KOUT(" ");
  if (ip_string_to_int (&(tcpid->remote_ip), remote_ip))
    KOUT(" ");
  for (i=0; i<MAC_ADDR_LEN; i++)
    {
    tcpid->local_mac[i]  = local_mac[i] & 0xFF;
    tcpid->remote_mac[i] = remote_mac[i] & 0xFF;
    }
  tcpid->local_port  = OFFSET_PORT + llid;
  tcpid->remote_port = remote_port;
}
/*---------------------------------------------------------------------------*/

#define CLOONIX_INFO "user %s ip %s port %d "

/*****************************************************************************/
static int get_info_from_buf(t_ctx_unix2inet *ctx, int len, char *ibuf)
{
  int port, result = -1;
  char *ptr;
  char *buf = (char *) malloc(len);
  memcpy(buf, ibuf, len);
  if (len >= TCP_MAX_SIZE)
    KERR("%d %s %d", len, buf, TCP_MAX_SIZE); 
  else
    {
    ptr = strchr(buf, '=');
    while (ptr)
      {
      *ptr = ' ';
      ptr = strchr(buf, '=');
      }
    ptr = (strstr(buf, "cloonix_info_end"));
    if (!(ptr))
      KERR("%d %s", len, buf); 
    else
      {
      *ptr = 0;
      if (sscanf(buf,CLOONIX_INFO,ctx->remote_user,ctx->remote_ip,&port) != 3)
        KERR("%d %s", len, buf); 
      else
        {
        ctx->remote_port = (port & 0xFFFF);
        ptr = ptr + strlen("cloonix_info_end");
        ctx->payload_len = len - (ptr - buf);
        if ((ctx->payload_len < 1) || (ctx->payload_len >= TCP_MAX_SIZE)) 
          KOUT("%d %s %d %d", len, buf, TCP_MAX_SIZE, ctx->payload_len); 
        memcpy(ctx->payload, ptr, ctx->payload_len);
        result = 0;
        }
      }
    }
  free(buf);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int send_first_tcp_syn(t_ctx_unix2inet *ctx, int llid,
                              char *remote_mac, char *remote_ip,
                              uint16_t remote_port)
{
  int result = -1;
  t_clo *clo;
  unix2inet_init_tcp_id(&(ctx->tcpid),remote_mac,remote_ip,llid,remote_port);
  if (clo_high_syn_tx(&(ctx->tcpid)))
    {
    KERR(" ");
    free_ctx(ctx->all_ctx, llid);
    }
  else
    {
    clo = util_get_fast_clo(&(ctx->tcpid));
    if (clo)
      {
      util_attach_llid_clo(llid, clo);
      clo->tcpid.llid_unlocked = 1;
      result = 0;
      }
    else
      {
      KERR(" ");
      free_ctx(ctx->all_ctx, llid);
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void request_mac_with_ip(char *remote_ip)
{
  int resp_len;
  char *resp_data;
  resp_len = format_arp_req(get_unix2inet_ip(), remote_ip, &resp_data);
  packet_output_to_slirptux(resp_len, resp_data);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void unix2inet_ssh_rx_cb(t_all_ctx *all_ctx, int llid, 
                                int len, char *buf)
{
  int is_blkd;
  void *ptr = (void *) all_ctx;
  t_ctx_unix2inet *ctx = find_ctx(llid);
  if (!ctx)
    {
    KERR("%d", llid);
    if (msg_exist_channel(all_ctx, llid, &is_blkd, __FUNCTION__))
      msg_delete_channel(all_ctx, llid);
    DOUT(ptr, FLAG_HOP_APP, "%s NO CTX", __FUNCTION__);
    }
  else
    {
    DOUT(ptr, FLAG_HOP_APP, "%s CTX STATE:%d", __FUNCTION__, ctx->state);
    if (ctx->state == state_wait_info) 
      {
      if (get_info_from_buf(ctx, len, buf)) 
        {
        KERR("%s", buf);
        free_ctx(all_ctx, llid);
        }
      else
        {
        if (alloc_ctx_waiting_for_arp(all_ctx, ctx, llid))
          {
          KERR("%s", buf);
          free_ctx(all_ctx, llid);
          }
        else
          {
          DOUT(ptr, FLAG_HOP_APP, "%s REMOTE:%s %d", __FUNCTION__, 
                                  ctx->remote_ip, ctx->remote_port);
          request_mac_with_ip(ctx->remote_ip);
          change_state(ctx, state_wait_arp_resp);
          }
        }
      }
    else if (ctx->state != state_running) 
      {
      KERR(" ");
      free_ctx(all_ctx, llid);
      DOUT(ptr, FLAG_HOP_APP, "%s NO RUNNING", __FUNCTION__);
      }
    else
      {
      DOUT(ptr, FLAG_HOP_APP, "%s DATA OF LEN: %d", __FUNCTION__, len);
      if (clo_high_data_tx(&(ctx->tcpid), len, (u8_t *) buf))
        KERR("%s %s", ctx->remote_user, ctx->remote_ip);
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void unix2inet_ssh_err_cb(void *ptr, int llid, int err, int from)
{
  t_all_ctx *all_ctx = (t_all_ctx *) ptr;
  KERR("OPENSSH CLOSED");
  free_ctx(all_ctx, llid);
  DOUT(ptr, FLAG_HOP_APP, "%s", __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void unix2inet_ssh_connect(void *ptr, int llid, int llid_new)
{
  t_all_ctx *all_ctx = (t_all_ctx *) ptr;
  t_ctx_unix2inet *ctx = find_ctx(llid_new);
  if (ctx)
    KOUT(" ");
  ctx = alloc_ctx(all_ctx, llid_new);
  change_state(ctx, state_wait_info);
  msg_mngt_set_callbacks(all_ctx, llid_new,unix2inet_ssh_err_cb,
                                  unix2inet_ssh_rx_cb);
  DOUT(ptr, FLAG_HOP_APP, "%s", __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void unix2inet_arp_resp(char *mac, char *ip)
{
  int llid;
  uint16_t port;
  t_ctx_unix2inet *ctx;
  void *ti;
  if (free_ctx_waiting_for_arp_resp(ip, &llid, &port))
    KERR("%s %s", mac, ip);
  else
    {
    ctx = find_ctx(llid);
    if (!ctx)
      KERR("%s %d %s", ip, port, mac);
    else
      {
      ti = clownix_timeout_del(ctx->all_ctx, ctx->timeout_abs_beat, 
                               ctx->timeout_ref, __FILE__, __LINE__);
      free(ti);
      if (send_first_tcp_syn(ctx, llid, mac, ip, port))
        KERR("%s %d %s", ip, port, mac);
      else
        change_state(ctx, state_wait_syn_ack);
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int unix2inet_ssh_syn_ack_arrival(t_tcp_id *tcpid)
{
  int llid, result = -1;
  t_ctx_unix2inet *ctx;
  t_clo *clo;
  if (!tcpid)
    KOUT(" ");
  clo = util_get_fast_clo(tcpid);
  llid = tcpid->local_port - OFFSET_PORT;
  if ((llid <= 0) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  ctx = find_ctx(llid);
  if (!ctx)
    KERR("%d", llid);
  else if (!tcpid_are_the_same(tcpid, &(ctx->tcpid))) 
    KERR("%d", llid);
  else if (!clo)
    KERR("%d", llid);
  else if (clo->tcpid.llid != llid)
    KERR("%d %d", llid, clo->tcpid.llid);
  else if (ctx->state != state_wait_syn_ack) 
    KERR("%d %d", llid, ctx->state);
  else
    {
    if (ctx->payload_len == 0)
      KERR("%d %s", ctx->state, (char *) ctx->payload);
    else
      { 
      if (clo_high_data_tx(&(ctx->tcpid), ctx->payload_len, ctx->payload))
        KERR("%d %d %s", ctx->state, ctx->payload_len, (char *) ctx->payload);
      else
        {  
        ctx->payload_len = 0;
        change_state(ctx, state_running);
        result = 0;
        }
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void unix2inet_close_tcpid(t_tcp_id *tcpid)
{
  int llid, i, local_mac[MAC_ADDR_LEN];
  t_ctx_unix2inet *ctx;
  uint32_t addr;
  int our_concern = 1;
  if (sscanf(OUR_MAC_CISCO, "%02X:%02X:%02X:%02X:%02X:%02X",
             &(local_mac[0]), &(local_mac[1]),
             &(local_mac[2]), &(local_mac[3]), 
             &(local_mac[4]), &(local_mac[5])) != 6)
    KOUT(" ");
  if (ip_string_to_int (&(addr), get_unix2inet_ip()))
    KOUT(" ");
  if (tcpid->local_ip != addr)
    our_concern = 0;
  for (i=0; i<MAC_ADDR_LEN; i++)
    {
    if (tcpid->local_mac[i] != (local_mac[i] & 0xFF))
      our_concern = 0;
    }
  if (our_concern)
    {
    llid = tcpid->local_port - OFFSET_PORT;
    if ((llid <= 0) || (llid >= CLOWNIX_MAX_CHANNELS))
      KOUT("%d", llid);
    ctx = find_ctx(llid);
    if (ctx)
      {
      if (!tcpid_are_the_same(tcpid, &(ctx->tcpid)))
        KERR("%d", llid);
      else
        free_ctx(ctx->all_ctx, llid);
      }
    }
}
/*---------------------------------------------------------------------------*/



/*****************************************************************************/
void unix2inet_init(t_all_ctx *all_ctx)
{
  char tcp_path[MAX_PATH_LEN];
  void *ptr = (void *) all_ctx;
  memset(llid_to_ctx, 0, CLOWNIX_MAX_CHANNELS * sizeof(t_ctx_unix2inet *));
  if ((strlen(all_ctx->g_path) + 10) > MAX_PATH_LEN) 
    KOUT("%s", all_ctx->g_path);
  sprintf(tcp_path, "%s_u2i", all_ctx->g_path);
  if (rawdata_server_unix(all_ctx, tcp_path, unix2inet_ssh_connect) == 0)
    KOUT("PROBLEM %s", tcp_path);
  DOUT(ptr, FLAG_HOP_APP, "%s %s", __FUNCTION__, tcp_path);
}
/*--------------------------------------------------------------------------*/

