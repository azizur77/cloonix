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
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "cfg_store.h"
#include "utils_cmd_line_maker.h"
#include "llid_trace.h"
#include "mulan_mngt.h"
#include "mueth_mngt.h"
#include "mueth_events.h"
#include "hop_event.h"
#include "stats_counters.h"

void uml_clownix_switch_error_cb(void *ptr, int llid, int err, int from);
void uml_clownix_switch_rx_cb(int llid, int len, char *buf);
void murpc_dispatch_send_tx_flow_control(int llid, int rank, int stop);


/****************************************************************************/
typedef struct t_muswitch_connect
{
  char name[MAX_NAME_LEN];
  int  eth;
  char lan[MAX_NAME_LEN];
  char muswitch_sock[MAX_PATH_LEN];
} t_muswitch_connect;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
typedef struct t_mueth_timer
{
  char name[MAX_NAME_LEN];
  int eth;
} t_mueth_timer;
/*--------------------------------------------------------------------------*/


/****************************************************************************/
typedef struct t_mueth_qemu
{
  char name[MAX_NAME_LEN];
  char sock[MAX_PATH_LEN];
  int eth;
  int pid;
  int llid;
  int waiting_resp;
  int destroy_timer_on;
  char waiting_resp_txt[MAX_NAME_LEN];
  int periodic_count;
  struct t_mueth_qemu *prev;
  struct t_mueth_qemu *next;
} t_mueth_qemu;
/*--------------------------------------------------------------------------*/

static t_mueth_qemu *g_head_mueth_qemu;


/****************************************************************************/
static int try_send_mueth(t_mueth_qemu *mu, char *msg)
{
  int result = -1;
  if (mu->llid)
    {
    if (msg_exist_channel(mu->llid))
      {
      hop_event_hook(mu->llid, FLAG_HOP_DIAG, msg);
      rpct_send_diag_msg(NULL, mu->llid, mu->pid, msg);
      result = 0;
      }
    else
      KERR("%s %d", mu->name, mu->eth);
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int trace_alloc(t_mueth_qemu *mu)
{
  char *sock = mu->sock;
  char *name = mu->name;
  int llid;
  llid = string_client_unix(sock, uml_clownix_switch_error_cb, 
                                  uml_clownix_switch_rx_cb, "mueth");
  if (llid)
    {
    if (hop_event_alloc(llid, type_hop_mueth, mu->name, mu->eth))
      KERR("%s eth%d", mu->name, mu->eth);
    llid_trace_alloc(llid, name, 0, 0, type_llid_trace_musat_eth);
    }
  else
    KERR("%s eth%d  %s", mu->name, mu->eth, sock);
  return llid;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_mueth_qemu *mueth_find_with_name(char *name, int eth)
{
  t_mueth_qemu *cur = g_head_mueth_qemu;
  while(cur && ((strcmp(cur->name, name)) || (cur->eth != eth)))
    cur = cur->next;
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_mueth_qemu *mueth_find_with_llid(int llid)
{
  t_mueth_qemu *cur = g_head_mueth_qemu;
  if ((llid <1) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  while(cur && (cur->llid != llid))
    cur = cur->next;
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mueth_get_all_llid(int **llid_tab)
{
  t_mueth_qemu *cur = g_head_mueth_qemu;
  int i, result = 0;
  *llid_tab = NULL;
  while(cur)
    {
    if (cur->llid)
      result++;
    cur = cur->next;
    }
  if (result)
    {
    *llid_tab = (int *)clownix_malloc(result * sizeof(int), 5);
    memset((*llid_tab), 0, result * sizeof(int));
    cur = g_head_mueth_qemu;
    i = 0;
    while(cur)
      {
      if (cur->llid)
        (*llid_tab)[i++] = cur->llid;
      cur = cur->next;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
int mueth_can_be_found_with_llid(int llid, char *name, int *eth)
{
  t_mueth_qemu *cur = g_head_mueth_qemu;
  memset(name, 0, MAX_NAME_LEN);
  if ((llid <1) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  while(cur && (cur->llid != llid))
    cur = cur->next;
  if (cur)
    {
    strncpy(name, cur->name, MAX_NAME_LEN-1);
    *eth = cur->eth;
    return 1;
    }
  else
    return 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mueth_can_be_found_with_name(char *name, int eth)
{
  int result = 0;
  t_mueth_qemu *cur = mueth_find_with_name(name, eth);
  if (cur)
    {
    if (msg_exist_channel(cur->llid))
      result = cur->llid;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_mueth_qemu *mueth_alloc(char *name, int eth, t_vm *vm) 
{
  t_mueth_qemu *mu;
  mu = (t_mueth_qemu *) clownix_malloc(sizeof(t_mueth_qemu), 4);
  memset(mu, 0, sizeof(t_mueth_qemu));
  strncpy(mu->name, name, MAX_NAME_LEN-1);
  strncpy(mu->sock, utils_get_mueth_path(vm->vm_id, eth), MAX_PATH_LEN-1);
  mu->eth = eth;
  if (g_head_mueth_qemu)
    g_head_mueth_qemu->prev = mu;
  mu->next = g_head_mueth_qemu;
  g_head_mueth_qemu = mu; 
  return mu;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_mueth_free(void *data)
{
  t_mueth_timer *mt = (t_mueth_timer *) data;
  t_mueth_qemu *mu = mueth_find_with_name(mt->name, mt->eth);
  if (!mu)
    KERR("%s %d", mt->name, mt->eth);
  else
    {
    if (mu->prev)
      mu->prev->next = mu->next;
    if (mu->next)
      mu->next->prev = mu->prev;
    if (mu == g_head_mueth_qemu)
      g_head_mueth_qemu = mu->next;
    mueth_event_death(mu->name, mu->eth);
    if (mu->llid)
      llid_trace_free(mu->llid, 0, __FUNCTION__);
    clownix_free(mu, __FUNCTION__);
    }
  clownix_free(mt, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void mueth_free(t_mueth_qemu *mu)
{
  t_mueth_timer *mt;
  if (mu->destroy_timer_on == 0)
    {
    mu->destroy_timer_on = 1;
    mt = (t_mueth_timer *) clownix_malloc(sizeof(t_mueth_timer), 5);
    memset(mt, 0, sizeof(t_mueth_timer));
    strncpy(mt->name, mu->name, MAX_NAME_LEN-1);
    mt->eth = mu->eth; 
    clownix_timeout_add(100, timer_mueth_free, (void *) mt, NULL, NULL);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_muswitch_connect(void *data)
{
  char cmd[2*MAX_PATH_LEN];
  t_muswitch_connect *mc = ( t_muswitch_connect *) data;
  t_mueth_qemu *mu;
  if (!mc)
    KOUT(" ");
  mu = mueth_find_with_name(mc->name, mc->eth);
  if (!mu)
    KERR("%s %s %d", mc->name, mc->lan, mc->eth);
  else
    {
    memset(cmd, 0, 2*MAX_PATH_LEN);
    snprintf(cmd, 2*MAX_PATH_LEN-1, 
             "cloonix_req_connect sock=%s lan=%s sat=%s num=%d", 
             mc->muswitch_sock, mc->lan, 
             utils_get_mueth_name(mc->name, mc->eth), mc->eth);
    if (try_send_mueth(mu, cmd))
      {
      mu->waiting_resp = 0;
      memset(mu->waiting_resp_txt, 0, MAX_NAME_LEN);
      KERR("%s %s %s %d", mc->name,mc->lan,mc->muswitch_sock,mc->eth);
      }
    }
  clownix_free(data, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void mueth_eventfull_update_tx(t_vm *vm, int eth, unsigned int ms,
                                      int pkt, int bytes) 
{
  t_eth *cur = vm->eth_head;
  while(cur)
    {
    if (cur->eth == eth)
      break;
    cur = cur->next;
    }
  if (cur)
    {
    stats_counters_update_eth_tx(cur, ms, pkt, bytes);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void mueth_eventfull_update_rx(t_vm *vm, int eth, unsigned int ms,
                                      int pkt, int bytes)   
{
  t_eth *cur = vm->eth_head;
  while(cur)
    {
    if (cur->eth == eth)
      break;
    cur = cur->next;
    }
  if (cur)
    {
    stats_counters_update_eth_rx(cur, ms, pkt, bytes);
    }
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
void mueth_pid_resp(int llid, char *name, int pid)
{
  int vm_pid;
  t_mueth_qemu *mueth = mueth_find_with_llid(llid);
  t_vm *vm = cfg_get_vm(name);
  if ((!vm) || (!mueth))
    KERR("%s %d", name, pid);
  else if (strcmp(name,  mueth->name))
    KERR("%s %s", name, mueth->name);
  else
    {
    vm_pid = utils_get_pid_of_machine(vm);
    if (mueth->pid == 0)
      {
      if (vm_pid != pid)
        KERR("WRONG PID %s %d %d", name, pid, vm_pid);
      else
        {
        mueth->pid = pid;
        mueth_event_birth(mueth->name, mueth->eth);
        }
      }
    else
      {
      if (mueth->pid != pid)
        KERR("%s %d %d", name, pid, mueth->pid);
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int llid_flow_to_restrict(char *name)
{
  int llid = mulan_can_be_found_with_name(name);
  return llid;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_rpct_recv_evt_msg(int llid, int tid, char *line)
{
  int peer_llid, pkt, bytes, eth, rank, stop;
  unsigned int ms;
  t_mueth_qemu *mu = mueth_find_with_llid(llid);
  char nm[MAX_NAME_LEN];
  t_vm *vm;
  if (mu)
    {
    vm = cfg_get_vm(mu->name);
    if (!vm)
      KERR("%s", mu->name);
    else
      {
      if (sscanf(line, "cloonix_evt_peer_flow_control=%s rank=%d stop=%d",
                       nm, &rank, &stop) == 3)
        {
        peer_llid = llid_flow_to_restrict(nm);
        if (peer_llid)
          murpc_dispatch_send_tx_flow_control(peer_llid, rank, stop);
        else
          KERR("%s", nm);
        }
      else if (sscanf(line, "mueth_eventfull_tx %u %d %d %d", 
                       &ms, &eth, &pkt, &bytes) == 4)
        {
        mueth_eventfull_update_tx(vm, eth, ms, pkt, bytes);
        }
      else if (sscanf(line, "mueth_eventfull_rx %u %d %d %d", 
                            &ms, &eth, &pkt, &bytes) == 4)
        {
        mueth_eventfull_update_rx(vm, eth, ms, pkt, bytes);
        }
      else
        KERR("%s %s", mu->name, line);
      }
    } 
  else
    KOUT("%s", line);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_rpct_recv_diag_msg(int llid, int tid, char *line)
{
  t_mueth_qemu *mu = mueth_find_with_llid(llid);
  char lan[MAX_NAME_LEN];
  char sat[MAX_NAME_LEN];
  t_vm *vm;
  int num, rank;
  if (mu)
    {
    vm = cfg_get_vm(mu->name);
    if (!vm)
      KERR("%s", mu->name);
    else
      {
      if (sscanf(line, 
                 "cloonix_resp_connect_ok lan=%s sat=%s num=%d rank=%d", 
                 lan, sat,  &num, &rank) == 4)
        {
        if (strcmp(mu->waiting_resp_txt, "unix_sock"))
          KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
        if (strcmp(utils_get_mueth_name(mu->name, mu->eth), sat))
          KERR("%s %s %d", sat, mu->name, mu->eth);
        if (mu->eth != num)
          KERR("%d %d", mu->eth, num);
        mueth_event_connect_OK(mu->name, mu->eth, lan, rank);
        }
      else if  (sscanf(line,
                       "cloonix_resp_disconnect_ok lan=%s sat=%s num=%d",
                       lan, sat,  &num) == 3)
        {
        if (strcmp(utils_get_mueth_name(mu->name, mu->eth), sat))
          KERR("%s %s %s %d", utils_get_mueth_name(mu->name, mu->eth),
                              sat, mu->name, mu->eth);
        if (mu->eth != num)
          KERR("%d %d", mu->eth, num);
        if (strcmp(mu->waiting_resp_txt, "disconnect"))
          KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
        }
      else if  (sscanf(line,
                       "cloonix_resp_connect_ko lan=%s sat=%s num=%d",
                       lan, sat, &num) == 3) 
        {
        if (strcmp(utils_get_mueth_name(mu->name, mu->eth), sat))
          KERR("%s %s %d", sat, mu->name, mu->eth);
        if (mu->eth != num)
          KERR("%d %d", mu->eth, num);
        if (strcmp(mu->waiting_resp_txt, "unix_sock"))
          KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
        mueth_event_connect_KO(mu->name, mu->eth, lan);
        }
      else
        KOUT("%s %s", mu->name, line);
      mu->waiting_resp = 0;
      memset(mu->waiting_resp_txt, 0, MAX_NAME_LEN);
      }
    } 
  else
    KOUT("%s", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_err_cb (int llid)
{
  t_mueth_qemu *mu = mueth_find_with_llid(llid);
  if (mu)
    mueth_free(mu);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_mueth_beat(void *data)
{
  t_mueth_qemu *cur = g_head_mueth_qemu;
  while(cur)
    {
    if (cur->destroy_timer_on == 0)
      {
      if (cur->periodic_count < 3)
        cur->periodic_count += 1;
      else if (cur->llid == 0)
        cur->llid = trace_alloc(cur);
      else if (cur->pid == 0) 
        rpct_send_pid_req(NULL, cur->llid, type_hop_mueth, 
                         cloonix_get_sec_offset(), cur->name);
      else if (cur->pid)
        {
        cur->periodic_count += 1;
        if (cur->periodic_count >= 10)
          {
          rpct_send_pid_req(NULL, cur->llid, type_hop_mueth, 
                           cloonix_get_sec_offset(), cur->name);
          cur->periodic_count = 1;
          } 
        }
      }
    cur = cur->next;
    }
  clownix_timeout_add(50, timer_mueth_beat, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mueth_vm_start(char *name, int eth)
{
  int result = -1;
  t_vm *vm;
  t_mueth_qemu *mu = mueth_find_with_name(name, eth);
  if (mu == NULL)
    {
    vm = cfg_get_vm(name);
    if (vm)
      {
      result = 0;
      mu = mueth_alloc(name, eth, vm);
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mueth_exists(char *name, int eth)
{
  int result = -1;
  t_mueth_qemu *mu = mueth_find_with_name(name, eth);
  if (mu != NULL)
    result = 0;
  return result;
}   
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mueth_ready(char *name, int eth)
{
  int result = 0;
  t_mueth_qemu *mu = mueth_find_with_name(name, eth);
  if ((mu) && (mu->waiting_resp == 0))
    result = 1;
  else if (mu)
    {
    KERR("%s eth%d WAITING FOR %s", name, eth, mu->waiting_resp_txt);
    }
  else
    KERR("%s", name);
  return result;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
int mueth_vm_stop(char *name, int eth)
{
  int result = -1;
  t_mueth_qemu *mu = mueth_find_with_name(name, eth);
  if (mu)
    {
    result = 0;
    mueth_free(mu);
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mueth_send_muswitch_connect(int delay, char *name, int eth,
                                char *lan, char *muswitch_sock)
{
  int result = -1;
  t_muswitch_connect *mc;
  t_mueth_qemu *mu = mueth_find_with_name(name, eth);
  if (mu && (lan[0]) && (muswitch_sock[0]) && (!mu->waiting_resp))
    {
    result = 0;
    mc = (t_muswitch_connect *) clownix_malloc(sizeof(t_muswitch_connect), 5); 
    memset(mc, 0, sizeof(t_muswitch_connect));
    strncpy(mc->name, name, MAX_NAME_LEN-1);
    strncpy(mc->lan, lan, MAX_NAME_LEN-1);
    strncpy(mc->muswitch_sock, muswitch_sock, MAX_PATH_LEN-1);
    mc->eth = eth;
    mu->waiting_resp = 1;
    strcpy(mu->waiting_resp_txt, "unix_sock");
    clownix_timeout_add(delay,timer_muswitch_connect,(void *)mc,NULL,NULL);
    }
  else if (mu)
    KERR("%s %d %s %s %d %s", name, eth, lan, muswitch_sock, 
                              mu->waiting_resp, mu->waiting_resp_txt);
  else
    KERR("%s %d %s %s",name,eth,lan,muswitch_sock);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mueth_send_muswitch_disconnect(char *name, int eth,
                                   char *lan, char *muswitch_sock)
{
  int result = -1;
  char cmd[MAX_PATH_LEN];
  t_mueth_qemu *mu = mueth_find_with_name(name, eth);
  if (mu && (lan[0]) && (muswitch_sock[0]) && (!mu->waiting_resp))
    {
    memset(cmd, 0, MAX_PATH_LEN);
    snprintf(cmd, MAX_PATH_LEN-1, 
             "cloonix_req_disconnect lan=%s sat=%s num=%d", 
             lan, utils_get_mueth_name(name, eth), eth);
    result = try_send_mueth(mu, cmd);
    if (!result)
      {
      mu->waiting_resp = 1;
      strcpy(mu->waiting_resp_txt, "disconnect");
      }
    }
  else
    KERR("%s %d %s %s", name, eth, lan, muswitch_sock);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void mueth_init(void)
{
  g_head_mueth_qemu = NULL;
  mueth_event_init();
  clownix_timeout_add(50, timer_mueth_beat, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

