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
#include "doors_rpc.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "cfg_store.h"
#include "utils_cmd_line_maker.h"
#include "system_callers.h"
#include "llid_trace.h"
#include "mulan_mngt.h"
#include "musat_mngt.h"
#include "musat_events.h"
#include "file_read_write.h"
#include "pid_clone.h"
#include "hop_event.h"
#include "stats_counters.h"
#include "doorways_mngt.h"
#include "c2c_utils.h"

void uml_clownix_switch_error_cb(void *ptr, int llid, int err, int from);
void uml_clownix_switch_rx_cb(int llid, int len, char *buf);
void murpc_dispatch_send_tx_flow_control(int llid, int rank, int stop);


/****************************************************************************/
typedef struct t_muswitch_connect
{
  char name[MAX_NAME_LEN];
  int eth;
  char lan[MAX_NAME_LEN];
  char muswitch_sock[MAX_PATH_LEN];
} t_muswitch_connect;
/*--------------------------------------------------------------------------*/


/****************************************************************************/
typedef struct t_musat
{
  char name[MAX_NAME_LEN];
  int clone_start_pid;
  int pid;
  int getsuidroot;
  int opensat;
  int init_munat_mac;
  int musat_type;
  int llid;
  int cli_llid;
  int cli_tid;
  int waiting_resp;
  char waiting_resp_txt[MAX_NAME_LEN];
  t_tux *tux;
  int periodic_count;
  int doors_fd_ready;
  int doors_fd_value;
  int musat_stop_done;
  struct t_musat *prev;
  struct t_musat *next;
} t_musat;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
typedef struct t_musat_arg
{
  char net_name[MAX_NAME_LEN];
  char name[MAX_NAME_LEN];
  char bin_path[MAX_PATH_LEN];
  char sock[MAX_PATH_LEN];
  int musat_type;
  int cli_llid;
  int cli_tid;
} t_musat_arg;
/*--------------------------------------------------------------------------*/


static t_musat *g_head_musat;


/****************************************************************************/
static int try_send_musat(t_musat *mu, char *msg)
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
      KERR("%s", mu->name);
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int try_send_app_musat(t_musat *mu, char *msg)
{
  int result = -1;
  if (mu->llid)
    {
    if (msg_exist_channel(mu->llid))
      {
      hop_event_hook(mu->llid, FLAG_HOP_APP, msg);
      rpct_send_app_msg(NULL, mu->llid, mu->pid, msg);
      result = 0;
      }
    else
      KERR("%s", mu->name);
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void init_mac_in_munat(t_musat *cur, 
                              char *name, int vm_id, 
                              int nb_eth, t_eth_params *eth)
{
  int i;
  char msg[MAX_PATH_LEN];
  char *mc;
  for (i=0; i<nb_eth; i++)
    {
    mc = eth[i].mac_addr;
    memset(msg, 0, MAX_PATH_LEN);
    snprintf(msg, MAX_PATH_LEN-1,
             "add_machine_mac name=%s vm_id=%d num=%d "
             "mac=%02X:%02X:%02X:%02X:%02X:%02X",
             name, vm_id, i, mc[0]&0xFF, mc[1]&0xFF, mc[2]&0xFF,
             mc[3]&0xFF, mc[4]&0xFF, mc[5]&0xFF);
    try_send_app_musat(cur, msg);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void musat_mngt_add_vm(char *name, int vm_id, int nb_eth, t_eth_params *eth)
{
  t_musat *cur = g_head_musat;
  while(cur)
    {
    if (cur->musat_type == musat_type_nat)
      {
      init_mac_in_munat(cur, name, vm_id, nb_eth, eth); 
      }
    cur = cur->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void musat_mngt_add_all_vm(t_musat *cur)
{
  char *name;
  int nb, vm_id, nb_eth;
  t_eth_params *eth;
  t_vm *vm = cfg_get_first_vm(&nb);
  while (vm)
    {
    name = vm->vm_params.name;
    vm_id = vm->vm_id;
    nb_eth = vm->vm_params.nb_eth;
    eth = vm->vm_params.eth_params;
    init_mac_in_munat(cur, name, vm_id, nb_eth, eth);
    vm = vm->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void musat_mngt_del_vm(char *name, int vm_id, int nb_eth, t_eth_params *eth)
{
  t_musat *cur = g_head_musat;
  int i;
  char msg[MAX_PATH_LEN];
  char *mc;
  while(cur)
    {
    if (cur->musat_type == musat_type_nat)
      {
      for (i=0; i<nb_eth; i++)
        {
        mc = eth[i].mac_addr;
        memset(msg, 0, MAX_PATH_LEN);
        snprintf(msg, MAX_PATH_LEN-1,
                 "del_machine_mac name=%s vm_id=%d num=%d "
                 "mac=%02X:%02X:%02X:%02X:%02X:%02X", 
                 name, vm_id, i, mc[0]&0xFF, mc[1]&0xFF, mc[2]&0xFF,
                 mc[3]&0xFF, mc[4]&0xFF, mc[5]&0xFF);  
        try_send_app_musat(cur, msg);
        }
      }
    cur = cur->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void status_reply_if_possible(int is_ok, t_musat *musat, char *txt)
{
  char info[MAX_PATH_LEN];
  memset(info, 0, MAX_PATH_LEN);
  if ((musat->cli_llid) && msg_exist_channel(musat->cli_llid))
    {
    snprintf(info, MAX_PATH_LEN-1, "%s %s", musat->name, txt);  
    if (is_ok)
      send_status_ok(musat->cli_llid, musat->cli_tid, info);
    else
      send_status_ko(musat->cli_llid, musat->cli_tid, info);
    musat->cli_llid = 0;
    musat->cli_tid = 0;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_is_tap(int type)
{
  int result = 0;
  if ((type == musat_type_tap)  || 
      (type == musat_type_wif)) 
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_is_snf(int type)
{
  int result = 0;
  if (type == musat_type_snf)
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_is_a2b(int type)
{
  int result = 0;
  if (type == musat_type_a2b)
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_is_nat(int type)
{
  int result = 0;
  if (type == musat_type_nat)
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/



/****************************************************************************/
int musat_mngt_is_c2c(int type)
{
  int result = 0;
  if (type == musat_type_c2c)
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int trace_alloc(t_musat *mu)
{
  int llid;
  char *sock = utils_get_musat_path(mu->name);
  llid = string_client_unix(sock, uml_clownix_switch_error_cb, 
                                  uml_clownix_switch_rx_cb, "musat");
  if (llid)
    {
    if (hop_event_alloc(llid, type_hop_musat, mu->name, 0))
      KERR("%s", mu->name);
    if (mu->musat_type == musat_type_tap)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_musat_tap);
    else 
    if (mu->musat_type == musat_type_snf) 
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_musat_snf);
    else 
    if (mu->musat_type == musat_type_c2c)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_musat_c2c);
    else 
    if (mu->musat_type == musat_type_nat)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_musat_nat);
    else 
    if (mu->musat_type == musat_type_a2b)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_musat_a2b);
    else 
    if (mu->musat_type == musat_type_wif)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_musat_wif);
    else
      KOUT("%d", mu->musat_type);
    }
  else
    KERR("%s %s", mu->name, sock);
  return llid;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_musat *musat_find_with_name(char *name)
{
  t_musat *cur = g_head_musat;
  while(cur && name[0] && (strcmp(cur->name, name)))
    cur = cur->next;
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_musat *musat_find_with_llid(int llid)
{
  t_musat *cur = g_head_musat;
  if ((llid <1) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  while(cur && (cur->llid != llid))
    cur = cur->next;
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_can_be_found_with_llid(int llid, char *name, int *musat_type)
{
  t_musat *cur = g_head_musat;
  memset(name, 0, MAX_NAME_LEN);
  if ((llid <1) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  while(cur && (cur->llid != llid))
    cur = cur->next;
  if (cur)
    {
    strncpy(name, cur->name, MAX_NAME_LEN-1);
    *musat_type = cur->musat_type;
    return 1;
    }
  else
    return 0; 
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_can_be_found_with_name(char *name, int *musat_type)
{
  int result = 0;
  t_musat *cur = musat_find_with_name(name);
  if (cur)
    {
    if (msg_exist_channel(cur->llid))
      {
      result = cur->llid;
      *musat_type = cur->musat_type;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_get_type_with_name(char *name)
{
  int result = 0;
  t_musat *cur = musat_find_with_name(name);
  if (cur)
    {
    result = cur->musat_type;
    }
  return result;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static t_musat *musat_alloc(char *name, int llid, int tid, int musat_type)
{
  t_musat *mu;
  mu = (t_musat *) clownix_malloc(sizeof(t_musat), 4);
  memset(mu, 0, sizeof(t_musat));
  strncpy(mu->name, name, MAX_NAME_LEN-1);
  mu->cli_llid = llid;
  mu->cli_tid = tid;
  mu->musat_type = musat_type;
  if (g_head_musat)
    g_head_musat->prev = mu;
  mu->next = g_head_musat;
  g_head_musat = mu; 
  return mu;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int musat_mngt_set_tux(int llid, char *name, int musat_type, 
                              int snf_capture_on, char *snf_recpath,
                              char *req_cloonix_slave,
                              int c2c_ip_slave, int c2c_port_slave)
{
  int result = 0;
  t_musat *mu = musat_find_with_name(name);
  if (mu)
    {
    if (mu->tux)
      KOUT(" ");
    cfg_set_tux(1, musat_type, name, llid);
    mu->tux = cfg_get_tux(name);
    if (!mu->tux)
      KOUT(" ");
    if (musat_mngt_is_snf(musat_type))
      {
      mu->tux->snf_info.capture_on = snf_capture_on;
      snprintf(mu->tux->snf_info.recpath, MAX_PATH_LEN-1, "%s", snf_recpath);
      }
    if (musat_mngt_is_c2c(musat_type))
      {
      if (req_cloonix_slave)
        {
        strncpy(mu->tux->c2c_info.req_cloonix_slave, 
                req_cloonix_slave, MAX_NAME_LEN-1);
        }
      mu->tux->c2c_info.ip_slave = c2c_ip_slave;
      mu->tux->c2c_info.port_slave = c2c_port_slave;
      }
    }
  else
    KOUT("%s %d", name, musat_type);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void musat_mngt_update_unset_tux_action(char *name, t_tux *tmptux)
{
  t_musat *mu = musat_find_with_name(name);
  if (mu)
    {
    if (mu->tux != tmptux)
      KOUT("%p %p", mu->tux, tmptux);
    mu->tux = NULL;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void musat_mngt_unset_tux(char *name)
{
  t_tux *tmptux;
  t_musat *mu = musat_find_with_name(name);
  if (mu && mu->tux)
    {
    tmptux = cfg_get_tux(name);
    if (mu->tux != tmptux)
      KOUT(" ");
    if (tmptux)
      {
      if (musat_mngt_is_c2c(tmptux->musat_type))
        c2c_free_ctx(name);
      else
        cfg_unset_tux(name);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void musat_free(char *name)
{
  t_musat *mu = musat_find_with_name(name);
  if (mu)
    {
    status_reply_if_possible(0, mu, "ERROR"); 
    musat_mngt_unset_tux(name);
    if (mu->prev)
      mu->prev->next = mu->next;
    if (mu->next)
      mu->next->prev = mu->prev;
    if (mu == g_head_musat)
      g_head_musat = mu->next;
    if (mu->llid)
      {
      llid_trace_free(mu->llid, 0, __FUNCTION__);
      }
    clownix_free(mu, __FUNCTION__);
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void musat_mngt_pid_resp(int llid, char *name, int pid)
{
  t_musat *musat = musat_find_with_llid(llid);
  if (musat)
    {
    if (strcmp(name, musat->name))
      KERR("%s %s", name, musat->name);
    if (musat->pid == 0)
      {
      if (musat->clone_start_pid != pid)
        {
        KERR("WRONG PID %s %d %d", name, pid, musat->clone_start_pid);
        if (musat->clone_start_pid == 0)
          {
          KERR("MODIFYING START PID %s %d", name, pid);
          musat->clone_start_pid = pid;
          }
        }
      musat->pid = pid;
      if (musat->musat_type == musat_type_snf)
        {
        rpct_send_cli_req(NULL, llid, 0, 0, 0, "-get_conf");
        }
      }
    else
      {
      if (musat->pid != pid)
        KERR("%s %d %d", name, pid, musat->pid);
      }
    }
  else
    KERR("%s %d", name, pid);
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
void musat_mngt_rpct_recv_evt_msg(int llid, int tid, char *line)
{
  int num, peer_llid, pkt, bytes, rank, stop;
  unsigned int ms;
  t_musat *mu = musat_find_with_llid(llid);
  char nm[MAX_NAME_LEN];
  if (mu)
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
    else if (sscanf(line,"musat_eventfull_tx %u %d %d %d",
                         &ms, &num, &pkt, &bytes) == 4)
      {
      if ((num != 0) && (num != 1))
        KOUT("%d", num);
      if (mu->tux)
        stats_counters_update_tux_tx(mu->tux, ms, num, pkt, bytes);
      else
        KERR(" ");
      }
    else if (sscanf(line,"musat_eventfull_rx %u %d %d %d",
                         &ms, &num, &pkt, &bytes) == 4)
      {
      if ((num != 0) && (num != 1))
        KOUT("%d", num);
      if (mu->tux)
        stats_counters_update_tux_rx(mu->tux, ms, num, pkt, bytes);
      else
        KERR(" ");
      }
    }
  else
    KERR("%s", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_mngt_rpct_recv_diag_msg(int llid, int tid, char *line)
{
  t_musat *mu = musat_find_with_llid(llid);
  char sat[MAX_NAME_LEN];
  char lan[MAX_NAME_LEN];
  int num, rank;
  if (mu)
    {
    if (!strcmp(line, "cloonix_resp_suidroot_ok"))
      mu->getsuidroot = 1;
    else if (!strcmp(line, "cloonix_resp_suidroot_ko"))
      {
      mu->getsuidroot = 1;
      mu->opensat = 1;
      status_reply_if_possible(0, mu, 
      "\"sudo chmod u+s /usr/local/bin/cloonix"
      "/server/muswitch/mutap/cloonix_mutap\"");

      musat_mngt_send_muswitch_quit(mu->name);
      }
    else if ((!strcmp(line, "cloonix_resp_tap_ok"))  ||
             (!strcmp(line, "cloonix_resp_wif_ok"))  ||
             (!strcmp(line, "cloonix_resp_snf_ok"))  ||
             (!strcmp(line, "cloonix_resp_c2c_ok"))  ||
             (!strcmp(line, "cloonix_resp_nat_ok"))  ||
             (!strcmp(line, "cloonix_resp_a2b_ok")))
      {
      mu->opensat = 1;
      musat_event_birth(mu->name, mu->musat_type);
      status_reply_if_possible(1, mu, "OK"); 
      }
    else if ((!strcmp(line, "cloonix_resp_tap_ko"))  ||
             (!strcmp(line, "cloonix_resp_wif_ko"))  ||
             (!strcmp(line, "cloonix_resp_snf_ko"))  ||
             (!strcmp(line, "cloonix_resp_c2c_ko"))  ||
             (!strcmp(line, "cloonix_resp_nat_ko"))  ||
             (!strcmp(line, "cloonix_resp_a2b_ko")))
      {
      mu->opensat = 1;
      status_reply_if_possible(0, mu, line);
      musat_mngt_send_muswitch_quit(mu->name);
      }
    else if (sscanf(line, 
                    "cloonix_resp_connect_ok lan=%s sat=%s num=%d rank=%d",
                    lan, sat, &num, &rank) == 4)
      {
      if (strcmp(sat, mu->name))
        KERR("%s %s", sat, mu->name);
      if (strcmp(mu->waiting_resp_txt, "unix_sock"))
        KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
      musat_event_connect_OK(sat, lan, num, rank);
      }
    else if  (sscanf(line,
                     "cloonix_resp_disconnect_ok lan=%s sat=%s num=%d",
                     lan, sat, &num) == 3)
      {
      if (strcmp(sat, mu->name))
        KERR("%s %s", sat, mu->name);
      if (strcmp(mu->waiting_resp_txt, "disconnect"))
        KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
      }
    else if  (sscanf(line,
                     "cloonix_resp_connect_ko lan=%s sat=%s num=%d", 
                     lan, sat, &num) == 3)
      {
      if (strcmp(sat, mu->name))
        KERR("%s %s", sat, mu->name);
      if (strcmp(mu->waiting_resp_txt, "unix_sock"))
        KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
      musat_event_connect_KO(sat, lan, num);
      }
    else
      KERR("%s %s", mu->name, line);
    mu->waiting_resp = 0;
    memset(mu->waiting_resp_txt, 0, MAX_NAME_LEN);
    }
  else
    KOUT("%s", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_mngt_err_cb (int llid)
{
  t_musat *mu = musat_find_with_llid(llid);
  if (mu)
    {
    status_reply_if_possible(0, mu, "llid_err");
    musat_event_quick_death(mu->name);
    musat_free(mu->name);
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void send_type_req(t_musat *cur)
{
  char msg_info[MAX_PATH_LEN];
  memset(msg_info, 0, MAX_PATH_LEN);
  if (cur->musat_type == musat_type_tap)
    try_send_musat(cur, "cloonix_req_tap");
  else if (cur->musat_type == musat_type_wif)
    try_send_musat(cur, "cloonix_req_wif");
  else if (cur->musat_type == musat_type_snf)
    try_send_musat(cur, "cloonix_req_snf");
  else if (cur->musat_type == musat_type_c2c)
    try_send_musat(cur, "cloonix_req_c2c");
  else if (cur->musat_type == musat_type_a2b)
    try_send_musat(cur, "cloonix_req_a2b");
  else if (cur->musat_type == musat_type_nat)
    try_send_musat(cur, "cloonix_req_nat");
  else
    KERR("%d", cur->musat_type);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_musat_beat(void *data)
{
  t_musat *cur = g_head_musat;
  while(cur)
    {
    if (cur->periodic_count < 3)
      cur->periodic_count += 1;
    else if (cur->clone_start_pid)
      {
      if (cur->llid == 0)
        cur->llid = trace_alloc(cur);
      else if (cur->pid == 0) 
        rpct_send_pid_req(NULL, cur->llid, type_hop_musat,
                         cloonix_get_sec_offset(), cur->name);
      else if ((musat_mngt_is_tap(cur->musat_type)) && (cur->getsuidroot == 0))
        try_send_musat(cur, "cloonix_req_suidroot");
      else if (cur->opensat == 0)
        send_type_req(cur);
      else if (cur->pid)
        {
        if (cur->init_munat_mac == 0)
          {
          musat_mngt_add_all_vm(cur);
          cur->init_munat_mac = 1;
          } 
        cur->periodic_count += 1;
        if (cur->periodic_count >= 10)
          {
          rpct_send_pid_req(NULL, cur->llid, type_hop_musat,
                           cloonix_get_sec_offset(), cur->name);
          cur->periodic_count = 1;
          }
        }
      }
    cur = cur->next;
    }
  clownix_timeout_add(50, timer_musat_beat, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void musat_watchdog(void *data)
{
  t_musat_arg *mua = (t_musat_arg *) data;
  t_musat *musat = musat_find_with_name(mua->name);
  if (musat && ((!musat->llid) || (!musat->pid)))
    {
    status_reply_if_possible(0, musat, "timeout");
    KERR("%s", musat->name);
    musat_event_quick_death(musat->name);
    musat_free(musat->name);
    }
  clownix_free(mua, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void doors_recv_c2c_clone_death(int llid, int tid, char *name)
{
  t_musat *musat = musat_find_with_name(name);
  event_print("End doors musat %s", name);
  if (musat)
    {
    status_reply_if_possible(0, musat, "death");
    musat_event_quick_death(musat->name);
    musat_free(musat->name);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void musat_death(void *data, int status, char *name)
{
  t_musat_arg *mua = (t_musat_arg *) data;
  t_musat *musat = musat_find_with_name(mua->name);
  if (strcmp(name, mua->name))
    KOUT("%s %s", name, mua->name);
  event_print("End musat %s", name);
  if (musat)
    {
    event_print("End musat two %s", name);
    status_reply_if_possible(0, musat, "death");
    musat_event_quick_death(musat->name);
    musat_free(musat->name);
    }
  clownix_free(mua, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static char **musat_birth_argv(t_musat_arg *mu)
{
  static char musat_type[MAX_NAME_LEN];
  static char net_name[MAX_NAME_LEN];
  static char name[MAX_NAME_LEN];
  static char bin_path[MAX_PATH_LEN];
  static char sock[MAX_PATH_LEN];
  static char *argv[] = {bin_path, net_name, name, sock, musat_type, NULL};
  memset(musat_type, 0, MAX_NAME_LEN);
  memset(net_name, 0, MAX_NAME_LEN);
  memset(name, 0, MAX_NAME_LEN);
  memset(bin_path, 0, MAX_PATH_LEN);
  memset(sock, 0, MAX_PATH_LEN);
  snprintf(musat_type, MAX_NAME_LEN-1, "%d", mu->musat_type);
  snprintf(net_name, MAX_NAME_LEN-1, "%s", mu->net_name);
  snprintf(name, MAX_NAME_LEN-1, "%s", mu->name);
  snprintf(bin_path, MAX_PATH_LEN-1, "%s", mu->bin_path);
  snprintf(sock, MAX_PATH_LEN-1, "%s", mu->sock);
  return argv;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int musat_birth(void *data)
{
  t_musat_arg *mu = (t_musat_arg *) data;
  char **argv = musat_birth_argv(mu);

//VIP
//sleep(1000000);

  execv(mu->bin_path, argv);
  return 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void create_two_musat_arg(char *name, int musat_type,
                                 t_musat_arg **mua1, t_musat_arg **mua2)
{
  char *bin_path = utils_get_musat_bin_path(musat_type);
  *mua1 = (t_musat_arg *) clownix_malloc(sizeof(t_musat_arg), 4);
  *mua2 = (t_musat_arg *) clownix_malloc(sizeof(t_musat_arg), 4);
  memset(*mua1, 0, sizeof(t_musat_arg));
  memset(*mua2, 0, sizeof(t_musat_arg));
  strncpy((*mua1)->net_name, cfg_get_cloonix_name(), MAX_NAME_LEN-1);
  strncpy((*mua2)->net_name, cfg_get_cloonix_name(), MAX_NAME_LEN-1);
  strncpy((*mua1)->name, name, MAX_NAME_LEN-1);
  strncpy((*mua2)->name, name, MAX_NAME_LEN-1);
  strncpy((*mua1)->bin_path, bin_path, MAX_PATH_LEN-1);
  strncpy((*mua2)->bin_path, bin_path, MAX_PATH_LEN-1);
  strncpy((*mua1)->sock, utils_get_musat_path(name), MAX_PATH_LEN-1);
  strncpy((*mua2)->sock, utils_get_musat_path(name), MAX_PATH_LEN-1);
  (*mua1)->musat_type = musat_type;
  (*mua2)->musat_type = musat_type;
  if (!file_exists(bin_path, X_OK))
    KERR("%s Does not exist or not exec", bin_path);

}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_exists(char *name, int *musat_type)
{
  int result = 0;
  t_musat *musat = musat_find_with_name(name);
  if (musat)
    {
    *musat_type = musat->musat_type;
    result = 1;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_connection_state_is_restfull(char *name)
{
  int result = 0;
  t_musat *mu = musat_find_with_name(name);
  if ((mu) && (mu->waiting_resp == 0))
    result = 1;
  else if (mu)
    KERR("%s %s", name, mu->waiting_resp_txt);
  else
    KERR("%s", name);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void doors_recv_c2c_clone_birth_pid(int llid, int tid, char *name, int pid)
{
  t_musat *mu = musat_find_with_name(name);
  if (!mu)
    KERR("%s %d", name, pid);
  else
    {
    if (mu->clone_start_pid)
      KERR("%s %d %d", name, pid, mu->clone_start_pid);
    mu->clone_start_pid = pid;
    if (!mu->clone_start_pid)
      KERR(" ");
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int fd_ready_doors_clone_has_arrived(char *name, int doors_fd)
{
  int result = -1;
  t_musat *mu = musat_find_with_name(name);
  if (mu)
    {
    if (mu->doors_fd_ready)
      KERR("%s %d", name, doors_fd);
    else
      {
      mu->doors_fd_ready = 1;
      mu->doors_fd_value = doors_fd;
      result = 0;
      }
    }
  else
    KERR("%s %d", name, doors_fd);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void fd_ready_doors_clone(void *data)
{
  t_musat_arg  *mua2 = (t_musat_arg  *) data;
  t_musat *mu = musat_find_with_name(mua2->name);
  if (mu)
    {
    if (mu->doors_fd_ready)
      {
      doors_send_c2c_clone_birth(get_doorways_llid(), 0, mua2->net_name,  
                                 mua2->name, mu->doors_fd_value, 
                                 mua2->musat_type, mua2->bin_path, 
                                 mua2->sock);
      clownix_free(mua2, __FUNCTION__);
      }
    else
      {
      clownix_timeout_add(10,fd_ready_doors_clone,(void *)mua2,NULL,NULL);
      }
    }
  else
    {
    KERR("Musat %s has disapeared", mua2->name);
    clownix_free(mua2, __FUNCTION__);
    }
}


/****************************************************************************/
int musat_mngt_start(int llid, int tid, char *name, int musat_type,
                     int snf_capture_on, char *snf_recpath,
                     char *req_cloonix_slave,
                     int c2c_ip_slave, int c2c_port_slave)
{
  int result = -1;
  char *sock = utils_get_musat_path(name);
  t_musat *mu = musat_find_with_name(name);
  t_musat_arg  *mua1, *mua2;
  char **argv;
  if (mu == NULL)
    {
    result = 0;
    if (file_exists(sock, F_OK))
      unlink(sock);
    mu = musat_alloc(name, llid, tid, musat_type);
    if (!mu)
      KOUT(" ");
    result = musat_mngt_set_tux(llid, name, musat_type, 
                                snf_capture_on, snf_recpath,
                                req_cloonix_slave,
                                c2c_ip_slave, c2c_port_slave);
    if (result)
      {
      musat_free(name);
      }
    else
      {
      my_mkdir(utils_get_musat_sock_dir());
      create_two_musat_arg(name, musat_type, &mua1, &mua2);
      if (mu->musat_type == musat_type_c2c)
        {
        clownix_free(mua1, __FUNCTION__);
        clownix_timeout_add(10,fd_ready_doors_clone,(void *)mua2,NULL,NULL);
        }
      else
        {
        argv = musat_birth_argv(mua2);
        utils_send_creation_info("musat", argv);
        mu->clone_start_pid = pid_clone_launch(musat_birth, musat_death, 
                                               NULL, mua2, mua2, NULL, 
                                               name, -1, 1);
        if (!mu->clone_start_pid)
          KERR(" ");

//VIP
        clownix_timeout_add(1000, musat_watchdog, (void *) mua1, NULL, NULL);
//clownix_timeout_add(10000, musat_watchdog, (void *) mua1, NULL, NULL);
//mu->clone_start_pid = 0;
        }
      result = 0;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_muswitch_connect(void *data)
{
  char cmd[MAX_PATH_LEN];
  t_muswitch_connect *mc = ( t_muswitch_connect *) data;
  t_musat *mu;
  if (!mc)
    KOUT(" ");
  mu = musat_find_with_name(mc->name);
  if (!mu)
    KERR("%s %s", mc->name, mc->lan);
  else
    {
    memset(cmd, 0, MAX_PATH_LEN);
    snprintf(cmd, MAX_PATH_LEN-1, 
             "cloonix_req_connect sock=%s lan=%s sat=%s num=%d",
             mc->muswitch_sock, mc->lan, mc->name, mc->eth);
    if (try_send_musat(mu, cmd))
      {
      mu->waiting_resp = 0;
      memset(mu->waiting_resp_txt, 0, MAX_NAME_LEN);
      KERR("%s %s %s",mc->name, mc->lan, mc->muswitch_sock);
      }
    }
  clownix_free(data, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_send_mulan_connect(int delay, char *name, int eth,
                                  char *lan, char *muswitch_sock)
{
  int result = -1;
  t_muswitch_connect *mc;
  t_musat *mu = musat_find_with_name(name);
  if (mu && (lan[0]) && (muswitch_sock[0]) && (mu->waiting_resp == 0))
    {
    result = 0;
    mc=(t_muswitch_connect *)clownix_malloc(sizeof(t_muswitch_connect), 5); 
    memset(mc, 0, sizeof(t_muswitch_connect));
    strncpy(mc->name, name, MAX_NAME_LEN-1);
    mc->eth = eth;
    strncpy(mc->lan, lan, MAX_NAME_LEN-1);
    strncpy(mc->muswitch_sock, muswitch_sock, MAX_PATH_LEN-1);
    mu->waiting_resp = 1;
    strcpy(mu->waiting_resp_txt, "unix_sock");
    clownix_timeout_add(delay,timer_muswitch_connect,(void *)mc,NULL,NULL);
    }
  else
    KERR("%s %s %s %d %s", name, lan, muswitch_sock, 
                           mu->waiting_resp, mu->waiting_resp_txt);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_send_mulan_disconnect(char *name, int num,
                                     char *lan, char *muswitch_sock)
{
  int result = -1;
  char cmd[MAX_PATH_LEN];
  t_musat *mu = musat_find_with_name(name);
  if (mu && (lan[0]) && (muswitch_sock[0]) && (mu->waiting_resp == 0))
    {
    memset(cmd, 0, MAX_PATH_LEN);
    snprintf(cmd, MAX_PATH_LEN-1, 
             "cloonix_req_disconnect lan=%s sat=%s num=%d",
             lan, name, num);
    result = try_send_musat(mu, cmd);
    if (!result)
      {
      mu->waiting_resp = 1;
      strcpy(mu->waiting_resp_txt, "disconnect");
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_musat_free(void *data)
{
  char *name = (char *) data;
  musat_free(name);
  clownix_free(name, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void musat_mngt_send_muswitch_quit(char *name)
{
  t_musat *mu = musat_find_with_name(name);
  char *vname;
  if (mu)
    {
    vname = (char *) clownix_malloc(MAX_NAME_LEN, 4); 
    memset(vname, 0, MAX_NAME_LEN);
    strncpy(vname, name, MAX_NAME_LEN-1);
    try_send_musat(mu, "cloonix_req_quit");
    mu->waiting_resp = 1;
    strcpy(mu->waiting_resp_txt, "quit");
    clownix_timeout_add(50, timer_musat_free, (void *)vname, NULL, NULL);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_get_type(char *name, int *musat_type)
{
  int result = -1;
  t_musat *mu = musat_find_with_name(name);
  *musat_type = 0;
  if (mu != NULL)
    {
    *musat_type = mu->musat_type;
    result = 0;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int musat_mngt_stop(char *name)
{
  int result = -1;
  t_musat *mu = musat_find_with_name(name);
  if ((mu) && (!mu->musat_stop_done))
    {
    mu->musat_stop_done = 1;
    result = 0;
    if (musat_event_death(mu->name))
      {
      musat_free(mu->name);
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void musat_mngt_stop_all(void)
{
  t_musat *next, *cur = g_head_musat;
  while(cur)
    {
    next = cur->next;
    musat_mngt_stop(cur->name);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int musat_get_all_llid(int **llid_tab)
{
  t_musat *cur = g_head_musat;
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
    cur = g_head_musat;
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

/*****************************************************************************/
int musat_mngt_get_all_pid(t_lst_pid **lst_pid)
{
  t_lst_pid *glob_lst = NULL;
  t_musat *cur = g_head_musat;
  int i, result = 0;
  event_print("%s", __FUNCTION__);
  while(cur)
    {
    if (cur->pid)
      result++;
    cur = cur->next;
    }
  if (result)
    {
    glob_lst = (t_lst_pid *)clownix_malloc(result*sizeof(t_lst_pid),5);
    memset(glob_lst, 0, result*sizeof(t_lst_pid));
    cur = g_head_musat;
    i = 0;
    while(cur)
      {
      if (cur->pid)
        {
        strncpy(glob_lst[i].name, cur->name, MAX_NAME_LEN-1);
        glob_lst[i].pid = cur->pid;
        i++;
        }
      cur = cur->next;
      }
    if (i != result)
      KOUT("%d %d", i, result);
    }
  *lst_pid = glob_lst;
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void musat_mngt_init(void)
{
  g_head_musat = NULL;
  musat_event_init();
  clownix_timeout_add(50, timer_musat_beat, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

