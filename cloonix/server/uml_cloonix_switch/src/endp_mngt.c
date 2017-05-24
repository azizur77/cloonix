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
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "io_clownix.h"
#include "rpc_clownix.h"
#include "doors_rpc.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "cfg_store.h"
#include "utils_cmd_line_maker.h"
#include "system_callers.h"
#include "llid_trace.h"
#include "mulan_mngt.h"
#include "endp_mngt.h"
#include "file_read_write.h"
#include "pid_clone.h"
#include "hop_event.h"
#include "stats_counters.h"
#include "doorways_mngt.h"
#include "c2c_utils.h"
#include "endp_evt.h"
#include "lan_to_name.h"
#include "layout_rpc.h"
#include "layout_topo.h"

void uml_clownix_switch_error_cb(void *ptr, int llid, int err, int from);
void uml_clownix_switch_rx_cb(int llid, int len, char *buf);
void murpc_dispatch_send_tx_flow_control(int llid, int rank, int stop);

/****************************************************************************/
typedef struct t_time_delay
{
  char name[MAX_NAME_LEN];
  int num;
} t_time_delay;
/*--------------------------------------------------------------------------*/


/****************************************************************************/
typedef struct t_muswitch_connect
{
  char name[MAX_NAME_LEN];
  int num;
  int tidx;
  char lan[MAX_NAME_LEN];
  char muswitch_sock[MAX_PATH_LEN];
} t_muswitch_connect;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
typedef struct t_musat
{
  char name[MAX_NAME_LEN];
  int num;
  int clone_start_pid;
  int pid;
  int getsuidroot;
  int opensat;
  int init_munat_mac;
  int endp_type;
  int llid;
  int cli_llid;
  int cli_tid;
  int waiting_resp;
  char waiting_resp_txt[MAX_NAME_LEN];
  int periodic_count;
  int doors_fd_ready;
  int doors_fd_value;
  int musat_stop_done;
  t_topo_c2c c2c;
  t_topo_snf snf;
  t_lan_attached lan_attached[MAX_TRAF_ENDPOINT];
  struct t_musat *prev;
  struct t_musat *next;
} t_musat;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
typedef struct t_argendp
{
  char net_name[MAX_NAME_LEN];
  char name[MAX_NAME_LEN];
  int num;
  char bin_path[MAX_PATH_LEN];
  char sock[MAX_PATH_LEN];
  int endp_type;
  int cli_llid;
  int cli_tid;
} t_argendp;
/*--------------------------------------------------------------------------*/


static t_musat *g_head_musat;
static int g_nb_musat;


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
             "add_machine_mac name=%s vm_id=%d vm_eth=%d "
             "mac=%02X:%02X:%02X:%02X:%02X:%02X",
             name, vm_id, i, mc[0]&0xFF, mc[1]&0xFF, mc[2]&0xFF,
             mc[3]&0xFF, mc[4]&0xFF, mc[5]&0xFF);
    try_send_app_musat(cur, msg);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_add_mac_eth_vm(char *name, int vm_id, 
                              int nb_eth, t_eth_params *eth)
{
  t_musat *cur = g_head_musat;
  while(cur)
    {
    if (cur->endp_type == endp_type_nat)
      {
      init_mac_in_munat(cur, name, vm_id, nb_eth, eth); 
      }
    cur = cur->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_add_all_vm(t_musat *cur)
{
  char *name;
  int nb, vm_id, nb_eth;
  t_eth_params *eth;
  t_vm *vm = cfg_get_first_vm(&nb);
  while (vm)
    {
    name = vm->kvm.name;
    vm_id = vm->kvm.vm_id;
    nb_eth = vm->kvm.nb_eth;
    eth = vm->kvm.eth_params;
    init_mac_in_munat(cur, name, vm_id, nb_eth, eth);
    vm = vm->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_del_mac_eth_vm(char *name, int vm_id, 
                              int nb_eth, t_eth_params *eth)
{
  t_musat *cur = g_head_musat;
  int i;
  char msg[MAX_PATH_LEN];
  char *mc;
  while(cur)
    {
    if (cur->endp_type == endp_type_nat)
      {
      for (i=0; i<nb_eth; i++)
        {
        mc = eth[i].mac_addr;
        memset(msg, 0, MAX_PATH_LEN);
        snprintf(msg, MAX_PATH_LEN-1,
                 "del_machine_mac name=%s vm_id=%d vm_eth=%d "
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
static int trace_alloc(t_musat *mu)
{
  int llid;
  char *sock = utils_get_endp_path(mu->name, mu->num);
  llid = string_client_unix(sock, uml_clownix_switch_error_cb, 
                                  uml_clownix_switch_rx_cb, "musat");
  if (llid)
    {
    if (hop_event_alloc(llid, type_hop_endp, mu->name, mu->num))
      KERR("%s", mu->name);
    if (mu->endp_type == endp_type_tap)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_endp_tap);
    else 
    if (mu->endp_type == endp_type_snf) 
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_endp_snf);
    else 
    if (mu->endp_type == endp_type_c2c)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_endp_c2c);
    else 
    if (mu->endp_type == endp_type_nat)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_endp_nat);
    else 
    if (mu->endp_type == endp_type_a2b)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_endp_a2b);
    else 
    if (mu->endp_type == endp_type_raw)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_endp_raw);
    else
    if (mu->endp_type == endp_type_wif)
      llid_trace_alloc(llid, mu->name, 0, 0, type_llid_trace_endp_wif);
    else
      KOUT("%d", mu->endp_type);
    }
  else
    KERR("%s %s", mu->name, sock);
  return llid;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_musat *musat_find_with_name(char *name, int num)
{
  t_musat *cur = NULL;
  if (name[0])
    { 
    cur = g_head_musat;
    while(cur)
      {
      if ((!strcmp(cur->name, name)) && (cur->num == num))
        break;
      cur = cur->next;
      }
    }
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
int endp_mngt_can_be_found_with_llid(int llid, char *name, int *num,
                                     int *endp_type)
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
    *num = cur->num;
    *endp_type = cur->endp_type;
    return 1;
    }
  else
    return 0; 
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int endp_mngt_can_be_found_with_name(char *name, int num, int *endp_type)
{
  int result = 0;
  t_musat *cur = musat_find_with_name(name, num);
  if (cur)
    {
    if (msg_exist_channel(cur->llid))
      {
      result = cur->llid;
      *endp_type = cur->endp_type;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_musat *musat_alloc(char *name, int num, int llid, int tid, int endp_type)
{
  t_musat *mu;
  mu = (t_musat *) clownix_malloc(sizeof(t_musat), 4);
  memset(mu, 0, sizeof(t_musat));
  strncpy(mu->name, name, MAX_NAME_LEN-1);
  mu->num = num;
  mu->cli_llid = llid;
  mu->cli_tid = tid;
  mu->endp_type = endp_type;
  if (g_head_musat)
    g_head_musat->prev = mu;
  mu->next = g_head_musat;
  g_head_musat = mu; 
  g_nb_musat += 1;
  return mu;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_topo_snf *get_snf(char *name, int num)
{
  t_topo_snf *result = NULL;
  t_musat *mu = musat_find_with_name(name, num);
  if (!mu)
    KERR("%s %d", name, num);
  else if (mu->endp_type != endp_type_snf)
    KERR("%s %d %d", name, num, mu->endp_type);
  else
    result = &(mu->snf);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_snf_set_name(char *name, int num)
{
  t_topo_snf *snf = get_snf(name, num);
  if (snf)
    strncpy(snf->name, name, MAX_NAME_LEN-1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_snf_set_capture(char *name, int num, int capture_on)
{
  t_topo_snf *snf = get_snf(name, num);
  if (snf)
    snf->capture_on = capture_on;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_snf_set_recpath(char *name, int num, char *recpath)
{
  t_topo_snf *snf = get_snf(name, num);
  if (snf)
    strncpy(snf->recpath, recpath, MAX_PATH_LEN-1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_c2c_info(char *name, int num, int local_is_master, 
                       char *master, char *slave, int ip, int port)
{
  t_musat *mu = musat_find_with_name(name, num);
  if (!mu)
    KERR("%s %d", name, num);
  else if (mu->endp_type != endp_type_c2c)
    KERR("%s %d %d", name, num, mu->endp_type);
  else
    {
    strncpy(mu->c2c.name, name, MAX_NAME_LEN-1);
    strncpy(mu->c2c.master_cloonix, master, MAX_NAME_LEN-1);
    strncpy(mu->c2c.slave_cloonix, slave, MAX_NAME_LEN-1);
    mu->c2c.local_is_master = local_is_master;
    mu->c2c.ip_slave = ip;
    mu->c2c.port_slave = port;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_c2c_peered(char *name, int num, int is_peered)
{
  t_musat *mu = musat_find_with_name(name, num);
  if (!mu)
    KERR("%s %d", name, num);
  else if (mu->endp_type != endp_type_c2c)
    KERR("%s %d %d", name, num, mu->endp_type);
  else
    mu->c2c.is_peered = is_peered;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_add_attached_lan(int llid, char *name, int num,
                                int tidx, char *lan)
{
  int lan_num;
  t_musat *mu = musat_find_with_name(name, num);
  if (!mu)
    KERR("%s %d %s", name, num, lan);
  else  if (mu->lan_attached[tidx].lan_num != 0)
    KERR("%s %d %s %d", name, num, lan, mu->lan_attached[tidx].lan_num);
  else
    {
    lan_num = lan_add_name(lan, llid);
    if ((lan_num <= 0) || (lan_num >= MAX_LAN))
      KOUT("%d", lan_num);
    mu->lan_attached[tidx].lan_num = lan_num;
    event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_del_attached_lan(char *name, int num, int tidx, char *lan)
{
  int lan_num;
  t_musat *mu = musat_find_with_name(name, num);
  if (!mu)
    KERR("%s %d %s", name, num, lan);
  else  if (mu->lan_attached[tidx].lan_num == 0)
    KERR("%s %d %s", name, num, lan);
  else
    {
    lan_num = lan_del_name(lan);
    if (mu->lan_attached[tidx].lan_num != lan_num)
      KERR("%s %d %s %d %d", name, num, lan, lan_num,
                          mu->lan_attached[tidx].lan_num);
    else
      {
      memset(&(mu->lan_attached[tidx]), 0, sizeof(t_lan_attached));
      event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void musat_free(char *name, int num)
{
  t_musat *mu = musat_find_with_name(name, num);
  if (mu)
    {
    status_reply_if_possible(0, mu, "ERROR"); 
    if (mu->endp_type == endp_type_c2c)
      c2c_free_ctx(name);
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
    if (num == 0)
    layout_del_sat(name);
    stats_counters_death(name, num);
    event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    clownix_free(mu, __FUNCTION__);
    if (g_nb_musat <= 0)
      KOUT("%d", g_nb_musat);
    g_nb_musat -= 1;
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_pid_resp(int llid, char *name, int pid)
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
      if (musat->endp_type == endp_type_snf)
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
static int llid_flow_to_restrict(char *name, int num)
{
  int llid = mulan_can_be_found_with_name(name);
  KERR("TO RESTRICT: %s %d", name, num);
  return llid;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void endp_mngt_rpct_recv_evt_msg(int llid, int tid, char *line)
{
  int num, tidx, peer_llid, pkts, bytes, rank, stop;
  unsigned int ms;
  t_musat *mu = musat_find_with_llid(llid);
  char name[MAX_NAME_LEN];
  if (mu)
    {
    if (sscanf(line, 
           "cloonix_evt_peer_flow_control name=%s num=%d rank=%d stop=%d",
                     name, &num, &rank, &stop) == 4)
      {
      peer_llid = llid_flow_to_restrict(name, num);
      if (peer_llid)
        murpc_dispatch_send_tx_flow_control(peer_llid, rank, stop);
      else
        KERR("%s %d", name, num);
      }
    else if (sscanf(line,"endp_eventfull_tx %u %d %d %d",
                         &ms, &tidx, &pkts, &bytes) == 4)
      {
      mu->lan_attached[tidx].eventfull_tx_p += pkts;
      stats_counters_update_endp_tx(mu->name, mu->num, ms, pkts, bytes);
      }
    else if (sscanf(line,"endp_eventfull_rx %u %d %d %d",
                         &ms, &tidx, &pkts, &bytes) == 4)
      {
      mu->lan_attached[tidx].eventfull_rx_p += pkts;
      stats_counters_update_endp_rx(mu->name, mu->num, ms, pkts, bytes);
      }
    }
  else
    KERR("%s", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void endp_mngt_rpct_recv_diag_msg(int llid, int tid, char *line)
{
  t_musat *mu = musat_find_with_llid(llid);
  char name[MAX_NAME_LEN];
  char lan[MAX_NAME_LEN];
  int num, tidx, rank;
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

      endp_mngt_send_muswitch_quit(mu->name, mu->num);
      }
    else if ((!strcmp(line, "cloonix_resp_tap_ok"))  ||
             (!strcmp(line, "cloonix_resp_wif_ok"))  ||
             (!strcmp(line, "cloonix_resp_raw_ok"))  ||
             (!strcmp(line, "cloonix_resp_snf_ok"))  ||
             (!strcmp(line, "cloonix_resp_c2c_ok"))  ||
             (!strcmp(line, "cloonix_resp_nat_ok"))  ||
             (!strcmp(line, "cloonix_resp_a2b_ok")))
      {
      mu->opensat = 1;
      endp_birth(mu->name, 0, mu->endp_type);
      if (mu->endp_type == endp_type_a2b)
        endp_birth(mu->name, 1, mu->endp_type);
      status_reply_if_possible(1, mu, "OK"); 
      }
    else if ((!strcmp(line, "cloonix_resp_tap_ko"))  ||
             (!strcmp(line, "cloonix_resp_wif_ko"))  ||
             (!strcmp(line, "cloonix_resp_raw_ko"))  ||
             (!strcmp(line, "cloonix_resp_snf_ko"))  ||
             (!strcmp(line, "cloonix_resp_c2c_ko"))  ||
             (!strcmp(line, "cloonix_resp_nat_ko"))  ||
             (!strcmp(line, "cloonix_resp_a2b_ko")))
      {
      mu->opensat = 1;
      status_reply_if_possible(0, mu, line);
      endp_mngt_send_muswitch_quit(mu->name, mu->num);
      }
    else if (sscanf(line, 
             "cloonix_resp_connect_ok lan=%s name=%s num=%d tidx=%d rank=%d",
             lan, name, &num, &tidx, &rank) == 5)
      {
      if (strcmp(name, mu->name))
        KERR("%s %s", name, mu->name);
      if (strcmp(mu->waiting_resp_txt, "unix_sock"))
        KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
      endp_connect_OK(name, num, lan, tidx, rank);
      }
    else if  (sscanf(line,
              "cloonix_resp_disconnect_ok lan=%s name=%s num=%d tidx=%d",
              lan, name, &num, &tidx) == 4)
      {
      if (strcmp(name, mu->name))
        KERR("%s %s", name, mu->name);
      if (strcmp(mu->waiting_resp_txt, "disconnect"))
        KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
      }
    else if  (sscanf(line,
              "cloonix_resp_connect_ko lan=%s name=%s num=%d tidx=%d", 
              lan, name, &num, &tidx) == 4)
      {
      if (strcmp(name, mu->name))
        KERR("%s %s", name, mu->name);
      if (strcmp(mu->waiting_resp_txt, "unix_sock"))
        KERR("%s %d %d %s", mu->name, tid, mu->pid, line);
      endp_connect_KO(name, num, lan, tidx);
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
void endp_mngt_err_cb (int llid)
{
  t_musat *mu = musat_find_with_llid(llid);
  if (mu)
    {
    status_reply_if_possible(0, mu, "llid_err");
    endp_quick_death(mu->name, mu->num);
    musat_free(mu->name, mu->num);
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void send_type_req(t_musat *cur)
{
  char msg_info[MAX_PATH_LEN];
  memset(msg_info, 0, MAX_PATH_LEN);
  if (cur->endp_type == endp_type_tap)
    try_send_musat(cur, "cloonix_req_tap");
  else if (cur->endp_type == endp_type_wif)
    try_send_musat(cur, "cloonix_req_wif");
  else if (cur->endp_type == endp_type_raw)
    try_send_musat(cur, "cloonix_req_raw");
  else if (cur->endp_type == endp_type_snf)
    try_send_musat(cur, "cloonix_req_snf");
  else if (cur->endp_type == endp_type_c2c)
    try_send_musat(cur, "cloonix_req_c2c");
  else if (cur->endp_type == endp_type_a2b)
    try_send_musat(cur, "cloonix_req_a2b");
  else if (cur->endp_type == endp_type_nat)
    try_send_musat(cur, "cloonix_req_nat");
  else
    KERR("%d", cur->endp_type);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_endp_beat(void *data)
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
        rpct_send_pid_req(NULL, cur->llid, type_hop_endp, cur->name, cur->num);
      else if ((cur->getsuidroot == 0) && 
               ((cur->endp_type == endp_type_tap) ||
                (cur->endp_type == endp_type_raw) ||
                (cur->endp_type == endp_type_wif)))
        try_send_musat(cur, "cloonix_req_suidroot");
      else if (cur->opensat == 0)
        send_type_req(cur);
      else if (cur->pid)
        {
        if (cur->init_munat_mac == 0)
          {
          endp_mngt_add_all_vm(cur);
          cur->init_munat_mac = 1;
          } 
        cur->periodic_count += 1;
        if (cur->periodic_count >= 10)
          {
          rpct_send_pid_req(NULL, cur->llid, type_hop_endp, cur->name, cur->num);
          cur->periodic_count = 1;
          }
        }
      }
    cur = cur->next;
    }
  clownix_timeout_add(50, timer_endp_beat, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void musat_watchdog(void *data)
{
  t_argendp *mua = (t_argendp *) data;
  t_musat *musat = musat_find_with_name(mua->name, mua->num);
  if (musat && ((!musat->llid) || (!musat->pid)))
    {
    status_reply_if_possible(0, musat, "timeout");
    KERR("%s", musat->name);
    endp_quick_death(musat->name, musat->num);
    musat_free(musat->name, musat->num);
    }
  clownix_free(mua, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void doors_recv_c2c_clone_death(int llid, int tid, char *name)
{
  t_musat *musat = musat_find_with_name(name, 0);
  event_print("End doors musat %s", name);
  if (musat)
    {
    status_reply_if_possible(0, musat, "death");
    endp_quick_death(musat->name, musat->num);
    musat_free(musat->name, musat->num);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void musat_death(void *data, int status, char *name)
{
  t_argendp *mua = (t_argendp *) data;
  t_musat *musat = musat_find_with_name(mua->name, mua->num);
  if (strcmp(name, mua->name))
    KOUT("%s %s", name, mua->name);
  if (mua->num != musat->num)
    KOUT("%s %d %d", name, mua->num, musat->num);
  event_print("End musat %s %d", name, musat->num);
  if (musat)
    {
    event_print("End musat two %s", name);
    status_reply_if_possible(0, musat, "death");
    endp_quick_death(musat->name, musat->num);
    musat_free(musat->name, musat->num);
    }
  clownix_free(mua, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static char **musat_birth_argv(t_argendp *mu)
{
  static char endp_type[MAX_NAME_LEN];
  static char net_name[MAX_NAME_LEN];
  static char name[MAX_NAME_LEN];
  static char bin_path[MAX_PATH_LEN];
  static char sock[MAX_PATH_LEN];
  static char *argv[] = {bin_path, net_name, name, sock, endp_type, NULL};
  memset(endp_type, 0, MAX_NAME_LEN);
  memset(net_name, 0, MAX_NAME_LEN);
  memset(name, 0, MAX_NAME_LEN);
  memset(bin_path, 0, MAX_PATH_LEN);
  memset(sock, 0, MAX_PATH_LEN);
  snprintf(endp_type, MAX_NAME_LEN-1, "%d", mu->endp_type);
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
  t_argendp *mu = (t_argendp *) data;
  char **argv = musat_birth_argv(mu);

//VIP
//sleep(1000000);

  execv(mu->bin_path, argv);
  return 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void create_two_endp_arg(char *name, int num, int endp_type,
                                 t_argendp **mua1, t_argendp **mua2)
{
  char *bin_path = utils_get_endp_bin_path(endp_type);
  *mua1 = (t_argendp *) clownix_malloc(sizeof(t_argendp), 4);
  *mua2 = (t_argendp *) clownix_malloc(sizeof(t_argendp), 4);
  memset(*mua1, 0, sizeof(t_argendp));
  memset(*mua2, 0, sizeof(t_argendp));
  strncpy((*mua1)->net_name, cfg_get_cloonix_name(), MAX_NAME_LEN-1);
  strncpy((*mua2)->net_name, cfg_get_cloonix_name(), MAX_NAME_LEN-1);
  strncpy((*mua1)->name, name, MAX_NAME_LEN-1);
  strncpy((*mua2)->name, name, MAX_NAME_LEN-1);
  strncpy((*mua1)->bin_path, bin_path, MAX_PATH_LEN-1);
  strncpy((*mua2)->bin_path, bin_path, MAX_PATH_LEN-1);
  strncpy((*mua1)->sock, utils_get_endp_path(name, num), MAX_PATH_LEN-1);
  strncpy((*mua2)->sock, utils_get_endp_path(name, num), MAX_PATH_LEN-1);
  (*mua1)->endp_type = endp_type;
  (*mua2)->endp_type = endp_type;
  (*mua1)->num = num;
  (*mua2)->num = num;
  if (!file_exists(bin_path, X_OK))
    KERR("%s Does not exist or not exec", bin_path);

}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int endp_mngt_connection_state_is_restfull(char *name, int num)
{
  int result = 0;
  t_musat *mu = musat_find_with_name(name, num);
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
  t_musat *mu = musat_find_with_name(name, 0);
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
  t_musat *mu = musat_find_with_name(name, 0);
  if (mu)
    {
    if (mu->endp_type != endp_type_c2c)
      KERR("%s", name);
    if (!mu->doors_fd_ready)
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
  t_argendp  *mua2 = (t_argendp  *) data;
  t_musat *mu = musat_find_with_name(mua2->name, 0);
  if (mu)
    {
    if (mu->endp_type != endp_type_c2c)
      KERR("%s", mu->name);
    if (mu->doors_fd_ready)
      {
      doors_send_c2c_clone_birth(get_doorways_llid(), 0, mua2->net_name,  
                                 mua2->name, mu->doors_fd_value, 
                                 mua2->endp_type, mua2->bin_path, 
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
int endp_mngt_start(int llid, int tid, char *name, int num, int endp_type)
{
  int result = -1;
  char *sock = utils_get_endp_path(name, num);
  t_musat *mu = musat_find_with_name(name, num);
  t_argendp  *mua1, *mua2;
  char **argv;
  if (mu == NULL)
    {
    result = 0;
    if (file_exists(sock, F_OK))
      unlink(sock);
    mu = musat_alloc(name, num, llid, tid, endp_type);
    if (!mu)
      KOUT(" ");

    event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    if ((num == 0) && (mu->endp_type != endp_type_kvm))
      layout_add_sat(name, llid);

    my_mkdir(utils_get_endp_sock_dir());
    create_two_endp_arg(name, num, endp_type, &mua1, &mua2);
    if (mu->endp_type == endp_type_c2c)
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
      clownix_timeout_add(1000, musat_watchdog, (void *) mua1, NULL, NULL);
      }
    result = 0;
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
  mu = musat_find_with_name(mc->name, mc->num);
  if (!mu)
    KERR("%s %s", mc->name, mc->lan);
  else
    {
    memset(cmd, 0, MAX_PATH_LEN);
    snprintf(cmd, MAX_PATH_LEN-1, 
             "cloonix_req_connect sock=%s lan=%s name=%s num=%d tidx=%d",
             mc->muswitch_sock, mc->lan, mc->name, mc->num, mc->tidx);
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
int endp_mngt_lan_connect(int delay, char *name, int num, int tidx, char *lan)
{
  int result = -1;
  t_muswitch_connect *mc;
  t_musat *mu = musat_find_with_name(name, num);
  char *muswitch_sock = utils_mulan_get_sock_path(lan);

  if (tidx < MAX_TRAF_ENDPOINT)
    num = 0;
  else
    num = 1;
  if (mu && (lan[0]) && (muswitch_sock[0]) && (mu->waiting_resp == 0))
    {
    result = 0;
    mc=(t_muswitch_connect *)clownix_malloc(sizeof(t_muswitch_connect), 5); 
    memset(mc, 0, sizeof(t_muswitch_connect));
    strncpy(mc->name, name, MAX_NAME_LEN-1);
    mc->num = num;
    mc->tidx = tidx;
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
int endp_mngt_lan_disconnect(char *name, int num, int tidx, char *lan)
{
  int result = -1;
  char cmd[MAX_PATH_LEN];
  t_musat *mu = musat_find_with_name(name, num);
  char *muswitch_sock = utils_mulan_get_sock_path(lan);
  if (tidx < MAX_TRAF_ENDPOINT)
    num = 0;
  else
    num = 1;
  if (mu && (lan[0]) && (muswitch_sock[0]) && (mu->waiting_resp == 0))
    {
    memset(cmd, 0, MAX_PATH_LEN);
    snprintf(cmd, MAX_PATH_LEN-1, 
             "cloonix_req_disconnect lan=%s name=%s num=%d tidx=%d",
             lan, name, num, tidx);
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
static void timer_endp_free(void *data)
{
  t_time_delay *td = (t_time_delay *) data;
  musat_free(td->name, td->num);
  clownix_free(data, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_send_muswitch_quit(char *name, int num)
{
  t_musat *mu = musat_find_with_name(name, num);
  t_time_delay *td;
  if (mu)
    {
    td = (t_time_delay *) clownix_malloc(sizeof(t_time_delay), 4); 
    memset(td, 0, sizeof(t_time_delay));
    strncpy(td->name, name, MAX_NAME_LEN-1);
    td->num = num;
    try_send_musat(mu, "cloonix_req_quit");
    mu->waiting_resp = 1;
    strcpy(mu->waiting_resp_txt, "quit");
    clownix_timeout_add(50, timer_endp_free, (void *)td, NULL, NULL);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int endp_mngt_exists(char *name, int num, int *endp_type)
{
  int result = 0;
  t_musat *mu = musat_find_with_name(name, num);
  *endp_type = 0;
  if (mu != NULL)
    {
    *endp_type = mu->endp_type;
    result = 1;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int endp_mngt_stop(char *name, int num)
{
  int result = -1;
  t_musat *mu = musat_find_with_name(name, num);
  if ((mu) && (!mu->musat_stop_done))
    {
    mu->musat_stop_done = 1;
    result = 0;
    if (endp_death(name, num))
      {
      musat_free(name, num);
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void endp_mngt_stop_all(void)
{
  t_musat *next, *cur = g_head_musat;
  while(cur)
    {
    next = cur->next;
    endp_mngt_stop(cur->name, cur->num);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int endp_mngt_get_all_llid(int **llid_tab)
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
int endp_mngt_get_all_pid(t_lst_pid **lst_pid)
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
static t_endp *fill_endp(t_musat *mu)
{
  t_endp *endp = (t_endp *) clownix_malloc(sizeof(t_endp), 11);
  memset(endp, 0, sizeof(t_endp));
  strcpy(endp->name, mu->name);
  endp->num = mu->num;
  endp->endp_type = mu->endp_type;
  memcpy(&(endp->c2c), &(mu->c2c), sizeof(t_topo_c2c));
  memcpy(&(endp->snf), &(mu->snf), sizeof(t_topo_snf));
  memcpy(endp->lan_attached, mu->lan_attached, 
         MAX_TRAF_ENDPOINT * sizeof(t_lan_attached));
  endp->next = (void *) mu->next;
  return endp;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
t_endp *endp_mngt_get_first(int *nb_endp)
{
  t_musat *mu = g_head_musat;
  t_endp *result = fill_endp(mu);
  *nb_endp = g_nb_musat;
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
t_endp *endp_mngt_get_next(t_endp *endp)
{
  t_musat *mu = (t_musat *) endp->next;
  t_endp *result = fill_endp(mu);
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
int endp_mngt_get_nb(int type)
{
  t_musat *cur = g_head_musat;
  int result = 0;
  while(cur)
    {
    if ((cur->endp_type == type) && (cur->num == 0))
      result++;
    cur = cur->next;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
int endp_mngt_get_nb_sat(void)
{
  t_musat *cur = g_head_musat;
  int result = 0;
  while(cur)
    {
    if (cur->num == 0)
      {
      if ((cur->endp_type == endp_type_tap) ||
          (cur->endp_type == endp_type_wif) ||
          (cur->endp_type == endp_type_raw) ||
          (cur->endp_type == endp_type_a2b) ||
          (cur->endp_type == endp_type_nat))
        result++;
      }
    cur = cur->next;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
int endp_mngt_get_nb_all(void)
{
  return g_nb_musat;
}

/****************************************************************************/
void endp_mngt_init(void)
{
  g_head_musat = NULL;
  g_nb_musat = 0;
  endp_init();
  clownix_timeout_add(50, timer_endp_beat, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

