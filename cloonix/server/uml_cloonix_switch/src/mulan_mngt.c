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
#include "pid_clone.h"
#include "utils_cmd_line_maker.h"
#include "system_callers.h"
#include "llid_trace.h"
#include "file_read_write.h"
#include "lan_to_name.h"
#include "mueth_mngt.h"
#include "musat_mngt.h"
#include "mueth_events.h"
#include "musat_events.h"
#include "automates.h"
#include "hop_event.h"


void uml_clownix_switch_error_cb(void *ptr, int llid, int err, int from);
void uml_clownix_switch_rx_cb(int llid, int len, char *buf);
void murpc_dispatch_send_tx_flow_control(int llid, int rank, int stop);

enum {
  traffic_lan_link_idle = 0,
  traffic_lan_link_wait,
  traffic_lan_link_done,
};

/****************************************************************************/
typedef struct t_zombie_kill
{
  char name[MAX_NAME_LEN];
  int pid_to_kill;
  int count;
  struct t_zombie_kill *prev;
  struct t_zombie_kill *next;
} t_zombie_kill;
/*--------------------------------------------------------------------------*/


/****************************************************************************/
typedef struct t_mulan
{
  char name[MAX_NAME_LEN];
  char sock[MAX_PATH_LEN];
  char key[MAX_PATH_LEN];
  char traf[MAX_PATH_LEN];
  int llid;
  int clone_start_pid;
  int pid;
  int traffic_lan_link_state;
  char start_vm[MAX_NAME_LEN];
  int  start_eth;
  char start_sat[MAX_NAME_LEN];
  int periodic_count;
  struct t_mulan *prev;
  struct t_mulan *next;
} t_mulan;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
typedef struct t_mulan_arg
{
  char name[MAX_NAME_LEN];
  char sock[MAX_PATH_LEN];
} t_mulan_arg;
/*--------------------------------------------------------------------------*/


static t_mulan *g_head_mulan;
static t_zombie_kill *g_head_zombie;


/****************************************************************************/
static int try_rpct_send_diag_msg(char *name, int llid, int pid, char *msg)
{
  int result = -1;
  if (llid)
    {
    if (msg_exist_channel(llid))
      {
      hop_event_hook(llid, FLAG_HOP_DIAG, msg);
      rpct_send_diag_msg(NULL, llid, pid, msg);
      result = 0;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_mulan *mulan_find_with_name(char *name)
{
  t_mulan *cur = g_head_mulan;
  while(cur && (strcmp(cur->name, name)))
    cur = cur->next;
  return cur;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
int mulan_exists(char *lan)
{
  int result = 0;
  if (mulan_find_with_name(lan))
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_zombie_kill(void *data)
{
  t_zombie_kill *zk = (t_zombie_kill *) data;
  if (mulan_exists(zk->name))
    {
    KERR("Retime for zombie: %s", zk->name);
    clownix_timeout_add(500, timer_zombie_kill, (void *) zk, NULL, NULL);
    zk->count += 1;
    if (zk->count > 3)
      {
      if (!zk->pid_to_kill)
        KERR("%s", zk->name);
      else
        {
        if (!kill(zk->pid_to_kill, SIGTERM))
          KERR("Emergency SIGTERM kill for %s", zk->name);
        else
          KERR("Fail Emergency SIGTERM kill for %s", zk->name);
        }
      }
    }
  else
    {
    if (zk->next)
      zk->next->prev = zk->prev;
    if (zk->prev)
      zk->prev->next = zk->next;
    if (zk == g_head_zombie)
      g_head_zombie = zk->next;
    clownix_free(zk, __FUNCTION__);
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static t_zombie_kill *zombie_find_with_name(char *name)
{
  t_zombie_kill *cur = g_head_zombie;
  while(cur && (strcmp(cur->name, name)))
    cur = cur->next;
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void trigger_zombie_kill(char *name, int llid, int pid_to_kill)
{
  t_zombie_kill *zk = zombie_find_with_name(name);
  if (zk)
    {
    if (zk->pid_to_kill != pid_to_kill)
      KERR("%s %d %d", name, zk->pid_to_kill, pid_to_kill);
    }
  else
    {
    mueth_event_mulan_death(name);
    musat_event_mulan_death(name);
    try_rpct_send_diag_msg(name, llid, pid_to_kill, "cloonix_req_quit");
    zk = (t_zombie_kill *) clownix_malloc(sizeof(t_zombie_kill), 4);
    memset(zk, 0,  sizeof(t_zombie_kill));
    strncpy(zk->name, name, MAX_NAME_LEN-1);
    zk->pid_to_kill = pid_to_kill;
    if (g_head_zombie)
      g_head_zombie->prev = zk;
    zk->next = g_head_zombie;
    g_head_zombie = zk;
    clownix_timeout_add(500, timer_zombie_kill, (void *) zk, NULL, NULL);
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void trace_alloc(t_mulan *mulan)
{
  char *sock = mulan->sock;
  char *name = mulan->name;
  int llid;
  llid = string_client_unix(sock, uml_clownix_switch_error_cb, 
                                  uml_clownix_switch_rx_cb, "mulan");
  if (llid)
    {
    mulan->llid = llid;
    if (hop_event_alloc(llid, type_hop_mulan, name, 0))
       KERR("BAD HOP CONNECT %s", name);
    llid_trace_alloc(llid, name, 0, 0, type_llid_trace_mulan);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_mulan *mulan_find_with_llid(int llid)
{
  t_mulan *cur = g_head_mulan;
  if ((llid <1) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  while(cur && (cur->llid != llid))
    cur = cur->next;
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mulan_can_be_found_with_llid(int llid, char *name)
{
  t_mulan *cur = g_head_mulan;
  memset(name, 0, MAX_NAME_LEN);
  if ((llid <1) || (llid >= CLOWNIX_MAX_CHANNELS))
    KOUT("%d", llid);
  while(cur && (cur->llid != llid))
    cur = cur->next;
  if (cur)
    {
    strncpy(name, cur->name, MAX_NAME_LEN-1); 
    return 1;
    }
  else
    return 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mulan_can_be_found_with_name(char *name)
{
  int result = 0;
  t_mulan *cur = mulan_find_with_name(name);
  if (cur)
    {
    if (msg_exist_channel(cur->llid))
    result = cur->llid;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static char *get_key_path(char *name)
{
  static char path[MAX_PATH_LEN];
  memset(path, 0, MAX_PATH_LEN);
  snprintf(path,MAX_PATH_LEN-1,"%s/%s",utils_get_muswitch_key_dir(),name);
  return path;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static char *get_traf_path(char *name)
{
  static char path[MAX_PATH_LEN];
  memset(path, 0, MAX_PATH_LEN);
  snprintf(path,MAX_PATH_LEN-1,"%s/%s",utils_get_muswitch_traf_dir(),name);
  return path;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_mulan *mulan_alloc(char *name, int start_is_vm,
                            char *start_name, int start_eth)
{
  t_mulan *mulan = NULL;
  if (name[0] == 0)
    KOUT(" ");
  if (!mulan_find_with_name(name))
    {
    mulan = (t_mulan *) clownix_malloc(sizeof(t_mulan), 4);
    memset(mulan, 0, sizeof(t_mulan));
    strncpy(mulan->name, name, MAX_NAME_LEN-1);
    strncpy(mulan->sock, utils_mulan_get_sock_path(name), MAX_PATH_LEN-1);
    strncpy(mulan->key, get_key_path(name), MAX_PATH_LEN-1);
    strncpy(mulan->traf, get_traf_path(name), MAX_PATH_LEN-1);
    if (start_is_vm)
      strncpy(mulan->start_vm, start_name, MAX_NAME_LEN-1);
    else
      strncpy(mulan->start_sat, start_name, MAX_NAME_LEN-1);
    mulan->start_eth = start_eth;
    if (g_head_mulan)
      g_head_mulan->prev = mulan;
    mulan->next = g_head_mulan;
    g_head_mulan = mulan; 
    inc_lock_self_destruction_dir();
    }
  return mulan;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void mulan_request_quit(t_mulan *mulan)
{
  trigger_zombie_kill(mulan->name, mulan->llid, mulan->clone_start_pid);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int  mulan_get_all_llid(int **llid_tab)
{
  t_mulan *cur = g_head_mulan;
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
    cur = g_head_mulan;
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
int  mulan_get_all_pid(t_lst_pid **lst_pid)
{
  t_lst_pid *glob_lst = NULL;
  t_mulan *cur = g_head_mulan;
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
    cur = g_head_mulan;
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
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void mulan_pid_resp(int llid, char *name, int pid)
{
  t_mulan *mulan = mulan_find_with_llid(llid);
  if (mulan)
    {
    if (strcmp(name, mulan->name))
      KERR("%s %s", name, mulan->name);
    if (mulan->pid == 0)
      {
      if (mulan->clone_start_pid != pid)
        {
        KERR("WRONG PID %s %d %d", name, pid, mulan->clone_start_pid);
        if (mulan->clone_start_pid == 0)
          {
          KERR("MODIFYING START PID %s %d", name, pid);
          mulan->clone_start_pid = pid;
          }
        }
      else
        mulan->pid = pid;
      }
    else
      {
      if (mulan->pid != pid)
        KERR("%s %d %d", name, pid, mulan->pid);
      }
    }
  else
    KERR("%s %d", name, pid);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int llid_flow_to_restrict(char *name)
{
  char *ptr;
  int eth, musat_type;
  int llid = musat_mngt_can_be_found_with_name(name, &musat_type);
  char vm_name[MAX_NAME_LEN];
  if (!llid)
    {
    memset(vm_name, 0, MAX_NAME_LEN);
    strncpy(vm_name, name, MAX_NAME_LEN-1);
    ptr = strrchr(vm_name, '_');
    if (ptr)
      {
      if (sscanf(ptr, "_%d", &eth) == 1)
        {
        *ptr = 0;
        llid = mueth_can_be_found_with_name(vm_name, eth);
        }
      }
    }
  llid = 0;
//TODO
/*
  if (!llid)
    KERR("%s", name);
  else
    {
    if (musat_type == musat_type_c2c)
      {
      llid = 0;
      KERR("%s", name);
      }
    }
*/
  return llid;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mulan_rpct_recv_evt_msg(int llid, int tid, char *line)
{
  int rank, stop;
  char nm[MAX_NAME_LEN];
  t_mulan *mulan = mulan_find_with_llid(llid);
  if (mulan)
    {
    if (sscanf(line, "cloonix_evt_peer_flow_control=%s rank=%d stop=%d",
                     nm, &rank, &stop) == 3)
      {
      llid = llid_flow_to_restrict(nm);
      if (llid)
        murpc_dispatch_send_tx_flow_control(llid, rank, stop);
      }
    }
  else
    KERR("%s", line);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mulan_rpct_recv_diag_msg(int llid, int tid, char *line)
{
  char tmpbuf[MAX_PATH_LEN];
  char *lan;
  t_mulan *mulan = mulan_find_with_llid(llid);
  if (mulan)
    {
    lan = mulan->name;
    if (!strcmp(line, "cloonix_resp_quit"))
      {
      }
    else if (sscanf(line, "cloonix_resp_listen_ok=%s", tmpbuf))
      {
      if (mulan->traffic_lan_link_state == traffic_lan_link_wait)
        {
        if (!strcmp(tmpbuf, mulan->traf))
          {
          mulan->traffic_lan_link_state = traffic_lan_link_done; 
          mueth_event_mulan_birth(lan);
          musat_event_mulan_birth(lan);
          }
        else
          KERR("%s %s %s", lan, mulan->traf, tmpbuf);
        }
      else
        KERR("%s %s", lan, tmpbuf);
      }
    else if (sscanf(line, "cloonix_resp_listen_ko=%s", tmpbuf))
      {
      KERR("%s %s", lan, tmpbuf);
      mulan_request_quit(mulan);
      if (mulan->start_vm[0])
        {
        mueth_event_timer_ko_resp(1, mulan->start_vm, 
                                  mulan->start_eth, lan, "alloc unix ko"); 
        }
      else if (mulan->start_sat[0])
        {
        musat_event_timer_ko_resp(1, mulan->start_sat, 
                                  mulan->start_eth, lan, "alloc unix ko");
        }
      }
    else if (!strcmp(line, "SELF-DESTROYING"))
      {
      }
    else
      KERR("%s", line);
    } 
  else
    KERR("%s", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void mulan_err_cb (int llid)
{
  t_mulan *mulan = mulan_find_with_llid(llid);
  if (mulan)
    {
    event_print("%s %s", __FUNCTION__, mulan->name);
    if (mulan->llid != llid)
      KERR("BAD  %d %d", mulan->llid, llid);
    mulan->llid = 0;
    trigger_zombie_kill(mulan->name, llid, mulan->clone_start_pid);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void mulan_death(void *data, int status, char *name)
{
  t_mulan_arg *mu = (t_mulan_arg *) data;
  t_mulan *mulan = mulan_find_with_name(mu->name);
  if (strcmp(name, mu->name))
    KOUT("%s %s", name, mu->name);
  event_print("End muswitch %s", name);
  if (!mulan)
    KERR("%s", name);
  else
    {
    if (mulan->llid)
      llid_trace_free(mulan->llid, 0, __FUNCTION__);
    mueth_event_mulan_death(mulan->name);
    musat_event_mulan_death(mulan->name);
    unlink(mulan->sock);
    unlink(mulan->traf);
    if (mulan->prev)
      mulan->prev->next = mulan->next;
    if (mulan->next)
      mulan->next->prev = mulan->prev;
    if (mulan == g_head_mulan)
      g_head_mulan = mulan->next;
    clownix_free(mulan, __FUNCTION__);
    dec_lock_self_destruction_dir();
    }
  clownix_free(mu, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static char **mulan_birth_argv(t_mulan_arg *mu)
{
  static char bin_path[MAX_PATH_LEN];
  static char sock[MAX_PATH_LEN];
  static char *argv[] = {bin_path, sock, NULL};
  memset(sock, 0, MAX_PATH_LEN);
  snprintf(sock, MAX_PATH_LEN-1, "%s", mu->sock);
  memset(bin_path, 0, MAX_PATH_LEN);
  snprintf(bin_path, MAX_PATH_LEN-1, "%s", utils_get_muswitch_bin_path());
  return argv;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int mulan_birth(void *data)
{
  char **argv = (char **) data;
  char *bin_path = utils_get_muswitch_bin_path();
  my_mkdir(utils_get_muswitch_sock_dir());
  my_mkdir(utils_get_muswitch_key_dir());
  my_mkdir(utils_get_muswitch_traf_dir());


//VIP
//sleep(10000000);
  execv(bin_path, argv);

  return 0;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static void timer_mulan_watchdog(void *data)
{
  t_mulan_arg *mu = (t_mulan_arg *) data;
  t_mulan *mulan = mulan_find_with_name(mu->name);
  if (mulan)
    {
    if ((!mulan->llid) || (!mulan->pid))
      KERR("%s", mu->name);
    }
  clownix_free(mu, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mulan_start(char *lan, int start_is_vm, char *name, int eth)
{
  int pid;
  char **argv;
  int result = -1;
  t_mulan_arg *mu1, *mu2;
  t_mulan *mulan = mulan_find_with_name(lan);
  if (mulan)
    KERR("mulan %s exists", lan);
  else if (zombie_find_with_name(lan))
    KERR("zombie of mulan %s exists", lan);
  else
    {
    result = 0;
    if (file_exists(utils_mulan_get_sock_path(lan), F_OK))
      unlink(utils_mulan_get_sock_path(lan));
    if (file_exists(get_key_path(lan), F_OK))
      unlink(get_key_path(lan));
    if (file_exists(get_traf_path(lan), F_OK))
      unlink(get_traf_path(lan));
    mulan = mulan_alloc(lan, start_is_vm, name, eth);
    if (!mulan)
      KOUT("Exists %s", lan);
    mu1 = (t_mulan_arg *) clownix_malloc(sizeof(t_mulan_arg), 4);
    mu2 = (t_mulan_arg *) clownix_malloc(sizeof(t_mulan_arg), 4);
    memset(mu1, 0, sizeof(t_mulan_arg));
    memset(mu2, 0, sizeof(t_mulan_arg));
    strncpy(mu1->name, mulan->name, MAX_NAME_LEN-1);
    strncpy(mu1->sock, mulan->sock, MAX_PATH_LEN-1);
    strncpy(mu2->name, mulan->name, MAX_NAME_LEN-1);
    strncpy(mu2->sock, mulan->sock, MAX_PATH_LEN-1);
    clownix_timeout_add(300, timer_mulan_watchdog, (void *) mu1, NULL, NULL);
    argv = mulan_birth_argv(mu2);
    utils_send_creation_info("mulan", argv);
    pid = pid_clone_launch(mulan_birth, mulan_death, NULL,
                           argv, mu2, NULL, mu2->name, -1, 1);
    mulan->clone_start_pid = pid;

//VIP
//    mulan->clone_start_pid = 0;

    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void mulan_test_stop(char *lan)
{
  t_mulan *mulan = mulan_find_with_name(lan);
  if (mulan)
    {
    if (!mueth_event_lan_is_in_use(lan))
      {
      if (!musat_event_lan_is_in_use(lan, 0))
        {
        if (!musat_event_lan_is_in_use(lan, 1))
          mulan_request_quit(mulan);
        }
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_mulan_beat(void *data)
{
  t_mulan *cur = g_head_mulan;
  char cmd[MAX_PATH_LEN];
  while(cur)
    {
    if (cur->periodic_count == 0)
      cur->periodic_count += 1;
    else if (cur->llid == 0)
      trace_alloc(cur);
    else if (cur->pid == 0) 
      rpct_send_pid_req(NULL, cur->llid, type_hop_mulan, 
                       cloonix_get_sec_offset(), cur->name);
    else if (cur->traffic_lan_link_state == traffic_lan_link_idle)
      {
      memset(cmd, 0, MAX_PATH_LEN);
      snprintf(cmd,MAX_PATH_LEN-1,"cloonix_req_listen=%s lan=%s",
                                  cur->traf, cur->name);
      if (!try_rpct_send_diag_msg(cur->name, cur->llid, cur->pid, cmd))
        cur->traffic_lan_link_state = traffic_lan_link_wait; 
      }

    if (cur->pid) 
      {
      cur->periodic_count += 1;
      if (cur->periodic_count >= 10)
        {
        rpct_send_pid_req(NULL, cur->llid, type_hop_mulan, 
                         cloonix_get_sec_offset(), cur->name);
        cur->periodic_count = 1;
        }
      }
    cur = cur->next;
    }
  clownix_timeout_add(50, timer_mulan_beat, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void mulan_del_all(void)
{
  t_mulan *next, *cur = g_head_mulan;
  while(cur)
    {
    next = cur->next;
    mulan_request_quit(cur);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mulan_is_zombie(char *lan)
{
  int result = 0;
  if (zombie_find_with_name(lan))
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int mulan_is_oper(char *lan)
{
  int result = 0;
  t_mulan *cur = mulan_find_with_name(lan);
  if (cur)
    {
    if (cur->pid)
      {
      if (cur->traffic_lan_link_state == traffic_lan_link_done)
        result = 1;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void mulan_init(void)
{
  g_head_mulan = NULL;
  clownix_timeout_add(50, timer_mulan_beat, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

