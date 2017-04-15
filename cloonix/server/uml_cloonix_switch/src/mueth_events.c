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
#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "cfg_store.h"
#include "mueth_events.h"
#include "utils_cmd_line_maker.h"
#include "lan_to_name.h"
#include "mulan_mngt.h"
#include "mueth_mngt.h"


void local_recv_add_lan_eth(int llid,int tid,char *name,int eth,char *lan);


/****************************************************************************/
typedef struct t_mueth_evt
{
  char vm_name[MAX_NAME_LEN];
  int  vm_eth;
  int  rank;
  char attached_lan[MAX_NAME_LEN];
  char lan[MAX_NAME_LEN];
  int timer_lan_ko_resp;
  int llid;
  int tid;
  int count;
  struct t_mueth_evt *prev;
  struct t_mueth_evt *next;
} t_mueth_evt;
/*--------------------------------------------------------------------------*/
typedef struct t_timer_evt
{
  int timer_lan_ko_resp;
  int  llid;
  int  tid;
  char vm_name[MAX_NAME_LEN];
  int  vm_eth;
  char lan[MAX_NAME_LEN];
  int  count;
  char label[MAX_PATH_LEN];
  struct t_timer_evt *prev;
  struct t_timer_evt *next;
} t_timer_evt;
/*--------------------------------------------------------------------------*/

static t_timer_evt *g_head_timer;
static t_mueth_evt *g_head_mueth;

/****************************************************************************/
static void timer_topo_send(void *data)
{
  event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static t_mueth_evt *mueth_find_next_with_lan(t_mueth_evt *start, char *lan)
{
  t_mueth_evt *cur = start;
  if (lan[0] == 0) 
    KOUT(" ");
  if (!cur)
    cur = g_head_mueth;
  else 
    cur = cur->next;
  while(cur && (strcmp(cur->lan, lan)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_mueth_evt *mueth_find_next_with_attached_lan(t_mueth_evt *start, 
                                                      char *lan)
{
  t_mueth_evt *cur = start;
  if (lan[0] == 0) 
    KOUT(" ");
  if (!cur)
    cur = g_head_mueth;
  else
    cur = cur->next;
  while(cur && (strcmp(cur->attached_lan, lan)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_mueth_evt *mueth_find(char *vm_name, int vm_eth)
{
  t_mueth_evt *cur = g_head_mueth;
  while(cur && vm_name[0] &&
        (strcmp(cur->vm_name,vm_name) ||
        (cur->vm_eth!=vm_eth)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_mueth_evt *mueth_alloc(char *vm_name, int vm_eth)
{
  t_mueth_evt *mueth = mueth_find(vm_name, vm_eth);
  if (mueth)
    KOUT("%s %d", vm_name, vm_eth);
  mueth = (t_mueth_evt *)clownix_malloc(sizeof(t_mueth_evt), 4);
  memset(mueth, 0, sizeof(t_mueth_evt));
  strncpy(mueth->vm_name, vm_name, MAX_NAME_LEN-1);
  mueth->vm_eth = vm_eth;
  if (g_head_mueth)
    g_head_mueth->prev = mueth;
  mueth->next = g_head_mueth;
  g_head_mueth = mueth;
  return mueth;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void mueth_free(char *vm_name, int vm_eth)
{
  t_mueth_evt *mueth = mueth_find(vm_name, vm_eth);
  if (!mueth)
    KOUT("%s %d", vm_name, vm_eth);
  if (mueth->prev)
    mueth->prev->next = mueth->next;
  if (mueth->next)
    mueth->next->prev = mueth->prev;
  if (mueth == g_head_mueth)
    g_head_mueth = mueth->next;
  clownix_free(mueth, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/



/*****************************************************************************/
static t_timer_evt *timer_find(char *vm_name, int vm_eth)
{
  t_timer_evt *cur = g_head_timer;
  while(cur && vm_name[0] && 
        (strcmp(cur->vm_name,vm_name) || 
        (cur->vm_eth!=vm_eth)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_timer_evt *timer_alloc(char *vm_name, int vm_eth)
{
  t_timer_evt *timer = timer_find(vm_name, vm_eth);
  if (timer)
    KOUT("%s %d", vm_name, vm_eth);
  timer = (t_timer_evt *)clownix_malloc(sizeof(t_timer_evt), 4);
  memset(timer, 0, sizeof(t_timer_evt));
  strncpy(timer->vm_name, vm_name, MAX_NAME_LEN-1);
  timer->vm_eth = vm_eth;
  if (g_head_timer)
    g_head_timer->prev = timer;
  timer->next = g_head_timer;
  g_head_timer = timer;
  return timer;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timer_free(t_timer_evt *timer)
{
  if (timer->prev)
    timer->prev->next = timer->next;
  if (timer->next)
    timer->next->prev = timer->prev;
  if (timer == g_head_timer)
    g_head_timer = timer->next;
  clownix_free(timer, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
int mueth_event_already_in_lan(char *vm_name, int vm_eth)
{
  int result = 0;
  t_mueth_evt *mueth = mueth_find(vm_name, vm_eth);
  if ((mueth) && (mueth->attached_lan[0]))
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void resp_to_cli(t_mueth_evt *mueth,int ok,char *nm,int eth,char *lan)
{
  char info[MAX_PATH_LEN];
  if ((mueth->llid) && msg_exist_channel(mueth->llid))
    {
    if (ok)
      {
      sprintf( info, "ethvadd %s %d %s", nm, eth, lan);
      send_status_ok(mueth->llid, mueth->tid, info);
      }
    else
      {
      sprintf( info, "fail ethvadd %s %d %s", nm, eth, lan);
      send_status_ko(mueth->llid, mueth->tid, info);
      }
    }
  if (!ok)
    memset(mueth->lan, 0, MAX_NAME_LEN);
  mueth->llid = 0;
  mueth->tid = 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_evt(void *data)
{
  t_mueth_evt *mueth;
  t_timer_evt *te = (t_timer_evt *) data;
  mueth = mueth_find(te->vm_name, te->vm_eth);
  if ((mueth) && (mueth->llid) && 
      (te->timer_lan_ko_resp == mueth->timer_lan_ko_resp))
    { 
    if ((!strcmp(mueth->lan, te->lan)) &&
        (mueth->attached_lan[0] == 0))
      {
      if(msg_exist_channel(mueth->llid))
        send_status_ko(mueth->llid, mueth->tid, te->label);
      memset(mueth->lan, 0, MAX_NAME_LEN);
      mueth->llid = 0;
      mueth->tid = 0;
      KERR("%s", te->label);
      }
    }
  clownix_free(te, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void mueth_event_timer_ko_resp(int delay, char *vm_name, int vm_eth,
                               char *lan, char *label)
{
  t_timer_evt *te;
  t_mueth_evt *mueth = mueth_find(vm_name, vm_eth);
  if ((mueth) && (mueth->llid))
    {
    mueth->timer_lan_ko_resp += 1;
    te = (t_timer_evt *) clownix_malloc(sizeof(t_timer_evt), 5);
    memset(te, 0, sizeof(t_timer_evt));
    te->timer_lan_ko_resp = mueth->timer_lan_ko_resp;
    strncpy(te->vm_name, vm_name, MAX_NAME_LEN-1);
    te->vm_eth = vm_eth;
    strncpy(te->lan, lan, MAX_NAME_LEN-1);
    strncpy(te->label, label, MAX_PATH_LEN-1);
    clownix_timeout_add(delay, timer_evt, (void *) te, NULL, NULL);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_waiting_mueth(void *data)
{
  t_mueth_evt *mueth;
  t_timer_evt *te = (t_timer_evt *) data;
  char err[MAX_PATH_LEN];
  mueth = mueth_find(te->vm_name, te->vm_eth);
  if (mueth) 
    {
    local_recv_add_lan_eth(te->llid,te->tid,te->vm_name,te->vm_eth,te->lan);
    timer_free(te);
    }
  else
    {
    te->count++;
    if (te->count >= 200) 
      {
      sprintf(err, "bad mueth start: %s %d %s", 
              te->vm_name, te->vm_eth, te->lan);
      mueth_event_timer_ko_resp(1, te->vm_name, te->vm_eth, te->lan, err);
      timer_free(te);
      }
    else
      {
      clownix_timeout_add(100, timer_waiting_mueth, (void *) te, NULL, NULL);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_waiting_mueth_init(int llid, int tid, 
                                     char *vm_name, int vm_eth, char *lan)
{
  t_timer_evt *te = timer_find(vm_name, vm_eth);
  if (te)
    send_status_ko(llid, tid, "mueth waiting reserved");
  else
    { 
    te = timer_alloc(vm_name, vm_eth);
    te->llid = llid;
    te->tid = tid;
    strncpy(te->lan, lan, MAX_NAME_LEN-1);
    clownix_timeout_add(100, timer_waiting_mueth, (void *) te, NULL, NULL);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_event_admin_add_lan(int llid, int tid, 
                               char *vm_name, int vm_eth, char *lan)
{
  t_mueth_evt *mueth = mueth_find(vm_name, vm_eth);
  char *sock = utils_mulan_get_sock_path(lan);
  char err[MAX_PATH_LEN];
  if ((!lan) || (!lan[0]))
    KOUT("%s %d", vm_name, vm_eth);
  if (!mueth)
    timer_waiting_mueth_init(llid, tid, vm_name, vm_eth, lan);
  else if (mueth_exists(vm_name, vm_eth))
    {
    KERR("%s %d %s", vm_name, vm_eth, lan);
    if (msg_exist_channel(llid))
      {
      sprintf(err, "mueth record not found %s %d %s", vm_name, vm_eth, lan);
      send_status_ko(llid, tid, err);
      }
    }
  else if (mueth->lan[0])
    {
    if (msg_exist_channel(llid))
      {
      sprintf(err, "mueth connecting: %s %d %s", vm_name, vm_eth, lan);
      send_status_ko(llid, tid, err);
      }
    }
  else if (mueth->attached_lan[0])
    {
    if (msg_exist_channel(llid))
      {
      sprintf(err, "mueth connected: %s %d %s", vm_name, vm_eth, lan);
      send_status_ko(llid, tid, err);
      }
    }
  else if (!mueth_ready(vm_name, vm_eth))
    {
    if (msg_exist_channel(llid))
      {
      sprintf(err, "mueth is not ready: %s %d %s", vm_name, vm_eth, lan);
      send_status_ko(llid, tid, err);
      }
    }
  else
    {
    if (mueth->llid)
      KERR("%s %d %s", vm_name, vm_eth, lan);
    mueth->llid = 0;
    if (!(mulan_exists(lan)))
      {
      if (mulan_start(lan, 1, vm_name, vm_eth))
        {
        sprintf(err, "bad mulan start: %s %d %s", vm_name, vm_eth, lan);
        send_status_ko(llid, tid, err);
        }
      else
        {
        mueth->llid = llid;
        mueth->tid = tid;
        strncpy(mueth->lan, lan, MAX_NAME_LEN-1);
        sprintf(err, "mulan timeout start: %s %d %s", vm_name, vm_eth, lan);
        mueth_event_timer_ko_resp(2000, vm_name, vm_eth, lan, err);
        }
      }
    else
      {
      if (mulan_is_zombie(lan))
        {
        KERR("%s %d %s", vm_name, vm_eth, lan);
        if (msg_exist_channel(llid))
          {
          sprintf(err, "mulan is zombie: %s %d %s", vm_name, vm_eth, lan);
          send_status_ko(llid, tid, err);
          }
        }
      else
        {
        mueth->llid = llid;
        mueth->tid = tid;
        strncpy(mueth->lan, lan, MAX_NAME_LEN-1);
        if (mulan_is_oper(lan))
          {
          if (mueth_send_muswitch_connect(1, vm_name, vm_eth,  lan, sock))
            KERR("%s %d %s", vm_name, vm_eth, lan);
          }
        }
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int mueth_event_lan_is_in_use(char *lan)
{
  int result = 0;
  if ((!lan) || (!lan[0]))
    KOUT(" ");
  if (mueth_find_next_with_lan(NULL, lan))
    result = 1;
  if (mueth_find_next_with_attached_lan(NULL, lan))
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
int mueth_event_admin_del_lan(char *vm_name, int vm_eth, char *lan)
{
  t_mueth_evt *mueth = mueth_find(vm_name, vm_eth);
  int lan_num, result = -1;
  char *sock = utils_mulan_get_sock_path(lan);
  if ((!lan) || (!lan[0]))
    KOUT("%s %d", vm_name, vm_eth);
  lan_num = lan_get_with_name(lan);
  if ((lan_num <= 0) || (lan_num >= MAX_LAN))
    KERR("%s %d %s %d", vm_name, vm_eth, lan, lan_num);
  else
    {
    if (cfg_unset_eth_lan(vm_name, vm_eth, lan))
      KERR("%s %d %s", vm_name, vm_eth, lan);
    if (!mueth)
      KERR("%s %d %s", vm_name, vm_eth, lan);
    else
      {
      if (mueth_send_muswitch_disconnect(vm_name, vm_eth, lan, sock))
        KERR("%s %d %s", vm_name, vm_eth, lan);
      memset(mueth->lan, 0, MAX_NAME_LEN);
      memset(mueth->attached_lan, 0, MAX_NAME_LEN);
      mueth->llid = 0;
      mueth->tid = 0;
      mulan_test_stop(lan);
      clownix_timeout_add(10, timer_topo_send, NULL, NULL, NULL);
      result = 0;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_event_connect_OK(char *name, int eth, char *lan, int rank)
{
  t_mueth_evt *mueth = mueth_find(name, eth);
  if (!lan[0])
    KERR(" ");
  else if (!mueth)
    KERR("%s %d %s", name, eth, lan);
  else if (strcmp(mueth->lan, lan))
    KERR("%s %d %s", name, eth, lan);
  else
    {
    strncpy(mueth->attached_lan, mueth->lan, MAX_NAME_LEN-1);
    mueth->rank = rank;
    memset(mueth->lan, 0, MAX_NAME_LEN);
    if (cfg_set_eth_lan(name, eth, lan, mueth->llid))
      KOUT("%s %d", name, eth);
    resp_to_cli(mueth, 1, name, eth, lan);
    clownix_timeout_add(10, timer_topo_send, NULL, NULL, NULL);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_event_connect_KO(char *name, int eth, char *lan)
{
  t_mueth_evt *mueth = mueth_find(name, eth);
  if (!lan[0])
    KERR("%s %d %s", name, eth, lan);
  else if (!mueth)
    KERR("%s %d %s", name, eth, lan);
  else if (strcmp(mueth->lan, lan))
    KERR("%s %d %s %s", name, eth, mueth->lan, lan);
  else 
    resp_to_cli(mueth, 0, name, eth, lan);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_event_birth(char *name, int eth)
{
  t_mueth_evt *mueth = mueth_find(name, eth);
  if (mueth)
    KERR("%s %d", name, eth);
  else
    mueth_alloc(name, eth);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_event_death(char *name, int eth)
{
  t_mueth_evt *mueth = mueth_find(name, eth);
  if (!mueth)
    KERR("%s %d", name, eth);
  else
    {
    if (strlen(mueth->attached_lan))
      {
      if (mueth_event_admin_del_lan(name, eth, mueth->attached_lan))
        KERR("%s %d %s", name, eth, mueth->attached_lan);
      }
    mueth_free(name, eth);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_event_mulan_death(char *lan)
{
  t_mueth_evt *cur, *next;
  if ((!lan) || (lan[0] == 0))
    KOUT(" ");
  cur = mueth_find_next_with_lan(NULL, lan);
  while (cur)
    {
    if (cur->llid)
      {
      if (msg_exist_channel(cur->llid))
        send_status_ko(cur->llid, cur->tid, "mulan death");
      memset(cur->lan, 0, MAX_NAME_LEN);
      cur->llid = 0;
      cur->tid = 0;
      }
    next = mueth_find_next_with_lan(cur, lan);
    cur = next;
    }
  cur = mueth_find_next_with_attached_lan(NULL, lan);
  while (cur)
    {
    next = mueth_find_next_with_attached_lan(cur, lan);
    mueth_event_admin_del_lan(cur->vm_name, cur->vm_eth, lan);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_event_mulan_birth(char *lan)
{
  t_mueth_evt *cur, *next;
  char *sock = utils_mulan_get_sock_path(lan);
  if ((!lan) || (!lan[0]))
    KOUT(" ");
  cur = mueth_find_next_with_lan(NULL, lan);
  while (cur)
    {
    if (mueth_send_muswitch_connect(10, cur->vm_name, cur->vm_eth,
                                    cur->lan, sock))
      KERR("%s %d %s", cur->vm_name, cur->vm_eth, cur->lan);
    next = mueth_find_next_with_lan(cur, lan);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void mueth_event_init(void)
{
  g_head_mueth = NULL;
  g_head_timer = NULL;
}
/*--------------------------------------------------------------------------*/



