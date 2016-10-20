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
#include <stdint.h>
#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "cfg_store.h"
#include "musat_events.h"
#include "utils_cmd_line_maker.h"
#include "lan_to_name.h"
#include "mulan_mngt.h"
#include "musat_mngt.h"


/****************************************************************************/
typedef struct t_attached
{
  char attached_lan[MAX_NAME_LEN];
  char waiting_lan[MAX_NAME_LEN];
  int llid;
  int tid;
  int timer_lan_ko_resp;
  int rank;
} t_attached;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
typedef struct t_musat_evt
{
  char name[MAX_NAME_LEN];
  t_attached atlan[2];
  struct t_musat_evt *prev;
  struct t_musat_evt *next;
} t_musat_evt;
/*--------------------------------------------------------------------------*/
typedef struct t_timer_evt
{
  int timer_lan_ko_resp;
  char name[MAX_NAME_LEN];
  char lan[MAX_NAME_LEN];
  char label[MAX_PATH_LEN];
  int num;
} t_timer_evt;
/*--------------------------------------------------------------------------*/

static t_musat_evt *g_head_musat;


/*****************************************************************************/
static t_musat_evt *musat_find(char *name)
{
  t_musat_evt *cur = g_head_musat;
  while(cur && name[0] && (strcmp(cur->name,name)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int musat_event_exists(char *name)
{
  if (musat_find(name))
    return 1;
  else
    return 0;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static t_attached *musat_atlan_find(char *name, int num)
{
  t_musat_evt *musat = musat_find(name);
  t_attached *atlan = NULL;
  if (musat)
    {
    if ((num != 0) && (num != 1))
      KOUT("%s %d", name, num);
    atlan = &(musat->atlan[num]);
    }
  return atlan;
}
/*---------------------------------------------------------------------------*/


/****************************************************************************/
static void init_waiting_lan(char *name, int num, 
                             char *lan, int llid, int tid)
{
  t_attached *atlan = musat_atlan_find(name, num);
  if (!atlan)
    KOUT("%s", name);
  if (lan == NULL)
    {
    memset(atlan->waiting_lan, 0, MAX_NAME_LEN);
    atlan->llid = 0;
    atlan->tid = 0;
    }
  else 
    {
    if (strlen(lan) == 0)
      KOUT(" ");
    if (strlen(atlan->waiting_lan))
      KOUT("%s", atlan->waiting_lan);
    memset(atlan->waiting_lan, 0, MAX_NAME_LEN);
    strncpy(atlan->waiting_lan, lan, MAX_NAME_LEN-1);
    atlan->llid = llid;
    atlan->tid = tid;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static t_musat_evt *musat_find_next_with_lan(t_musat_evt *start, 
                                             char *lan, int num)
{
  t_musat_evt *cur = start;
  if (!lan[0])
    KOUT(" ");
  if (!cur)
    cur = g_head_musat;
  else 
    cur = cur->next;
  while(cur && (strcmp(cur->atlan[num].waiting_lan, lan)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_musat_evt *musat_find_next_with_attached_lan(t_musat_evt *start, 
                                                      char *lan, int num)
{
  t_musat_evt *cur = start;
  if (!lan[0])
    KOUT(" ");
  if (!cur)
    cur = g_head_musat;
  else
    cur = cur->next;
  while(cur && (strcmp(cur->atlan[num].attached_lan, lan)))
    cur = cur->next;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *musat_get_attached_lan(char *name, int num)
{
  char *result  = NULL;
  t_attached *atlan = musat_atlan_find(name, num);
  if ((atlan) && (strlen(atlan->attached_lan)))
    result = atlan->attached_lan;
  return result;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static t_musat_evt *musat_evt_alloc(char *name)
{
  t_musat_evt *musat = musat_find(name);
  if (musat)
    KOUT("%s ", name);
  musat = (t_musat_evt *)clownix_malloc(sizeof(t_musat_evt), 4);
  memset(musat, 0, sizeof(t_musat_evt));
  strncpy(musat->name, name, MAX_NAME_LEN-1);
  if (g_head_musat)
    g_head_musat->prev = musat;
  musat->next = g_head_musat;
  g_head_musat = musat;
  init_waiting_lan(name, 0, NULL, 0, 0);
  init_waiting_lan(name, 1, NULL, 0, 0);
  return musat;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void musat_free(char *name)
{
  t_musat_evt *musat = musat_find(name);
  if (musat)
    {
    if (musat->prev)
      musat->prev->next = musat->next;
    if (musat->next)
      musat->next->prev = musat->prev;
    if (musat == g_head_musat)
      g_head_musat = musat->next;
    clownix_free(musat, __FUNCTION__);
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
int musat_event_already_in_lan(char *name, int num)
{
  int result = 0;
  t_attached *atlan = musat_atlan_find(name, num);
  if ((atlan) && (strlen(atlan->attached_lan)))
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void resp_to_cli(char *nm, int llid, int tid, int ok, char *lan)
{
  char info[MAX_PATH_LEN];
  if (llid && msg_exist_channel(llid))
    {
    if (ok)
      {
      sprintf( info, "ethvadd %s %s", nm, lan);
      send_status_ok(llid, tid, info);
      }
    else
      {
      sprintf( info, "ethvadd %s %s", nm, lan);
      send_status_ko(llid, tid, info);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_evt(void *data)
{
  t_attached *atlan;
  t_timer_evt *te = (t_timer_evt *) data;
  atlan = musat_atlan_find(te->name, te->num);
  if ((atlan) && (atlan->llid) && 
      (strlen(atlan->waiting_lan)) && 
      (te->timer_lan_ko_resp == atlan->timer_lan_ko_resp))
    {
    if (strcmp(atlan->waiting_lan, te->lan))
      KERR("%s %s", atlan->waiting_lan, te->lan);
    else 
      {
      if (strlen(atlan->attached_lan) == 0)
        {
        if (msg_exist_channel(atlan->llid))
          send_status_ko(atlan->llid, atlan->tid, te->label);
        init_waiting_lan(te->name, te->num, NULL, 0, 0);
        KERR("%s", te->label);
        }
      }
    }
  clownix_free(te, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void musat_event_timer_ko_resp(int delay, char *name, int num,
                               char *lan, char *reason)
{
  t_attached *atlan = musat_atlan_find(name, num);
  t_timer_evt *te;
  if ((atlan) && (atlan->llid))
    {
    atlan->timer_lan_ko_resp += 1;
    te = (t_timer_evt *) clownix_malloc(sizeof(t_timer_evt), 5);
    memset(te, 0, sizeof(t_timer_evt));
    te->timer_lan_ko_resp = atlan->timer_lan_ko_resp;
    strncpy(te->name, name, MAX_NAME_LEN-1);
    te->num = num;
    strncpy(te->lan, lan, MAX_NAME_LEN-1);
    strncpy(te->label, reason, MAX_PATH_LEN-1);
    clownix_timeout_add(delay, timer_evt, (void *) te, NULL, NULL);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void do_add_lan(int llid, int tid, char *name, int num, 
                       t_musat_evt *musat, char *sock, char *lan)
{
  if (!(mulan_exists(lan)))
    {
    if (mulan_start(lan, 0, name, num))
      {
      send_status_ko(llid, tid, "bad mulan start");
      }
    else
      {
      init_waiting_lan(name, num, lan, llid, tid); 
      musat_event_timer_ko_resp(2000, name, num, lan, 
                                "timeout start mulan");
      }
    } 
  else
    {   
    if (mulan_is_zombie(lan))
      {
      KERR("%s %s", name, lan);
      if (msg_exist_channel(llid))
        send_status_ko(llid, tid, "mulan zombie");
      }
    else
      {
      init_waiting_lan(name, num, lan, llid, tid); 
      if (mulan_is_oper(lan))
        {
        if (musat_mngt_send_mulan_connect(1, name, num, lan, sock))
          KERR("%s %s", name, lan);
        }
      }
    }
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
void musat_event_admin_add_lan(int llid, int tid, 
                               char *name, int num, char *lan)
{
  t_musat_evt *musat = musat_find(name);
  t_attached *atlan = musat_atlan_find(name, num);
  int musat_type;
  char *sock = utils_mulan_get_sock_path(lan);
  if ((!lan) || (!lan[0]))
    KOUT("%s", name);
  if (musat_mngt_get_type(name, &musat_type))
    {
    KERR("%s %s", name, lan);
    if (msg_exist_channel(llid))
      send_status_ko(llid, tid, "musat record should be present");
    }
  else if ((!musat) || (!atlan))
    {
    if (msg_exist_channel(llid))
      {
      if (musat_mngt_is_c2c(musat_type))
        send_status_ko(llid, tid, "c2c exists only when connected to peer");
      else
        send_status_ko(llid, tid, "musat not found");
      }
    }
  else if (musat_mngt_get_type(name, &musat_type))
    {
    KERR("%s %s", name, lan);
    if (msg_exist_channel(llid))
      send_status_ko(llid, tid, "musat record should be present");
    }
  else if ((musat_type != musat_type_tap) &&
           (musat_type != musat_type_snf) &&
           (musat_type != musat_type_c2c) &&
           (musat_type != musat_type_nat) &&
           (musat_type != musat_type_a2b) &&
           (musat_type != musat_type_wif))
    KOUT("%d", musat_type);
  else if (!musat_mngt_connection_state_is_restfull(name))
    {
    if (msg_exist_channel(llid))
      send_status_ko(llid, tid, "musat is not restfull");
    }
  else if (strlen((atlan->waiting_lan)))
    {
    if (msg_exist_channel(llid))
      send_status_ko(llid, tid, "musat connecting");
    }
  else if (strlen((atlan->attached_lan)))
    {
    if (msg_exist_channel(llid))
      send_status_ko(llid, tid, "musat connected");
    }
  else
    do_add_lan(llid, tid, name, num, musat, sock, lan);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int musat_event_lan_is_in_use(char *lan, int num)
{
  int result = 0;
  if ((!lan) || (!lan[0]))
    KOUT(" ");
  if ((num != 0) && (num != 1))
    KOUT("%s %d", lan, num);
  if ((musat_find_next_with_lan(NULL, lan, num)) || 
      (musat_find_next_with_attached_lan(NULL, lan, num)))
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int musat_event_admin_del_lan(char *name, int num, char *lan)
{
  t_musat_evt *musat = musat_find(name);
  t_attached *atlan = musat_atlan_find(name, num);
  int lan_num, result = -1;
  char *sock;
  if ((!lan) || (!lan[0]))
    KOUT("%s", name);
  lan_num = lan_get_with_name(lan);
  if ((lan_num <= 0) || (lan_num >= MAX_LAN))
    KERR("%s %d %s %d", name, num, lan, lan_num);
  else
    {
    if (cfg_unset_tux_lan(name, num, lan))
      KERR("%s %d %s", name, num, lan);
    if ((!musat) || (!atlan))
      KERR("%s %s", name, lan);
    else if (strcmp(lan, atlan->attached_lan))
      KERR("%s %s", lan, atlan->attached_lan);
    else
      {
      sock = utils_mulan_get_sock_path(lan);
      musat_mngt_send_mulan_disconnect(name, num, lan, sock);
      init_waiting_lan(name, num, NULL, 0, 0);
      memset(atlan->attached_lan, 0, MAX_NAME_LEN);
      mulan_test_stop(lan);
      result = 0;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_event_connect_OK(char *name, char *lan, int num, int rank)
{
  t_musat_evt *musat = musat_find(name);
  t_attached *atlan0 = musat_atlan_find(name, 0);
  t_attached *atlan1 = musat_atlan_find(name, 1);
  int musat_type;
  int llid, tid;
  if (!lan[0])
    KERR(" ");
  else if ((!musat) || (!atlan0) ||  (!atlan1))
    KERR("%s %s", name, lan);
  else if ((musat_type = cfg_get_musat_type(name)) == -1)
    KERR("%s %s", name, lan);
  else if ((musat_type != musat_type_tap) && 
           (musat_type != musat_type_snf) &&
           (musat_type != musat_type_c2c) &&
           (musat_type != musat_type_nat) &&
           (musat_type != musat_type_a2b) &&
           (musat_type != musat_type_wif)) 
    KERR("%s %s", name, lan);
  else
    {
    if (!strcmp(atlan0->waiting_lan, lan))
      {
      llid = atlan0->llid;
      tid = atlan0->tid;
      atlan0->rank = rank;
      strncpy(atlan0->attached_lan, lan, MAX_NAME_LEN-1);
      init_waiting_lan(name, 0, NULL, 0, 0);
      if (num != 0)
        KERR("%d %s", num, lan);
      }
    else if (!strcmp(atlan1->waiting_lan, lan))
      {
      llid = atlan1->llid;
      tid = atlan1->tid;
      atlan1->rank = rank;
      strncpy(atlan1->attached_lan, lan, MAX_NAME_LEN-1);
      init_waiting_lan(name, 1, NULL, 0, 0);
      if (num != 1)
        KERR("%d %s", num, lan);
      }
    else
      KERR("%s %s", name, lan);
    if ((num == 0) || (num == 1))
      {
      if (cfg_set_tux_lan(name, num, lan, llid))
        KOUT("%s", name);
      resp_to_cli(name, llid, tid, 1, lan);
      }
    else
      KERR("%d %s", num, lan);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_event_connect_KO(char *name, char *lan, int num)
{
  t_musat_evt *musat = musat_find(name);
  t_attached *atlan0 = musat_atlan_find(name, 0);
  t_attached *atlan1 = musat_atlan_find(name, 1);
  int llid, tid;
  if (!lan[0])
    KERR("%s %s", name, lan);
  else if ((!musat) || (!atlan0) ||  (!atlan1))
    KERR("%s %s", name, lan);
  else
    {
   if (!strcmp(atlan0->waiting_lan, lan))
      {
      llid = atlan0->llid;
      tid = atlan0->tid;
      init_waiting_lan(name, 0, NULL, 0, 0);
      if (num != 0)
        KERR("%d %s", num, lan);
      }
    else if (!strcmp(atlan1->waiting_lan, lan))
      {
      llid = atlan1->llid;
      tid = atlan1->tid;
      init_waiting_lan(name, 1, NULL, 0, 0);
      if (num != 1)
        KERR("%d %s", num, lan);
      }
    else
      KERR("%s %s", name, lan);
    if ((num == 0) || (num == 1))
      resp_to_cli(name, llid, tid, 0, lan);
    else
      KERR("%s %s %d", name, lan, num);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_event_birth(char *name, int musat_type)
{
  t_musat_evt *musat = musat_find(name);
  if (musat)
    KERR("%s", name);
  else
    {
    musat_evt_alloc(name);
    }
  event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_event_quick_death(char *name)
{
  int i;
  t_attached *atlan;
  for (i=0; i<2; i++)
    {
    atlan = musat_atlan_find(name, i);
    if (atlan)
      {
      if (strlen(atlan->attached_lan))
        {
        musat_event_admin_del_lan(name, i, atlan->attached_lan);
        }
      }
    }
  musat_free(name);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void timer_musat_death(void *data)
{
  char *name = (char *) data;
  t_musat_evt *musat = musat_find(name);
  if (musat)
    {
    musat_event_quick_death(name);
    musat_mngt_send_muswitch_quit(name);
    }
  clownix_free(name, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int musat_event_death(char *name)
{
  t_musat_evt *musat = musat_find(name);
  t_attached *atlan;
  char *sock, *vname;
  int i, result = -1;
  if (musat)
    {
    for (i=0; i<2; i++)
      {
      atlan = musat_atlan_find(name, i);
      if (strlen(atlan->attached_lan))
        {
        sock = utils_mulan_get_sock_path(atlan->attached_lan);
        musat_mngt_send_mulan_disconnect(name, i, atlan->attached_lan, sock);
        }
      if (strlen(atlan->waiting_lan))
        {
        sock = utils_mulan_get_sock_path(atlan->waiting_lan);
        musat_mngt_send_mulan_disconnect(name, i, atlan->waiting_lan, sock);
        }
      }
    vname = (char *) clownix_malloc(MAX_NAME_LEN, 4);
    memset(vname, 0, MAX_NAME_LEN);
    strncpy(vname, name, MAX_NAME_LEN-1);
    clownix_timeout_add(50, timer_musat_death, (void *) vname, NULL, NULL);
    result = 0;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void death_mulan(char *lan, int num)
{
  t_musat_evt *cur, *next;
  cur = musat_find_next_with_lan(NULL, lan, num);
  while (cur)
    {
    next = musat_find_next_with_lan(cur, lan, num);
    if (cur->atlan[num].llid)
      {
      if (msg_exist_channel(cur->atlan[num].llid))
        send_status_ko(cur->atlan[num].llid,cur->atlan[num].tid,"mulan death");
      init_waiting_lan(cur->name, num, NULL, 0, 0);
      }
    cur = next;
    }
  
  cur = musat_find_next_with_attached_lan(NULL, lan, num);
  while (cur)
    {
    next = musat_find_next_with_attached_lan(cur, lan, num);
    musat_event_admin_del_lan(cur->name, num, lan);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_event_mulan_death(char *lan)
{
  if ((!lan) || (lan[0] == 0))
    KOUT(" ");
  death_mulan(lan, 0);
  death_mulan(lan, 1);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_event_mulan_birth(char *lan)
{
  int i;
  t_musat_evt *cur, *next;
  char *sock = utils_mulan_get_sock_path(lan);
  if ((!lan) || (!lan[0]))
    KOUT(" ");
  for (i = 0; i < 2; i++)
    {
    cur = musat_find_next_with_lan(NULL, lan, i);
    while (cur)
      {
      if (musat_mngt_send_mulan_connect(10, cur->name, i, lan,  sock)) 
        KERR("%s %s", cur->name, lan);
      next = musat_find_next_with_lan(cur, lan, i);
      cur = next;
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void musat_event_init(void)
{
  g_head_musat = NULL;
}
/*--------------------------------------------------------------------------*/



