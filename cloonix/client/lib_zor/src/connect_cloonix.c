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
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <errno.h>

#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "doorways_sock.h"
#include "file_read_write.h"
#include "connect_cloonix.h"
#include "interface.h"
/*--------------------------------------------------------------------------*/
typedef struct t_record_vm
{
  char name[MAX_NAME_LEN];
  int nb_eth;
  int vm_id;
  struct t_record_vm *prev;
  struct t_record_vm *next;
} t_record_vm;
/*--------------------------------------------------------------------------*/
typedef struct t_record_sat
{
  char name[MAX_NAME_LEN];
  int type;
  struct t_record_sat *prev;
  struct t_record_sat *next;
} t_record_sat;
/*--------------------------------------------------------------------------*/
typedef struct t_record_lan
{
  char name[MAX_NAME_LEN];
  struct t_record_lan *prev;
  struct t_record_lan *next;
} t_record_lan;
/*--------------------------------------------------------------------------*/
typedef struct t_record_net
{
  int llid;
  char name[MAX_NAME_LEN];
  t_record_vm *head_vm;
  t_record_sat *head_sat;
  t_record_lan *head_lan;
  struct t_record_net *prev;
  struct t_record_net *next;
} t_record_net;
/*--------------------------------------------------------------------------*/
static t_record_net *g_head_net;
/*--------------------------------------------------------------------------*/
static t_evt_net_exists_cb    g_net_exists_cb;
static t_evt_vm_exists_cb     g_vm_exists_cb;
static t_evt_sat_exists_cb    g_sat_exists_cb;
static t_evt_lan_exists_cb    g_lan_exists_cb;
static t_evt_stats_eth_cb     g_stats_eth_cb;
static t_evt_stats_sat_cb     g_stats_sat_cb;
static t_evt_stats_sysinfo_cb g_stats_sysinfo_cb;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_record_net *find_net_with_llid(int llid)
{
  t_record_net *cur = g_head_net;
  while(cur)
    {
    if (cur->llid == llid)
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_record_net *find_net_with_name(char *name)
{
  t_record_net *cur = g_head_net;
  while(cur)
    {
    if (!strcmp(cur->name, name))
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_record_vm *find_vm_with_name(t_record_net *net, char *name)
{
  t_record_vm *cur = net->head_vm;
  while(cur)
    {
    if (!strcmp(name, cur->name))
      break;
    cur = cur->next;
    }
  return(cur);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_record_sat *find_sat_with_name(t_record_net *net, char *name)
{ 
  t_record_sat *cur = net->head_sat;
  while(cur)
    {
    if (!strcmp(name, cur->name))
      break;
    cur = cur->next;
    }
  return(cur);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_record_lan *find_lan_with_name(t_record_net *net, char *name)
{
  t_record_lan *cur = net->head_lan;
  while(cur)
    {
    if (!strcmp(name, cur->name))
      break;
    cur = cur->next;
    }
  return(cur);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_record_net(char *name, int llid)
{
  t_record_net *cur;
  cur = find_net_with_name(name);
  if (cur)
    KOUT("%s", name);
  cur = find_net_with_llid(llid);
  if (cur)
    KOUT("%s", name);
  if (strlen(name) >= MAX_NAME_LEN)
    KOUT("%s", name);
  cur = (t_record_net *) clownix_malloc(sizeof(t_record_net), 5);
  memset(cur, 0, sizeof(t_record_net));
  cur->llid = llid;
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  cur->next = g_head_net;
  if (g_head_net)
    g_head_net->prev = cur;
  g_head_net = cur;
  g_net_exists_cb(name, 1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_record_vm(t_record_net *net, char *name, 
                            int nb_eth, int vm_id)
{
  t_record_vm *cur;
  int i;
  cur = (t_record_vm *) clownix_malloc(sizeof(t_record_vm), 5);
  memset(cur, 0, sizeof(t_record_vm));
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  cur->nb_eth = nb_eth;
  cur->vm_id = vm_id;
  cur->next = net->head_vm;
  if (net->head_vm)
    net->head_vm->prev = cur;
  net->head_vm = cur;
  send_evt_stats_sysinfo_sub(net->llid, 0, name, 1);
  for (i=0; i<nb_eth; i++)
    send_evt_stats_eth_sub(net->llid, 0, name, i, 1);
  g_vm_exists_cb(net->name, name, nb_eth, vm_id, 1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_record_vm(t_record_net *net, t_record_vm *vm)
{
  if (vm->prev)
    vm->prev->next = vm->next;
  if (vm->next)
    vm->next->prev = vm->prev;
  if (vm == net->head_vm)
    net->head_vm = vm->next;
  g_vm_exists_cb(net->name, vm->name, vm->nb_eth, vm->vm_id, 0);
  clownix_free(vm, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_record_sat(t_record_net *net, char *name, int type)
{
  t_record_sat *cur;
  cur = (t_record_sat *) clownix_malloc(sizeof(t_record_sat), 5);
  memset(cur, 0, sizeof(t_record_sat));
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  cur->type = type;
  cur->next = net->head_sat;
  if (net->head_sat)
    net->head_sat->prev = cur;
  net->head_sat = cur;
  send_evt_stats_sysinfo_sub(net->llid, 0, name, 1);
  send_evt_stats_sat_sub(net->llid, 0, name, 1);
  if ((type == musat_type_tap)  ||
      (type == musat_type_wif)  || 
      (type == musat_type_raw)  || 
      (type == musat_type_c2c)  ||
      (type == musat_type_nat)  ||
      (type == musat_type_snf)  ||
      (type == musat_type_a2b))
    g_sat_exists_cb(net->name, name, type, 1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_record_sat(t_record_net *net, t_record_sat *sat)
{
  if (sat->prev)
    sat->prev->next = sat->next;
  if (sat->next)
    sat->next->prev = sat->prev;
  if (sat == net->head_sat)
    net->head_sat = sat->next;
  if ((sat->type == musat_type_tap) ||
      (sat->type == musat_type_wif)  || 
      (sat->type == musat_type_raw)  || 
      (sat->type == musat_type_c2c)  ||
      (sat->type == musat_type_nat)  ||
      (sat->type == musat_type_snf)  ||
      (sat->type == musat_type_a2b))
    g_sat_exists_cb(net->name, sat->name, sat->type, 0);
  clownix_free(sat, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_record_lan(t_record_net *net, char *name)
{
  t_record_lan *cur;
  cur = (t_record_lan *) clownix_malloc(sizeof(t_record_lan), 5);
  memset(cur, 0, sizeof(t_record_lan));
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  cur->next = net->head_lan;
  if (net->head_lan)
    net->head_lan->prev = cur;
  net->head_lan = cur;
  g_lan_exists_cb(net->name, name, 1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_record_lan(t_record_net *net, t_record_lan *lan)
{
  if (lan->prev)
    lan->prev->next = lan->next;
  if (lan->next)
    lan->next->prev = lan->prev;
  if (lan == net->head_lan)
    net->head_lan = lan->next;
  g_lan_exists_cb(net->name, lan->name, 0);
  clownix_free(lan, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static void free_record_net(t_record_net *rec)
{
  while(rec->head_vm)
    free_record_vm(rec, rec->head_vm);
  while(rec->head_sat)
    free_record_sat(rec, rec->head_sat);
  while(rec->head_lan)
    free_record_lan(rec, rec->head_lan);
  if (rec->prev)
    rec->prev->next = rec->next;
  if (rec->next)
    rec->next->prev = rec->prev;
  if (rec == g_head_net)
    g_head_net = rec->next;
  g_net_exists_cb(rec->name, 0);
  clownix_free(rec, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_all_vm_not_in_topo(t_record_net *net, t_topo_info *topo)
{
  int i, found;
  t_record_vm *cur_vm, *next_vm;
  cur_vm = net->head_vm;
  while(cur_vm)
    {
    next_vm = cur_vm->next;
    found = 0;
    for (i=0; i<topo->nb_vm; i++)
      {
      if (!strcmp(cur_vm->name, topo->vmit[i].vm_params.name))
        {
        found = 1;
        break;
        }
      }
    if (!found)
      free_record_vm(net, cur_vm);
    cur_vm = next_vm;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_all_sat_not_in_topo(t_record_net *net, t_topo_info *topo)
{
  int i, found;
  t_record_sat *cur_sat, *next_sat;
  cur_sat = net->head_sat;
  while(cur_sat)
    {
    next_sat = cur_sat->next;
    found = 0;
    for (i=0; i<topo->nb_sat; i++)
      {
      if (!strcmp(cur_sat->name, topo->sati[i].name))
        {
        found = 1;
        break;
        }
      }
    if (!found)
      free_record_sat(net, cur_sat);
    cur_sat = next_sat;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_all_lan_not_in_topo(t_record_net *net, t_topo_info *topo)
{
  int i,j,k,found;
  char *lan;
  t_record_lan *cur_lan, *next_lan;
  cur_lan = net->head_lan;
  while(cur_lan)
    {
    found = 0;
    next_lan = cur_lan->next;
    for (i=0; i<topo->nb_vm; i++)
      {
      for (j=0; j<topo->vmit[i].vm_params.nb_eth; j++)
        {
        for (k=0; k < topo->vmit[i].lan_eth[j].nb_lan; k++)
          {
          lan = topo->vmit[i].lan_eth[j].lan[k].name;
        if (!strcmp(cur_lan->name, lan))
          {
          found = 1;
          break;
          }
          }
        }
      }
    for (i=0; i<topo->nb_sat; i++)
      {
      for (k=0; k < topo->sati[i].lan0_sat.nb_lan; k++)
        {
        lan = topo->sati[i].lan0_sat.lan[k].name;
        if (!strcmp(cur_lan->name, lan))
          {
          found = 1;
          break;
          }
        }

      for (k=0; k < topo->sati[i].lan1_sat.nb_lan; k++)
        {
        lan = topo->sati[i].lan1_sat.lan[k].name;
        if (!strcmp(cur_lan->name, lan))
          {
          found = 1;
          break;
          }
        }
      }
    if (!found)
      free_record_lan(net, cur_lan);
    cur_lan = next_lan;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_all_vm_not_in_records(t_record_net *net, t_topo_info *topo)
{
  int i;
  for (i=0; i<topo->nb_vm; i++)
    {
    if (!find_vm_with_name(net, topo->vmit[i].vm_params.name))
      alloc_record_vm(net, topo->vmit[i].vm_params.name,
                      topo->vmit[i].vm_params.nb_eth,
                      topo->vmit[i].vm_id);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_all_sat_not_in_records(t_record_net *net, t_topo_info *topo)
{
  int i;
  for (i=0; i<topo->nb_sat; i++)
    {
    if (!find_sat_with_name(net, topo->sati[i].name))
      alloc_record_sat(net, topo->sati[i].name, topo->sati[i].musat_type);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_all_lan_not_in_records(t_record_net *net, t_topo_info *topo)
{   
  int i,j,k;
  char *lan;
  for (i=0; i<topo->nb_vm; i++)
    {
    for (j=0; j<topo->vmit[i].vm_params.nb_eth; j++)
      {
      for (k=0; k < topo->vmit[i].lan_eth[j].nb_lan; k++)
        {
        lan = topo->vmit[i].lan_eth[j].lan[k].name;
        if (!find_lan_with_name(net, lan))
          alloc_record_lan(net, lan);
        }
      }
    }
  for (i=0; i<topo->nb_sat; i++)
    {
    for (k=0; k < topo->sati[i].lan0_sat.nb_lan; k++)
      {
      lan = topo->sati[i].lan0_sat.lan[k].name;
      if (!find_lan_with_name(net, lan))
        alloc_record_lan(net, lan);
      }
    for (k=0; k < topo->sati[i].lan1_sat.nb_lan; k++)
      {
      lan = topo->sati[i].lan1_sat.lan[k].name;
      if (!find_lan_with_name(net, lan))
        alloc_record_lan(net, lan);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_event_topo(int llid, int tid, t_topo_info *topo)
{
  t_record_net *net = find_net_with_name(topo->cloonix_config.network_name);
  if (!net)
    KERR("%s", topo->cloonix_config.network_name);
  else
    {
    free_all_vm_not_in_topo(net, topo);
    free_all_sat_not_in_topo(net, topo);
    free_all_lan_not_in_topo(net, topo);
    alloc_all_vm_not_in_records(net, topo);
    alloc_all_sat_not_in_records(net, topo);
    alloc_all_lan_not_in_records(net, topo);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_evt_stats_eth(int llid, int tid, char *net_name,
                        char *name, int eth,
                        t_stats_counts *stats_counts, int status)
{
  t_record_net *net = find_net_with_name(net_name);
  t_record_vm *vm = NULL;
  if (net)
    vm = find_vm_with_name(net, name);
  if (vm && (status == 0))
    g_stats_eth_cb(net_name, name, eth, stats_counts);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_evt_stats_sat(int llid, int tid, char *net_name, char *name,
                        t_stats_counts *stats_counts, int status)
{
  t_record_net *net = find_net_with_name(net_name);
  t_record_sat *sat = NULL;
  if (net)
    sat = find_sat_with_name(net, name);
  if (sat && (status == 0))
    {
    if ((sat->type == musat_type_tap) ||
        (sat->type == musat_type_wif) ||
        (sat->type == musat_type_raw) ||
        (sat->type == musat_type_c2c) ||
        (sat->type == musat_type_nat) ||
        (sat->type == musat_type_snf) ||
        (sat->type == musat_type_a2b))
      {
      g_stats_sat_cb(net_name, name, stats_counts);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_evt_stats_sysinfo(int llid, int tid, char *net_name, char *name,
                            t_stats_sysinfo *stats, char *df,  int status)
{
  t_record_net *net = find_net_with_name(net_name);
  t_record_vm *vm;
  if (net)
    {
    vm = find_vm_with_name(net, name);
    if (vm && (status == 0))
      {
      g_stats_sysinfo_cb(net_name, name, stats, df);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_blkd_reports(int llid, int tid, t_blkd_reports *blkd)
{
  KOUT(" ");
}
/*--------------------------------------------------------------------------*/



/****************************************************************************/
static void net_change_exists(char *net_name, int llid, int exists)
{
  t_record_net *net = find_net_with_name(net_name);
  if (exists)
    {
    if (net)
      KERR("%s %d %d", net->name, net->llid, llid); 
    else
      alloc_record_net(net_name, llid);
    }
  else
    {
    if (net)
      {
      if(net->llid != llid)
        KERR("%s %d %d", net_name, net->llid, llid);
      else
        free_record_net(net);
      }
    else
      KERR("%s", net_name);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void connect_cloonix_init(char *conf_path,
                          t_evt_net_exists_cb    net_exists,
                          t_evt_vm_exists_cb     vm_exists,
                          t_evt_sat_exists_cb    sat_exists,
                          t_evt_lan_exists_cb    lan_exists,
                          t_evt_stats_eth_cb     stats_eth,
                          t_evt_stats_sat_cb     stats_sat,
                          t_evt_stats_sysinfo_cb stats_sysinfo)
{
  g_net_exists_cb     = net_exists;
  g_vm_exists_cb      = vm_exists;
  g_sat_exists_cb     = sat_exists;
  g_lan_exists_cb     = lan_exists;
  g_stats_eth_cb      = stats_eth;
  g_stats_sat_cb      = stats_sat;
  g_stats_sysinfo_cb  = stats_sysinfo;
  interface_init(conf_path, net_change_exists);
}
/*--------------------------------------------------------------------------*/
