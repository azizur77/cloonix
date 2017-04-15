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
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <dirent.h>



#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "event_subscriber.h"
#include "commun_daemon.h"
#include "header_sock.h"



enum {
  type_evt_stats_none,
  type_evt_stats_eth,
  type_evt_stats_sat,
  type_evt_stats_max,
  };

typedef struct t_stats_sub
{
  int type_evt_stats;
  char name[MAX_NAME_LEN];
  int eth;
  int llid;
  int tid;
  t_stats_counts stats_counts;
  struct t_stats_sub *prev;
  struct t_stats_sub *next;
} t_stats_sub;

static t_stats_sub *g_head_stats_sub;


/****************************************************************************/
static t_stats_count_item *get_next_count(t_stats_sub *stats_sub, int is_tx)
{
  t_stats_count_item *result = NULL;
  int idx;
  if (is_tx)
    {
    if (stats_sub->stats_counts.nb_tx_items + 1 >= MAX_STATS_ITEMS)
      KERR("%s %d", stats_sub->name, stats_sub->stats_counts.nb_tx_items);
    else
      {
      idx = stats_sub->stats_counts.nb_tx_items;
      result = &(stats_sub->stats_counts.tx_item[idx]);
      stats_sub->stats_counts.nb_tx_items += 1;
      }
    }
  else
    {
    if (stats_sub->stats_counts.nb_rx_items + 1 >= MAX_STATS_ITEMS)
      KERR("%s %d", stats_sub->name, stats_sub->stats_counts.nb_rx_items);
    else
      {
      idx = stats_sub->stats_counts.nb_rx_items;
      result = &(stats_sub->stats_counts.rx_item[idx]);
      stats_sub->stats_counts.nb_rx_items += 1;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_stats_sub *find_stats_sub_with_llid(int llid)
{
  t_stats_sub *cur = g_head_stats_sub;
  while (cur)
    {
    if (cur->llid == llid)
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_stats_sub *find_stats_sub_with_name(int type_evt_stats, char *name)
{
  t_stats_sub *cur = g_head_stats_sub;
  while (cur)
    {
    if ((cur->type_evt_stats == type_evt_stats) && (!strcmp(cur->name, name)))
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_stats_sub *find_stats_sub(int type_evt_stats, char *name, 
                                   int eth, int llid)
{
  t_stats_sub *cur = g_head_stats_sub;
  while (cur)
    {
    if ((cur->type_evt_stats == type_evt_stats) && (cur->llid == llid) &&
        (!strcmp(cur->name, name)) && (cur->eth == eth))
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int alloc_stats_sub(int type_evt_stats, char *name, 
                           int eth, int llid, int tid)
{
  int result = -1;
  t_stats_sub *cur = find_stats_sub(type_evt_stats, name, eth, llid);
  if (!cur)
    {
    result = 0;
    cur = (t_stats_sub *) clownix_malloc(sizeof(t_stats_sub), 7);
    memset(cur, 0, sizeof(t_stats_sub));
    cur->type_evt_stats = type_evt_stats;
    strncpy(cur->name, name, MAX_NAME_LEN-1);
    cur->eth = eth;
    cur->llid = llid;
    cur->tid = tid;
    if (g_head_stats_sub)
      g_head_stats_sub->prev = cur;
    cur->next = g_head_stats_sub;
    g_head_stats_sub = cur;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_stats_sub(t_stats_sub *stats_sub)
{
  if (stats_sub->next)
    stats_sub->next->prev = stats_sub->prev;
  if (stats_sub->prev)
    stats_sub->prev->next = stats_sub->next;
  if (stats_sub == g_head_stats_sub)
    g_head_stats_sub = stats_sub->next;
  clownix_free(stats_sub, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int local_stats_sub(int type_evt_stats, int sub, 
                           char *name, int eth, int llid, int tid)
{
  int result = -1;
  t_stats_sub *cur;
  if (sub)
    {
    if (!(alloc_stats_sub(type_evt_stats, name, eth, llid, tid)))
      result = 0;
    else
      KERR("ERROR: %d %s %d", type_evt_stats, name, eth);
    }
  else
    {
    cur = find_stats_sub(type_evt_stats, name, eth, llid);
    if (cur)
      {
      free_stats_sub(cur);
      result = 0;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_stats_sub *find_next_stats_sub_eth(t_stats_sub *head, 
                                            char *name, int eth)
{
  t_stats_sub *cur;
  if (head)
    cur = head->next;
  else
    cur = g_head_stats_sub;
  while (cur)
    {
    if (cur->type_evt_stats == type_evt_stats_eth)
      {
      if ((!strcmp(name, cur->name)) &&
          (cur->eth == eth))
        break;
      }
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_stats_sub *find_next_stats_sub_sat(t_stats_sub *head, char *name)
{
  t_stats_sub *cur;
  if (head)
    cur = head->next;
  else
    cur = g_head_stats_sub;
  while (cur)
    {
    if (cur->type_evt_stats == type_evt_stats_sat)
      {
      if (!strcmp(name, cur->name))
        break;
      }
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_update_tux_tx(t_tux *tux, unsigned int ms, 
                                  int num, int pkts, int bytes)
{
  t_stats_count_item *sci;
  t_stats_sub *sub = find_next_stats_sub_sat(NULL, tux->name);
  tux->lan_attached[num].eventfull_tx_p += pkts;
  while(sub)
    {
    sci = get_next_count(sub, 1);
    if (sci)
      {
      sci->time_ms = ms;
      sci->pkts = pkts;
      sci->bytes = bytes;
      }
    sub = find_next_stats_sub_sat(sub, tux->name);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_update_eth_tx(t_eth *eth, unsigned int ms, 
                                  int pkts, int bytes)
{
  t_stats_count_item *sci;
  t_stats_sub *sub = find_next_stats_sub_eth(NULL, 
                                             eth->vm->vm_params.name, 
                                             eth->eth);
  eth->lan_attached.eventfull_tx_p += pkts;
  while (sub)
    {
    sci = get_next_count(sub, 1);
    if (sci)
      {
      sci->time_ms = ms;
      sci->pkts = pkts;
      sci->bytes = bytes;
      }
    sub = find_next_stats_sub_eth(sub, 
                                  eth->vm->vm_params.name,
                                  eth->eth);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_update_tux_rx(t_tux *tux, unsigned int ms, 
                                  int num, int pkts, int bytes)
{
  t_stats_count_item *sci;
  t_stats_sub *sub = find_next_stats_sub_sat(NULL, tux->name);
  tux->lan_attached[num].eventfull_rx_p += pkts;
  while(sub)
    {
    sci = get_next_count(sub, 0);
    if (sci)
      {
      sci->time_ms = ms;
      sci->pkts = pkts;
      sci->bytes = bytes;
      }
    sub = find_next_stats_sub_sat(sub, tux->name);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_update_eth_rx(t_eth *eth, unsigned int ms, 
                                  int pkts, int bytes)
{
  t_stats_count_item *sci;
  t_stats_sub *sub = find_next_stats_sub_eth(NULL,
                                             eth->vm->vm_params.name,
                                             eth->eth);
  eth->lan_attached.eventfull_rx_p += pkts;
  while(sub)
    {
    sci = get_next_count(sub, 0);
    if (sci)
      {
      sci->time_ms = ms;
      sci->pkts = pkts;
      sci->bytes = bytes;
      }
    sub = find_next_stats_sub_eth(sub, 
                                  eth->vm->vm_params.name,
                                  eth->eth);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_evt_stats_eth_sub(int llid, int tid, char *name, int eth, int sub)
{
  char *network_name = cfg_get_cloonix_name();
  t_vm  *vm;
  t_eth *peth;
  t_stats_counts sc;
  memset(&sc, 0, sizeof(t_stats_counts));
  vm = cfg_get_vm(name);
  if (!vm)
    {
    send_evt_stats_eth(llid, tid, network_name, name, eth, &sc, 1);
    }
  else
    {
    peth = cfg_find_eth(vm, eth);
    if (!peth)
      {
      send_evt_stats_eth(llid, tid, network_name, name, eth, &sc, 1);
      }
    else
      {
      if (local_stats_sub(type_evt_stats_eth, sub, name, eth, llid, tid))
        {
        send_evt_stats_eth(llid, tid, network_name, name, eth, &sc, 1);
        }
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_evt_stats_sat_sub(int llid, int tid, char *name, int sub)
{
  char *network_name = cfg_get_cloonix_name();
  t_tux *tux;
  t_stats_counts sc;
  memset(&sc, 0, sizeof(t_stats_counts));
  tux = cfg_get_tux(name);
  if ((!tux) || (!(tux->is_musat)))
    send_evt_stats_sat(llid, tid, network_name, name, &sc, 1);
  else
    {
    if (local_stats_sub(type_evt_stats_sat, sub, name, 0, llid, tid))
      send_evt_stats_sat(llid, tid, network_name, name, &sc, 1);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_heartbeat(void)
{
  char *network_name = cfg_get_cloonix_name();
  t_stats_sub *cur = g_head_stats_sub;
  while (cur)
    {
    if (msg_exist_channel(cur->llid))
      {
      if (cur->type_evt_stats == type_evt_stats_eth)
        {
        if ((cur->stats_counts.nb_tx_items) || 
            (cur->stats_counts.nb_rx_items))
          {
          send_evt_stats_eth(cur->llid, cur->tid, 
                             network_name, 
                             cur->name, cur->eth, 
                             &cur->stats_counts, 0);
          }
        }
      else if (cur->type_evt_stats == type_evt_stats_sat)
        {
        if ((cur->stats_counts.nb_tx_items) || 
            (cur->stats_counts.nb_rx_items))
          {
          send_evt_stats_sat(cur->llid, cur->tid, 
                             network_name, 
                             cur->name, 
                             &cur->stats_counts, 0);
          }
        }
      else
        KERR("ERROR: %d", cur->type_evt_stats);
      memset(&cur->stats_counts, 0, sizeof(t_stats_counts));
      }
    cur = cur->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_vm_death(char *name)
{
  char *network_name = cfg_get_cloonix_name();
  t_stats_sub *cur;
  t_stats_counts sc;
  memset(&sc, 0, sizeof(t_stats_counts));
  cur = find_stats_sub_with_name(type_evt_stats_eth, name);
  while (cur)
    {
    send_evt_stats_eth(cur->llid, cur->tid, network_name, 
                       cur->name, cur->eth, &sc, 1);
    free_stats_sub(cur);
    cur = find_stats_sub_with_name(type_evt_stats_eth, name);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_llid_close(int llid)
{
  t_stats_sub *cur;
  cur = find_stats_sub_with_llid(llid);
  while (cur)
    {
    free_stats_sub(cur);
    cur = find_stats_sub_with_llid(llid);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_sat_death(char *name)
{
  char *network_name = cfg_get_cloonix_name();
  t_stats_sub *cur;
  t_stats_counts sc;
  memset(&sc, 0, sizeof(t_stats_counts));
  cur = find_stats_sub_with_name(type_evt_stats_sat, name);
  while (cur)
    {
    send_evt_stats_sat(cur->llid, cur->tid, network_name, cur->name, &sc, 1);
    free_stats_sub(cur);
    cur = find_stats_sub_with_name(type_evt_stats_sat, name);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void stats_counters_init(void)
{
  g_head_stats_sub = NULL;
}
/*--------------------------------------------------------------------------*/

