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
#include <gtk/gtk.h>
#include <libcrcanvas.h>
#include <string.h>
#include <stdlib.h>
#include "io_clownix.h"
#include "rpc_clownix.h"
#include "commun_consts.h"
#include "bank.h"
#include "eventfull_eth.h"
#include "main_timer_loop.h"

typedef struct t_sat_blinks
{
  t_bank_item *bitem_sat;
  char name[MAX_NAME_LEN];
  int to_be_deleted;
  int blink_rx;
  int blink_last_rx;
  int blink_tx;
  int blink_last_tx;
  struct t_sat_blinks *hash_prev;
  struct t_sat_blinks *hash_next;
  struct t_sat_blinks *glob_prev;
  struct t_sat_blinks *glob_next;
} t_sat_blinks;


typedef struct t_eth_blinks
{
  t_bank_item *bitem_eth;  
  int blink_rx;
  int blink_last_rx;
  int blink_tx;
  int blink_last_tx;
} t_eth_blinks;

typedef struct t_node_blinks
{
  char name[MAX_NAME_LEN];
  int to_be_deleted;
  int nb_eth;
  t_eth_blinks eth_blinks[MAX_ETH_VM];
  t_bank_item *bitem_node;  
  struct t_node_blinks *hash_prev;
  struct t_node_blinks *hash_next;
  struct t_node_blinks *glob_prev;
  struct t_node_blinks *glob_next;
} t_node_blinks;

static int glob_current_node_nb;
static t_node_blinks *head_glob_node_blinks;
static t_node_blinks *head_hash_node_blinks[0xFF+1];

static int glob_current_sat_nb;
static t_sat_blinks *head_glob_sat_blinks;
static t_sat_blinks *head_hash_sat_blinks[0xFF+1];

/*****************************************************************************/
static int get_hash_of_name(char *name)
{
  int len = strlen(name);
  int i, result;
  char hash = 0;
  for (i=0; i<len; i++)
    hash ^= name[i];
  result = (hash & 0xFF);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_node_blinks *get_node_blinks_with_name(char *name)
{
  int idx = get_hash_of_name(name);
  t_node_blinks *cur = head_hash_node_blinks[idx];
  while (cur)
    {
    if (!strcmp(cur->name, name))
      break;
    cur = cur->hash_next;
    }
  if (cur && cur->to_be_deleted)
    cur = NULL;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_sat_blinks *get_sat_blinks_with_name(char *name)
{
  int idx = get_hash_of_name(name);
  t_sat_blinks *cur = head_hash_sat_blinks[idx];
  while (cur)
    {
    if (!strcmp(cur->name, name))
      break;
    cur = cur->hash_next;
    }
  if (cur && cur->to_be_deleted)
    cur = NULL;
  return cur;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void transfert_blink_on_eth_bitem(t_eth_blinks *cur)
{ 
  if (cur->bitem_eth)
    {
    if ((cur->blink_rx) || (cur->blink_last_rx))
      {
      cur->bitem_eth->pbi.blink_rx = 1;
      cur->blink_rx = 0;
      cur->blink_last_rx = cur->blink_rx;
      }
    else
      cur->bitem_eth->pbi.blink_rx = 0;

    if ((cur->blink_tx) || (cur->blink_last_tx))
      {
      cur->bitem_eth->pbi.blink_tx = 1;
      cur->blink_tx = 0;
      cur->blink_last_tx = cur->blink_tx;
      }
    else
      cur->bitem_eth->pbi.blink_tx = 0;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void blink_on_node(void)
{
  int i;
  t_node_blinks *cur = head_glob_node_blinks;
  while (cur)
    {
    if (!(cur->to_be_deleted))
      {
      for (i=0; i<cur->nb_eth; i++)
        {
        transfert_blink_on_eth_bitem(&(cur->eth_blinks[i]));
        }
      }
    cur = cur->glob_next;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void transfert_blink_on_sat_bitem(t_sat_blinks *cur)
{ 
  if ((cur->blink_rx) || (cur->blink_last_rx))
    {
    cur->bitem_sat->pbi.blink_rx = 1;
    cur->blink_last_rx = cur->blink_rx;
    cur->blink_rx = 0;
    }
  if ((cur->blink_tx) || (cur->blink_last_tx))
    {
    cur->bitem_sat->pbi.blink_tx = 1;
    cur->blink_last_tx = cur->blink_tx;
    cur->blink_tx = 0;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void blink_on_sat(void)
{
  t_sat_blinks *cur = head_glob_sat_blinks;
  while (cur)
    {
    if (!(cur->to_be_deleted))
      {
      if (cur->bitem_sat)
        {
        transfert_blink_on_sat_bitem(cur);
        }
      }
    cur = cur->glob_next;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void eventfull_arrival(int nb_endp, t_eventfull_endp *endp)
{
  t_node_blinks *curn;
  t_sat_blinks *curs;
  int i, num;
  for (i=0; i<nb_endp; i++)
    {
    curn = get_node_blinks_with_name(endp[i].name);
    if (curn)
      {
      num = endp[i].num;
      if ((num < 0) || (num > MAX_ETH_VM))
        KOUT("%d", num);
      curn->bitem_node->pbi.pbi_node->node_cpu = endp[i].cpu;
      curn->bitem_node->pbi.pbi_node->node_ram = endp[i].ram;
      if (curn->eth_blinks[num].bitem_eth)
        {
        if (curn->eth_blinks[num].bitem_eth->num != num)
          KOUT(" ");
        if (endp[i].rx)
          {
          curn->eth_blinks[num].blink_rx = 1;
          }
        if (endp[i].tx)
          {
          curn->eth_blinks[num].blink_tx = 1;
          }
        }
      }
    else
      {
      curs = get_sat_blinks_with_name(endp[i].name);
      if (curs)
        {
        if (curs->bitem_sat)
          {
          if (endp[i].rx)
            curs->blink_rx = 1;
          if (endp[i].tx)
            curs->blink_tx = 1;
          }
        }
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void eventfull_packets_data(t_eventfull *eventfull)
{
  if (!eventfull)
    KOUT(" ");
  eventfull_arrival(eventfull->nb_endp, eventfull->endp);
  blink_on_node();
  blink_on_sat();
  eventfull_periodic_work();
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void update_the_eth_blinks(t_node_blinks *node_blinks)
{
  int i;
  t_list_bank_item *cur,*head_eth_lst=node_blinks->bitem_node->head_eth_list;
  cur = head_eth_lst;
  while(cur)
    {
    if (cur->bitem->bank_type == bank_type_eth) 
      node_blinks->nb_eth += 1;
    cur = cur->next;
    }
  for (i=0; i<node_blinks->nb_eth; i++) 
    {
    cur = head_eth_lst;
    while (cur)
      {
      if (cur->bitem->num == i)
        {
        node_blinks->eth_blinks[i].bitem_eth = cur->bitem;
        break; 
        }
      cur = cur->next;
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timeout_node_create(void *data)
{
  t_node_blinks *cur, *nblk = (t_node_blinks *) data;
  int idx;
  t_bank_item *bitem;
  if (!nblk)
    KOUT(" ");
  cur = get_node_blinks_with_name(nblk->name);
  if (cur)
    KOUT(" ");
  idx = get_hash_of_name(nblk->name);
  bitem = look_for_node_with_id(nblk->name);
  if (bitem == NULL)
    clownix_free(nblk, __FUNCTION__);
  else
    {
    cur = nblk;
    cur->bitem_node = bitem;
    update_the_eth_blinks(cur);
    if (head_hash_node_blinks[idx])
      head_hash_node_blinks[idx]->hash_prev = cur;
    cur->hash_next = head_hash_node_blinks[idx];
    head_hash_node_blinks[idx] = cur;
    if (head_glob_node_blinks)
      head_glob_node_blinks->glob_prev = cur;
    cur->glob_next = head_glob_node_blinks;
    head_glob_node_blinks = cur;
    glob_current_node_nb += 1;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void eventfull_node_create(char *name)
{
  t_node_blinks *cur = get_node_blinks_with_name(name);
  if (cur)
    KOUT("%s", name);
  cur = (t_node_blinks *) clownix_malloc(sizeof(t_node_blinks), 13);
  memset(cur, 0, sizeof(t_node_blinks));
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  clownix_timeout_add(1, timeout_node_create, cur, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timeout_node_delete(void *data)
{
  int idx;
  t_node_blinks *cur = (t_node_blinks *) data;
  if (!cur)
    KOUT(" ");
  if (cur->to_be_deleted != 1) 
    KOUT("%d", cur->to_be_deleted);
  idx = get_hash_of_name(cur->name);
  if (cur->hash_prev)
    cur->hash_prev->hash_next = cur->hash_next;
  if (cur->hash_next)
    cur->hash_next->hash_prev = cur->hash_prev;
  if (cur == head_hash_node_blinks[idx])
    head_hash_node_blinks[idx] = cur->hash_next;
  if (cur->glob_prev)
    cur->glob_prev->glob_next = cur->glob_next;
  if (cur->glob_next)
    cur->glob_next->glob_prev = cur->glob_prev;
  if (cur == head_glob_node_blinks)
    head_glob_node_blinks = cur->glob_next;
  clownix_free(cur, __FUNCTION__);
  glob_current_node_nb -= 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void eventfull_node_delete(char *name)
{
  t_node_blinks *cur = get_node_blinks_with_name(name);
  if (!cur)
    KOUT("%s", name);
  cur->to_be_deleted = 1;
  clownix_timeout_add(1, timeout_node_delete, cur, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timeout_sat_create(void *data)
{
  t_sat_blinks *cur, *nblk = (t_sat_blinks *) data;
  int idx;
  t_bank_item *bitem;
  if (!nblk)
    KOUT(" ");
  cur = get_sat_blinks_with_name(nblk->name);
  if (cur)
    KOUT(" ");
  idx = get_hash_of_name(nblk->name);
  bitem = look_for_sat_with_id(nblk->name);
  if (bitem == NULL)
    clownix_free(nblk, __FUNCTION__);
  else
    {
    cur = nblk;
    cur->bitem_sat = bitem;
    if (head_hash_sat_blinks[idx])
      head_hash_sat_blinks[idx]->hash_prev = cur;
    cur->hash_next = head_hash_sat_blinks[idx];
    head_hash_sat_blinks[idx] = cur;
    if (head_glob_sat_blinks)
      head_glob_sat_blinks->glob_prev = cur;
    cur->glob_next = head_glob_sat_blinks;
    head_glob_sat_blinks = cur;
    glob_current_sat_nb += 1;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void eventfull_sat_create(char *name)
{
  t_sat_blinks *cur = get_sat_blinks_with_name(name);
  if (cur)
    KOUT("%s", name);
  cur = (t_sat_blinks *) clownix_malloc(sizeof(t_sat_blinks), 13);
  memset(cur, 0, sizeof(t_sat_blinks));
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  clownix_timeout_add(1, timeout_sat_create, cur, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timeout_sat_delete(void *data)
{
  int idx;
  t_sat_blinks *cur = (t_sat_blinks *) data;
  if (!cur)
    KOUT(" ");
  if (cur->to_be_deleted != 1)
    KOUT("%d", cur->to_be_deleted);
  idx = get_hash_of_name(cur->name);
  if (cur->hash_prev)
    cur->hash_prev->hash_next = cur->hash_next;
  if (cur->hash_next)
    cur->hash_next->hash_prev = cur->hash_prev;
  if (cur == head_hash_sat_blinks[idx])
    head_hash_sat_blinks[idx] = cur->hash_next;
  if (cur->glob_prev)
    cur->glob_prev->glob_next = cur->glob_next;
  if (cur->glob_next)
    cur->glob_next->glob_prev = cur->glob_prev;
  if (cur == head_glob_sat_blinks)
    head_glob_sat_blinks = cur->glob_next;
  clownix_free(cur, __FUNCTION__);
  glob_current_sat_nb -= 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void eventfull_sat_delete(char *name)
{
  t_sat_blinks *cur = get_sat_blinks_with_name(name);
  if (cur)
    {
    cur->to_be_deleted = 1;
    clownix_timeout_add(1, timeout_sat_delete, cur, NULL, NULL);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void eventfull_init(void)
{
  glob_current_node_nb = 0;
  glob_current_sat_nb = 0;
}
/*---------------------------------------------------------------------------*/

