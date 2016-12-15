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
#include <string.h>
#include <stdlib.h>
#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "bank.h"
#include "bank_item.h"
#include "external_bank.h"

/****************************************************************************/
static t_bank_item *edge_does_exist(t_bank_item *bitem, t_bank_item *lan)
{
  t_bank_item *result = NULL;
  t_list_bank_item *cur = bitem->head_edge_list;
  while (cur)
    {
    if (cur->bitem->att_lan == lan )
      {
      if (result == NULL)
        result = cur->bitem;
      else
        KOUT(" ");
      }
    cur = cur->next;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_edge_eth_create(char *name, int num, char *lan)
{
  t_bank_item *intf, *blan, *edge_item;
  intf = look_for_eth_with_id(name, num);
  blan = look_for_lan_with_id(lan);
  if (intf && blan)
    {
    edge_item = edge_does_exist(intf, blan);
    if (!edge_item)
      add_new_edge(intf, blan, eorig_modif);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_edge_sat_create(char *name, char *lan, int num)
{
  t_bank_item *sat, *blan, *edge_item;
  sat = look_for_sat_with_id(name);
  blan = look_for_lan_with_id(lan);
  if (sat && blan)
    {
    edge_item = edge_does_exist(sat, blan);
    if (!edge_item)
      add_new_edge(sat, blan, eorig_modif);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_node_create(char *name, char *ip, char *kernel,
                      char *rootfs_sod, char *rootfs_backing_file,
                      char *install_cdrom, char *added_cdrom, 
                      char *node_bdisk, int bank_type, 
                      int num_eth, int *mutype, 
                      int color_choice, int vm_id, int vm_config_flags,
                      double x, double y, int hidden_on_graph,
                      double *tx, double *ty, int *thidden_on_graph)
{
  int i;
  add_new_node(name, ip, kernel, rootfs_sod, rootfs_backing_file,
               install_cdrom, added_cdrom, node_bdisk,  
               bank_type, x, y, hidden_on_graph, color_choice, 
               vm_id, vm_config_flags);
  if (num_eth < 1)
    KOUT("%d", num_eth);

  for (i=0; i<num_eth; i++)
    add_new_eth(name, i, bank_type_eth, mutype[i], 
                 tx[i], ty[i], thidden_on_graph[i]);
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
void bank_sat_create(char *name, int mutype,
                     t_snf_info *snf_info, t_c2c_info *c2c_info,
                     double x, double y, 
                     double xa, double ya, 
                     double xb, double yb, 
                     int hidden)
{
  t_bank_item *sat;
  sat = look_for_sat_with_id(name);
  if (sat)
    KERR("%s", name);
  else
    {
    add_new_sat(name, mutype, snf_info, c2c_info, x, y, hidden);
    if (mutype == musat_type_a2b)
      {
      add_new_eth(name, 0, bank_type_eth, mutype, xa, ya, hidden);
      add_new_eth(name, 1, bank_type_eth, mutype, xb, yb, hidden);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_lan_create(char *lan,  double x, double y, int hidden_on_graph)
{
  add_new_lan(lan, x, y, hidden_on_graph);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void finish_delete_edge(t_bank_item *intf, t_bank_item *lan)
{
  t_bank_item *edge_item;
  if (intf && lan)
    {
    edge_item = edge_does_exist(intf, lan);
    if (edge_item)
      {
      if (edge_item->att_eth != intf)
        KOUT(" ");
      if (edge_item->att_lan != lan)
        KOUT(" ");
      delete_bitem(edge_item);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_edge_eth_delete(char *name, int num, char *lan)
{
  t_bank_item *intf, *blan;
  intf = look_for_eth_with_id(name, num);
  blan  = look_for_lan_with_id(lan);
  finish_delete_edge(intf, blan);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_edge_sat_delete(char *name, char *lan, int num)
{
  t_bank_item *sat, *blan;
  sat = look_for_sat_with_id(name);
  blan = look_for_lan_with_id(lan);
  finish_delete_edge(sat, blan);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_node_delete(char *name)
{
  t_bank_item *node;
  node = look_for_node_with_id(name);
  if (node)
    {
    delete_bitem(node);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_sat_delete(char *name)
{
  t_bank_item *sat;
  sat = look_for_sat_with_id(name);
  if (sat)
    delete_bitem(sat);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void bank_lan_delete(char *lan)
{
  t_bank_item *blan;
  blan = look_for_lan_with_id(lan);
  if (blan)
    {
    delete_bitem(blan);
    }
}
/*--------------------------------------------------------------------------*/
