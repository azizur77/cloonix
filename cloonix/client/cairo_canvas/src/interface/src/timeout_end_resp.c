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
#include "doorways_sock.h"
#include "client_clownix.h"
#include "commun_consts.h"
#include "interface.h"
#include "bank.h"
#include "popup.h"
#include "layout_x_y.h"
#include "timeout_start_resp.h"



/****************************************************************************/
void timer_create_item_node_resp(void *data)
{
  t_create_item_node_resp *pa = (t_create_item_node_resp *) data;
  int hidden_on_graph, color_choice;
  double x, y;
  double tx[MAX_PERIPH_VM];
  double ty[MAX_PERIPH_VM];
  int thidden_on_graph[MAX_PERIPH_VM];

  if (pa->bank_type != bank_type_node)
    KOUT("%d", pa->bank_type);
  get_node_layout_x_y(pa->name, &color_choice, &x, &y, &hidden_on_graph, 
                      tx, ty, thidden_on_graph);
  bank_node_create(pa->name, pa->ip, pa->kernel, pa->rootfs_sod, 
                   pa->rootfs_backing_file,  
                   pa->install_cdrom, pa->added_cdrom, pa->node_bdisk,
                   pa->bank_type, pa->num_eth, pa->mutype,
                   color_choice, pa->vm_id, pa->vm_config_flags,
                   x, y, hidden_on_graph, tx, ty, thidden_on_graph);
  clownix_free(pa, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void timer_create_item_resp(void *data)
{
  t_item_lan_resp *lan_pa = (t_item_lan_resp *) data;
  t_item_sat_resp *sat_pa;
  double x, y, xa, ya, xb, yb;
  int hidden_on_graph;
  switch(lan_pa->bank_type)
    {
    case bank_type_lan:
      get_gene_layout_x_y(lan_pa->bank_type, lan_pa->name, lan_pa->mutype, 
                          &x, &y,  &xa, &ya, &xb, &yb, &hidden_on_graph);
      bank_lan_create(lan_pa->name,  x, y, hidden_on_graph);
      break;
    case bank_type_sat:
      sat_pa = (t_item_sat_resp *) data;
      get_gene_layout_x_y(sat_pa->bank_type, sat_pa->name, sat_pa->mutype, 
                          &x, &y, &xa, &ya, &xb, &yb, &hidden_on_graph);
      bank_sat_create(sat_pa->name, sat_pa->mutype,
                      &(sat_pa->snf_info), &(sat_pa->c2c_info),
                      x, y, xa, ya, xb, yb, hidden_on_graph);
      break;

    default:
      KOUT("%d", lan_pa->bank_type);
    }
  clownix_free(data, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void timer_create_edge_eth_resp(void *data)
{
  t_edge_resp *pa = (t_edge_resp *) data;
  bank_edge_eth_create(pa->name, pa->num, pa->lan);
  clownix_free(pa, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void timer_create_edge_resp(void *data)
{
  t_edge_resp *pa = (t_edge_resp *) data;
  switch(pa->bank_type)
    {
    case bank_type_edge_sat2lan:
      if (sat_is_a_a2b(pa->name))
        bank_edge_eth_create(pa->name, pa->num, pa->lan);
      else
        bank_edge_sat_create(pa->name, pa->lan, pa->num);
      break;
    default:
      KOUT("%d", pa->bank_type);
    }
  clownix_free(pa, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void timer_delete_item_resp(void *data)
{
  t_item_delete_resp *pa = (t_item_delete_resp *) data;
  switch(pa->bank_type)
    {
    case bank_type_node:
      bank_node_delete(pa->name);
      break;
    case bank_type_lan:
      bank_lan_delete(pa->name);
      break;
    case bank_type_sat:
      bank_sat_delete(pa->name);
      break;
    default:
      KOUT("%d", pa->bank_type);
    }

  clownix_free(pa, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void timer_delete_edge_eth_resp(void *data)
{
  t_edge_resp *pa = (t_edge_resp *) data;
  if (pa->bank_type != bank_type_edge_eth2lan) 
    KOUT("%d", pa->bank_type);
  bank_edge_eth_delete(pa->name, pa->num, pa->lan);
  clownix_free(pa, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void timer_delete_edge_resp(void *data)
{
  t_edge_resp *pa = (t_edge_resp *) data;
  switch(pa->bank_type)
    {
    case bank_type_edge_sat2lan:
      if (sat_is_a_a2b(pa->name))
        bank_edge_eth_delete(pa->name, pa->num, pa->lan);
      else
        bank_edge_sat_delete(pa->name, pa->lan, pa->num);
      break;
    default:
      KOUT("%d", pa->bank_type);
    }
  clownix_free(pa, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/


