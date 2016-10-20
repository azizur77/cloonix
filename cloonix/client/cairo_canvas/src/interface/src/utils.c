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
#include "interface.h"
#include "bank.h"
#include "move.h"


/****************************************************************************/
void process_all_diffs(t_topo_differences *diffs)
{
  t_topo_node_chain      *node  = diffs->add_nodes;
  t_topo_sat_chain       *sat   = diffs->add_sats;
  t_topo_lan_chain      *lan  = diffs->add_lans;
  t_topo_edge_eth_chain  *edgei = diffs->add_edge_eth;
  t_topo_edge_eth_chain  *edgeu = diffs->add_edge_sat;
  while(node)
    {
    from_cloonix_switch_create_node(node->name, node->ip, node->kernel,
                                    node->rootfs_used, 
                                    node->rootfs_backing, 
                                    node->node_bdisk, 
                                    node->num_eth, 
                                    node->vm_id, node->vm_config_flags);
    node = node->next;
    }

  while(sat)
    {
    from_cloonix_switch_create_sat(sat->name, sat->musat_type, 
                                   &(sat->snf_info), &(sat->c2c_info));
    sat = sat->next;
    }

  while(lan)
    {
    if (look_for_lan_with_id(lan->lan) == NULL)
      {
      from_cloonix_switch_create_lan(lan->lan);
      }
    lan = lan->next;
    }

  while(edgei)
    {
    from_cloonix_switch_create_eth_edge(edgei->name,edgei->num,edgei->lan);
    edgei = edgei->next;
    }

  while(edgeu)
    {
    from_cloonix_switch_create_sat_edge(edgeu->name, edgeu->lan, edgeu->num);
    edgeu = edgeu->next;
    }


  node  = diffs->del_nodes;
  sat   = diffs->del_sats;
  lan  = diffs->del_lans;
  edgei = diffs->del_edge_eth;
  edgeu = diffs->del_edge_sat;

  while(edgei)
    {
    from_cloonix_switch_delete_eth_edge(edgei->name,edgei->num,edgei->lan);
    edgei = edgei->next;
    }
  while(edgeu)
    {
    from_cloonix_switch_delete_sat_edge(edgeu->name, edgeu->lan, edgeu->num);
    edgeu = edgeu->next;
    }

  while(node)
    {
    from_cloonix_switch_delete_node(node->name);
    node = node->next;
    }
  while(sat)
    {
    from_cloonix_switch_delete_sat(sat->name);
    sat = sat->next;
    }

  while(lan)
    {
    from_cloonix_switch_delete_lan(lan->lan);
    lan = lan->next;
    }
}
/*--------------------------------------------------------------------------*/








