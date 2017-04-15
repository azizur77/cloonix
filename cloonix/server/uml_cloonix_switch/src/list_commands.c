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
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/types.h>
#include <unistd.h>
#include <string.h>
#include "io_clownix.h"
#include "lib_commons.h"
#include "commun_daemon.h"
#include "rpc_clownix.h"
#include "layout_rpc.h"
#include "cfg_store.h"
#include "lan_to_name.h"
#include "layout_topo.h"
#include "musat_mngt.h"



/*****************************************************************************/
static int can_increment_index(int val)
{
  int result = 1;
  if (val >= MAX_LIST_COMMANDS_QTY)
    {
    KERR("TOO MANY COMMANDS IN LIST");
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_add_vm_cmd(int offset, t_list_commands *hlist, 
                            t_vm_params *para)
{
  int len = 0;
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (can_increment_index(result))
    {
    len += sprintf(list->cmd + len, "cloonix_cli %s add kvm %s %d %d %d",
                   cfg_get_cloonix_name(), para->name, 
                   para->mem, para->cpu, para->nb_eth);
    len += sprintf(list->cmd + len, " %s", para->rootfs_input);
    if (para->vm_config_flags & VM_CONFIG_FLAG_PERSISTENT)
      len += sprintf(list->cmd + len, " --persistent");
    if (para->vm_config_flags & VM_CONFIG_FLAG_FULL_VIRT)
      len += sprintf(list->cmd + len, " --fullvirt");
    if (para->vm_config_flags & VM_CONFIG_FLAG_BALLOONING)
      len += sprintf(list->cmd + len, " --balloon");
    if (para->vm_config_flags & VM_CONFIG_FLAG_9P_SHARED)
      len += sprintf(list->cmd + len, " --9p_share=%s", para->p9_host_share);
    len += sprintf(list->cmd + len, " &");
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_add_tap_cmd(int offset, t_list_commands *hlist, t_tux *tux)
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (can_increment_index(result))
    {
    if (tux->musat_type == musat_type_tap)
      sprintf(list->cmd, "cloonix_cli %s add tap %s", 
                         cfg_get_cloonix_name(), tux->name);
    else if (tux->musat_type == musat_type_wif)
      sprintf(list->cmd, "cloonix_cli %s add wif %s", 
                         cfg_get_cloonix_name(), tux->name);
    else if (tux->musat_type == musat_type_raw)
      sprintf(list->cmd, "cloonix_cli %s add raw %s", 
                         cfg_get_cloonix_name(), tux->name);
    else
      KERR("%d", tux->musat_type);
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_add_c2c_cmd(int offset, t_list_commands *hlist, t_tux *tux) 
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s add c2c %s %s", 
            cfg_get_cloonix_name(), tux->name, 
            tux->c2c_info.req_cloonix_slave);
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_add_snf_cmd(int offset, t_list_commands *hlist, t_tux *tux)
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s add snf %s", 
                       cfg_get_cloonix_name(), tux->name);
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_add_a2b_cmd(int offset, t_list_commands *hlist, t_tux *tux)
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s add a2b %s",
                       cfg_get_cloonix_name(), tux->name);
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_add_nat_cmd(int offset, t_list_commands *hlist, t_tux *tux)
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s add nat %s",
                       cfg_get_cloonix_name(), tux->name);
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_add_sat_lan_cmd(int offset, t_list_commands *hlist, 
                                 char *name, int num, char *lan)
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s add lan %s %d %s", 
                        cfg_get_cloonix_name(), name, num, lan);
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_stop_go_cmd(int offset, t_list_commands *hlist, int go)
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (can_increment_index(result))
    {
    if (go)
      sprintf(list->cmd, "cloonix_cli %s cnf lay go", cfg_get_cloonix_name());
    else
      sprintf(list->cmd, "cloonix_cli %s cnf lay stop", cfg_get_cloonix_name());
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_width_height_cmd(int offset, t_list_commands *hlist, 
                                  int width, int height)
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (width && height)
    {
    if (can_increment_index(result))
      {
      sprintf(list->cmd, "cloonix_cli %s cnf lay width_height %d %d", 
                         cfg_get_cloonix_name(), width, height);
      result += 1;
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_center_scale_cmd(int offset, t_list_commands *hlist,
                                  int cx, int cy, int cw, int ch)
{
  int result = offset;
  t_list_commands *list = &(hlist[offset]);
  if (cw && ch)
    {
    if (can_increment_index(result))
      {
      sprintf(list->cmd, "cloonix_cli %s cnf lay scale %d %d %d %d", 
                         cfg_get_cloonix_name(), cx, cy, cw, ch);
      result += 1;
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_layout_eth(int offset, t_list_commands *hlist, 
                            char *name, int num, t_layout_eth *eth)
{
  int result = offset;
  t_list_commands *list = &(hlist[result]);
  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s cnf lay abs_xy_eth %s %d %d",
                        cfg_get_cloonix_name(), name, num, 
                        layout_node_solve(eth->x, eth->y));
    result += 1;
    if (eth->hidden_on_graph)
      {
      if (can_increment_index(result))
        {
        list = &(hlist[result]);
        sprintf(list->cmd, "cloonix_cli %s cnf lay hide_eth %s %d 1", 
                           cfg_get_cloonix_name(), name, num);
        result += 1;
        }
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_layout_node(int offset, t_list_commands *hlist, 
                             t_layout_node *node)
{
  int i, result = offset;
  t_list_commands *list = &(hlist[result]);

  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s cnf lay abs_xy_kvm %s %d %d",
                       cfg_get_cloonix_name(), node->name, 
                       (int) node->x, (int) node->y);
    result += 1;
    if (node->hidden_on_graph)
      {
      if (can_increment_index(result))
        {
        list = &(hlist[result]);
        sprintf(list->cmd, "cloonix_cli %s cnf lay hide_kvm %s 1", 
                           cfg_get_cloonix_name(), node->name);
        result += 1;
        }
      }
    }
  for (i=0; i < node->nb_eth; i++)
    result = build_layout_eth(result, hlist, node->name, i, &(node->eth[i])); 
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_layout_sat(int offset, t_list_commands *hlist, 
                            t_layout_sat *sat)
{
  int result = offset;
  t_list_commands *list = &(hlist[result]);
  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s cnf lay abs_xy_sat %s %d %d",
                       cfg_get_cloonix_name(), sat->name, 
                       (int) sat->x, (int) sat->y);
    result += 1;
    if (sat->hidden_on_graph)
      {
      if (can_increment_index(result))
        {
        list = &(hlist[result]);
        sprintf(list->cmd, "cloonix_cli %s cnf lay hide_sat %s 1", 
                           cfg_get_cloonix_name(), sat->name);
        result += 1;
        }
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int build_layout_lan(int offset, t_list_commands *hlist, 
                            t_layout_lan *lan)
{
  int result = offset;
  t_list_commands *list = &(hlist[result]);
  if (can_increment_index(result))
    {
    sprintf(list->cmd, "cloonix_cli %s cnf lay abs_xy_lan %s %d %d",
                       cfg_get_cloonix_name(), lan->name, 
                       (int) lan->x, (int) lan->y);
    result += 1;
    if (lan->hidden_on_graph)
      {
      if (can_increment_index(result))
        {
        list = &(hlist[result]);
        sprintf(list->cmd, "cloonix_cli %s cnf lay hide_lan %s 1", 
                           cfg_get_cloonix_name(), lan->name);
        result += 1;
        }
      }
   }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_sleep_line(int offset, t_list_commands *hlist, int sec)
{
  int result = offset;
  t_list_commands *list;
  if (can_increment_index(result))
    {
    list = &(hlist[result]);
    sprintf(list->cmd, "sleep %d", sec);
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_list_vm_cmd(int offset, t_list_commands *hlist,
                               int nb_vm, t_vm *vm) 
{
  int i, j, lan, result = offset;
  t_eth *eth;
  for (i=0; i<nb_vm; i++)
    {
    result = build_add_vm_cmd(result, hlist, &(vm->vm_params));
    result = produce_sleep_line(result, hlist, 5);
    eth = vm->eth_head;
    for (j=0; j<vm->nb_eth; j++)
      {
      lan = eth->lan_attached.lan;
      if (lan)
        {
        if (!lan_get_with_num(lan))
          KOUT(" ");
        result = build_add_sat_lan_cmd(result, hlist,
                                       vm->vm_params.name,
                                       eth->eth,
                                       lan_get_with_num(lan));
        }
      eth = eth->next;
      }
    vm = vm->next;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_list_sat_cmd(int offset, t_list_commands *hlist,
                                int nb_tux, t_tux *tux)
{
  int i, j, lan, result = offset;
  for (i=0; i<nb_tux; i++)
    {
    if (tux->is_musat)
      {
      if (musat_mngt_is_tap(tux->musat_type))
        {
        result = build_add_tap_cmd(result, hlist, tux);
        }
      else if (musat_mngt_is_c2c(tux->musat_type))
        {
        if (tux->c2c_info.local_is_master)
          result = build_add_c2c_cmd(result, hlist, tux);
        }
      else if (musat_mngt_is_snf(tux->musat_type))
        {
        result = build_add_snf_cmd(result, hlist, tux);
        }
      else if (musat_mngt_is_a2b(tux->musat_type))
        {
        result = build_add_a2b_cmd(result, hlist, tux);
        }
      else if (musat_mngt_is_nat(tux->musat_type))
        {
        result = build_add_nat_cmd(result, hlist, tux);
        }
      else
        KERR("%s", tux->name); 
      for (j=0; j<2; j++)
        {
        lan = tux->lan_attached[j].lan;
        if (lan)
          {
          if (!lan_get_with_num(lan))
            KOUT(" ");
          result = build_add_sat_lan_cmd(result, hlist,
                                         tux->name, j,
                                         lan_get_with_num(lan));
          }
        }
      } 
    tux = tux->next;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_list_canvas_layout_cmd(int offset, t_list_commands *hlist, 
                                          int go, int width, int height, 
                                          int cx, int cy, int cw, int ch)
{
  int result = offset;
  result = build_stop_go_cmd(result, hlist, go);
  result = produce_sleep_line(result, hlist, 1);
  result = build_width_height_cmd(result, hlist, width, height);
  result = produce_sleep_line(result, hlist, 1);
  result = build_center_scale_cmd(result, hlist, cx, cy, cw, ch);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_list_layout_node_cmd(int offset, t_list_commands *hlist,
                                        t_layout_node_xml *node_xml)
{
  int result = offset;
  t_layout_node_xml *cur = node_xml;
  while(cur)
    {
    result = build_layout_node(result, hlist, &(cur->node));
    cur = cur->next;
    }
  return result;
} 
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_list_layout_sat_cmd(int offset, t_list_commands *hlist,
                                       t_layout_sat_xml *sat_xml)    
{
  int result = offset;
  t_layout_sat_xml *cur = sat_xml;
  while(cur)
    {
    result = build_layout_sat(result, hlist, &(cur->sat));
    cur = cur->next;
    }
  return result;

}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_list_layout_lan_cmd(int offset, t_list_commands *hlist,
                                       t_layout_lan_xml *lan_xml)    
{
  int result = offset;
  t_layout_lan_xml *cur = lan_xml;
  while(cur)
    {
    result = build_layout_lan(result, hlist, &(cur->lan));
    cur = cur->next;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_first_lines(int offset, t_list_commands *hlist)
{
  int result = offset;
  t_list_commands *list;
  if (can_increment_index(result))
    {
    list = &(hlist[result]);
    sprintf(list->cmd, "#!/bin/bash");
    result += 1;
    }
  if (can_increment_index(result))
    {
    list = &(hlist[result]);
    sprintf(list->cmd, "#cloonix_net %s", cfg_get_cloonix_name());
    result += 1;
    }
  if (can_increment_index(result))
    {
    list = &(hlist[result]);
    sprintf(list->cmd, "#sleep 2");
    result += 1;
    }
  if (can_increment_index(result))
    {
    list = &(hlist[result]);
    sprintf(list->cmd, "#cloonix_gui %s", cfg_get_cloonix_name());
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int produce_last_lines(int offset, t_list_commands *hlist)
{
  int result = offset;
  t_list_commands *list;
  if (can_increment_index(result))
    {
    list = &(hlist[result]);
    sprintf(list->cmd, "echo END");
    result += 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int produce_list_commands(t_list_commands *hlist)
{
  int nb_vm, nb_tux, result = 0;
  t_vm  *vm  = cfg_get_first_vm(&nb_vm);
  t_tux *tux = cfg_get_first_tux(&nb_tux);
  int go, width, height, cx, cy, cw, ch;
  t_layout_xml *layout_xml;

  result = produce_first_lines(result, hlist);
  result = produce_list_vm_cmd(result, hlist, nb_vm, vm); 
  result = produce_list_sat_cmd(result, hlist, nb_tux, tux);
  get_layout_main_params(&go, &width, &height, &cx, &cy, &cw, &ch);
  result = produce_list_canvas_layout_cmd(result, hlist, go, 
                                               width, height, 
                                               cx, cy, cw, ch);
  layout_xml = get_layout_xml_chain();
  result = produce_list_layout_node_cmd(result, hlist, layout_xml->node_xml);
  result = produce_list_layout_sat_cmd(result, hlist, layout_xml->sat_xml);
  result = produce_list_layout_lan_cmd(result, hlist, layout_xml->lan_xml);
  result = produce_last_lines(result, hlist);
  return result;
}
/*---------------------------------------------------------------------------*/


