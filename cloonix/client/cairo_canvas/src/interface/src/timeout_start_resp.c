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
#include <sys/stat.h>
#include <unistd.h>
#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "bank.h"
#include "timeout_start_resp.h"
#include "popup.h"
#include "interface.h"

/****************************************************************************/
static void gene_delete_item(int bank_type, char *name)
{
  t_item_delete_resp *pa;
  pa = (t_item_delete_resp *) clownix_malloc(sizeof(t_item_delete_resp), 12);
  memset(pa, 0, sizeof(t_item_delete_resp));
  pa->bank_type = bank_type;
  strncpy(pa->name, name, MAX_NAME_LEN-1);
  clownix_timeout_add(1,timer_delete_item_resp,(void *)pa,NULL,NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void gene_create_edge(int bank_type, char *name, char *lan, int num)
{
  t_edge_resp *pa;
  pa = (t_edge_resp *) clownix_malloc(sizeof(t_edge_resp), 12);
  memset(pa, 0, sizeof(t_edge_resp));
  pa->bank_type = bank_type;
  pa->num = num;
  strncpy(pa->name, name, MAX_NAME_LEN-1);
  strncpy(pa->lan, lan, MAX_NAME_LEN-1);
  clownix_timeout_add(1,timer_create_edge_resp,(void *)pa,NULL,NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void gene_delete_edge(int bank_type, char *name, char *lan, int num)
{
  t_edge_resp *pa;
  pa = (t_edge_resp *) clownix_malloc(sizeof(t_edge_resp), 12);
  memset(pa, 0, sizeof(t_edge_resp));
  pa->bank_type = bank_type;
  pa->num = num;
  strncpy(pa->name, name, MAX_NAME_LEN-1);
  strncpy(pa->lan, lan, MAX_NAME_LEN-1);
  clownix_timeout_add(1,timer_delete_edge_resp,(void *)pa,NULL,NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_create_node(char *name, char *ip, char *kernel,
                                     char *rootfs_sod, char *rootfs_backing,
                                     char *install_cdrom, char *added_cdrom, 
                                     char *added_disk, int qty_eth, 
                                     int vm_id, int vm_config_flags)
{
  t_create_item_node_resp *pa;
  int len = sizeof(t_create_item_node_resp);
  pa = (t_create_item_node_resp *)clownix_malloc(len, 12);
  memset(pa, 0, len);
  pa->bank_type = bank_type_node;
  strncpy(pa->name, name, MAX_NAME_LEN-1);
  pa->vm_id = vm_id;
  strncpy(pa->rootfs_sod, rootfs_sod, MAX_PATH_LEN-1);
  strncpy(pa->rootfs_backing_file, rootfs_backing, MAX_PATH_LEN-1);
  strncpy(pa->install_cdrom, install_cdrom, MAX_PATH_LEN-1);
  strncpy(pa->added_cdrom, added_cdrom, MAX_PATH_LEN-1);
  strncpy(pa->added_disk, added_disk, MAX_PATH_LEN-1);
  if (kernel)
    strncpy(pa->kernel, kernel, MAX_NAME_LEN-1);
  strncpy(pa->ip, ip, MAX_NAME_LEN-1);
  pa->num_eth = qty_eth;
  pa->vm_config_flags = vm_config_flags;
  clownix_timeout_add(1, timer_create_item_node_resp, (void *)pa, NULL,NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_create_sat(char *name, int mutype, 
                                    t_snf_info *snf_info, 
                                    t_c2c_info *c2c_info)
{
  t_item_sat_resp *pa;
  pa = (t_item_sat_resp *) clownix_malloc(sizeof(t_item_sat_resp), 12);
  memset(pa, 0, sizeof(t_item_sat_resp));
  pa->bank_type = bank_type_sat;
  strncpy(pa->name, name, MAX_NAME_LEN-1);
  pa->mutype = mutype;
  memcpy(&(pa->snf_info), snf_info, sizeof(t_snf_info));
  memcpy(&(pa->c2c_info), c2c_info, sizeof(t_c2c_info));
  clownix_timeout_add(1,timer_create_item_resp,(void *)pa,NULL,NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_create_lan(char *name)
{
  t_item_lan_resp *pa;
  pa = (t_item_lan_resp *) clownix_malloc(sizeof(t_item_lan_resp), 12);
  memset(pa, 0, sizeof(t_item_lan_resp));
  pa->bank_type = bank_type_lan;
  pa->mutype = mulan_type;
  strncpy(pa->name, name, MAX_NAME_LEN-1);
  clownix_timeout_add(1,timer_create_item_resp,(void *)pa,NULL,NULL);

}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_create_eth_edge(char *name, int num, char *lan)
{
  t_edge_resp *pa;
  pa = (t_edge_resp *) clownix_malloc(sizeof(t_edge_resp), 12);
  memset(pa, 0, sizeof(t_edge_resp));
  strncpy(pa->name, name, MAX_NAME_LEN-1);
  strncpy(pa->lan, lan, MAX_NAME_LEN-1);
  pa->num = num;
  clownix_timeout_add(1,timer_create_edge_eth_resp,(void *)pa,NULL,NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_create_sat_edge(char *name, char *lan, int num)
{
  gene_create_edge(bank_type_edge_sat2lan, name, lan, num);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_delete_node(char *name)
{
  t_bank_item *node = look_for_node_with_id(name);
  if (!node)
    KOUT("%s", name);
  gene_delete_item(node->bank_type, name);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_delete_sat(char *name)
{
  gene_delete_item(bank_type_sat, name);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_delete_lan(char *lan)
{
  gene_delete_item(bank_type_lan, lan);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_delete_eth_edge(char *name, int num, char *lan)
{
  t_edge_resp *pa;
  t_bank_item *intf = look_for_eth_with_id(name, num);
  int bank_type;
  if (intf)
    {
    if (intf->bank_type == bank_type_eth)
      bank_type = bank_type_edge_eth2lan;
    else
      KOUT("%s %d", name, num);
    pa = (t_edge_resp *) clownix_malloc(sizeof(t_edge_resp), 12);
    memset(pa, 0, sizeof(t_edge_resp));
    pa->bank_type = bank_type;
    strncpy(pa->name, name, MAX_NAME_LEN-1);
    strncpy(pa->lan, lan, MAX_NAME_LEN-1);
    pa->num = num;
    clownix_timeout_add(1,timer_delete_edge_eth_resp,(void *)pa,NULL,NULL);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void from_cloonix_switch_delete_sat_edge(char *name, char *lan, int num)
{
  gene_delete_edge(bank_type_edge_sat2lan, name, lan, num);
}
/*--------------------------------------------------------------------------*/







