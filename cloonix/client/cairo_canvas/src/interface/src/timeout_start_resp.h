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
typedef struct t_create_item_node_resp
{
  int bank_type;
  char name[MAX_NAME_LEN];
  char kernel[MAX_NAME_LEN];
  char rootfs_sod[MAX_PATH_LEN];
  char rootfs_backing_file[MAX_PATH_LEN];
  char install_cdrom[MAX_PATH_LEN];
  char added_cdrom[MAX_PATH_LEN];
  char added_disk[MAX_PATH_LEN];
  char ip[MAX_NAME_LEN];
  int num_eth;
  int mutype[MAX_ETH_VM];
  int vm_id;
  int vm_config_flags;
} t_create_item_node_resp;
/*--------------------------------------------------------------------------*/
typedef struct t_item_sat_resp
{
  int bank_type;
  char name[MAX_NAME_LEN];
  int mutype;
  t_snf_info snf_info;
  t_c2c_info c2c_info;
} t_item_sat_resp;
/*--------------------------------------------------------------------------*/
typedef struct t_item_lan_resp
{
  int bank_type;
  int mutype;
  char name[MAX_NAME_LEN];
} t_item_lan_resp;
/*--------------------------------------------------------------------------*/
typedef struct t_item_delete_resp
{
  int bank_type;
  char name[MAX_NAME_LEN];
} t_item_delete_resp;
/*--------------------------------------------------------------------------*/
typedef struct t_edge_resp
{
  int bank_type;
  char name[MAX_PATH_LEN];
  char lan[MAX_NAME_LEN];
  int num;
} t_edge_resp;
/*--------------------------------------------------------------------------*/
void timer_create_item_node_resp(void *param);
void timer_create_item_resp(void *param);
void timer_create_edge_eth_resp(void *param);
void timer_create_edge_resp(void *param);
/*--------------------------------------------------------------------------*/
void timer_delete_item_resp(void *param);
void timer_delete_edge_eth_resp(void *param);
void timer_delete_edge_resp(void *param);
/*--------------------------------------------------------------------------*/








