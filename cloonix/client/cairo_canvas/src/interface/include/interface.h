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
void to_cloonix_switch_create_node(double x, double y,
                                   double *tx, double *ty);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_create_sat(char *name, int mutype, 
                                  t_c2c_req_info *c2c_req_info,
                                  double x, double y, 
                                  double xa, double ya, 
                                  double xb, double yb);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_create_lan(char *lan, double x, double y);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_delete_node(char *name);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_delete_sat(char *name);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_delete_snf(char *name);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_delete_lan(char *lan);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_create_eth_edge(char *name, int num, int bank_type,
                                        char *lan, int mutype);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_create_sat_edge(char *name, char *lan, 
                                       int mutype, int num);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_delete_eth_edge(char *name, int num, 
                                        int bank_type, char *lan);
/*--------------------------------------------------------------------------*/
void to_cloonix_switch_delete_sat_edge(char *name, char *lan,
                                       int mutype, int num);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_create_node(char *name, char *ip, char *kernel,
                                     char *rootfs_sod, 
                                     char *rootfs_backing_file, 
                                     char *install_cdrom, char *added_cdrom,
                                     char *added_disk,
                                     int qty_eth, int vm_id, 
                                     int vm_config_flags); 
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_create_snf(char *name, char *recpath, 
                                      int capture_on);
void from_cloonix_switch_delete_snf(char *name);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_create_sat(char *name, int mutype, 
                                    t_snf_info *snf_info, t_c2c_info *c2c_info);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_create_lan(char *lan);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_create_eth_edge(char *name, int num, char *lan);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_create_sat_edge(char *name, char *lan, int num);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_delete_node(char *name);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_delete_sat(char *name);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_delete_lan(char *lan);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_delete_eth_edge(char *name, int num, char *lan);
/*--------------------------------------------------------------------------*/
void from_cloonix_switch_delete_sat_edge(char *name, char *lan, int num);
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void interface_switch_init(char *path, char *password);
/*--------------------------------------------------------------------------*/
void launch_xterm_double_click(char *name, int vm_config_flags);
/*--------------------------------------------------------------------------*/
int get_vm_id_from_topo(char *name);
/*--------------------------------------------------------------------------*/
void timer_layout_subscribe(void *data);
/*--------------------------------------------------------------------------*/











