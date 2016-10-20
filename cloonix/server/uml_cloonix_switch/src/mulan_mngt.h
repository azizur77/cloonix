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
int mulan_can_be_found_with_llid(int llid, char *name);
int mulan_can_be_found_with_name(char *name);
void mulan_rpct_recv_diag_msg(int llid, int tid, char *line);
void mulan_rpct_recv_evt_msg(int llid, int tid, char *line);
int mulan_get_all_llid(int **llid_tab);
int mulan_start(char *lan, int start_is_vm, char *name, int vm_eth);
void mulan_test_stop(char *lan);
int  mulan_get_all_pid(t_lst_pid **lst_pid);
void mulan_del_all(void);
int  mulan_is_zombie(char *lan);
int mulan_exists(char *lan);
int mulan_is_oper(char *lan);
void mulan_init(void);
void mulan_err_cb (int llid);
void mulan_pid_resp(int llid, char *name, int pid);
/*--------------------------------------------------------------------------*/

