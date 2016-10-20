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
int mueth_can_be_found_with_llid(int llid, char *name, int *eth);
int mueth_can_be_found_with_name(char *name, int eth);
void mueth_rpct_recv_diag_msg(int llid, int tid, char *line);
void mueth_rpct_recv_evt_msg(int llid, int tid, char *line);
int mueth_get_all_llid(int **llid_tab);
int mueth_vm_start(char *name, int eth);
int mueth_vm_stop(char *name, int eth);
int mueth_send_muswitch_connect(int delay, char *vm_name, int vm_eth,
                                char *lan, char *muswitch_sock);
int mueth_send_muswitch_disconnect(char *vm_name, int vm_eth,
                                   char *lan, char *muswitch_sock);
int mueth_ready(char *name, int eth);
void mueth_err_cb (int llid);
void mueth_pid_resp(int llid, char *name, int pid);
int mueth_exists(char *name, int eth);
void mueth_init(void);
/*--------------------------------------------------------------------------*/

