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
int musat_get_all_llid(int **llid_tab);
int musat_mngt_exists(char *name, int *musat_type);
int musat_mngt_stop(char *name);
int musat_mngt_send_mulan_connect(int delay, char *name, int eth, 
                                  char *lan, char *sock);
int musat_mngt_send_mulan_disconnect(char *name, int num,
                                     char *lan, char *sock);
int musat_mngt_connection_state_is_restfull(char *name);
int musat_mngt_get_type(char *name, int *musat_type);
int musat_mngt_get_all_pid(t_lst_pid **lst_pid);
int musat_mngt_can_be_found_with_llid(int llid, char *name, int *musat_type);
int musat_mngt_can_be_found_with_name(char *name, int *musat_type);
void musat_mngt_rpct_recv_diag_msg(int llid, int tid, char *line);
void musat_mngt_rpct_recv_evt_msg(int llid, int tid, char *line);
void musat_mngt_send_muswitch_quit(char *name);
void musat_mngt_stop_all(void);
void musat_mngt_err_cb (int llid);
void musat_mngt_pid_resp(int llid, char *name, int pid);
int musat_mngt_is_nat(int type);
int musat_mngt_is_tap(int type);
int musat_mngt_is_c2c(int type);
int musat_mngt_is_a2b(int type);
int musat_mngt_is_snf(int type);
int musat_mngt_get_type_with_name(char *name);
void musat_mngt_init(void);
void musat_mngt_update_unset_tux_action(char *name, t_tux *tmptux);
int fd_ready_doors_clone_has_arrived(char *name, int doors_fd);

void musat_mngt_add_vm(char *name, int vm_id, int nb_eth, t_eth_params *eth);
void musat_mngt_del_vm(char *name, int vm_id, int nb_eth, t_eth_params *eth);

int musat_mngt_start(int llid, int tid, char *name, int musat_type,
                     int snf_capture_on, char *snf_recpath,
                     char *req_cloonix_slave,
                     int c2c_ip_slave, int c2c_port_slave);
/*--------------------------------------------------------------------------*/

