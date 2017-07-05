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
typedef struct t_lan_attached
{
  int lan_num;
  int eventfull_rx_p;
  int eventfull_tx_p;
} t_lan_attached;

typedef struct t_endp
{
  char name[MAX_NAME_LEN];
  int num;
  int pid;
  int endp_type;
  t_topo_c2c c2c;
  t_topo_snf snf;
  t_lan_attached lan_attached[MAX_TRAF_ENDPOINT];
  void *next;
} t_endp;

t_endp *endp_mngt_get_first(int *nb_endp);
t_endp *endp_mngt_get_next(t_endp *endp);
int endp_mngt_get_nb(int type);
int endp_mngt_get_nb_sat(void);
int endp_mngt_get_nb_all(void);
int endp_mngt_get_all_llid(int **llid_tab);
int endp_mngt_lan_connect(int delay, char *name, int num, int tidx, char *lan);
int endp_mngt_lan_disconnect(char *name, int num, int tidx, char *lan);
int endp_mngt_connection_state_is_restfull(char *name, int num);
int endp_mngt_exists(char *name, int num, int *endp_type);
int endp_mngt_get_all_pid(t_lst_pid **lst_pid);
int endp_mngt_can_be_found_with_name(char *name, int num, int *endp_type);
int endp_mngt_can_be_found_with_llid(int llid, char *name,
                                     int *num, int *endp_type);
void endp_mngt_rpct_recv_diag_msg(int llid, int tid, char *line);
void endp_mngt_rpct_recv_evt_msg(int llid, int tid, char *line);
void endp_mngt_send_quit(char *name, int num);
void endp_mngt_err_cb (int llid);
void endp_mngt_pid_resp(int llid, char *name, int toppid, int pid);
void endp_mngt_init(void);

int fd_ready_doors_clone_has_arrived(char *name, int doors_fd);

void endp_mngt_add_mac_eth_vm(char *name, int vm_id, int nb_eth, t_eth_params *eth);
void endp_mngt_del_mac_eth_vm(char *name, int vm_id, int nb_eth, t_eth_params *eth);

int endp_mngt_start(int llid, int tid, char *name, int num, int endp_type);

void endp_mngt_stop_all(void);
int endp_mngt_stop(char *name, int num);

void endp_mngt_snf_set_name(char *name, int num);
void endp_mngt_snf_set_capture(char *name, int num, int capture_on);
void endp_mngt_snf_set_recpath(char *name, int num, char *recpath);

void endp_mngt_c2c_info(char *name, int num, int local_is_master,
                        char *master, char *slave, int ip, int port, 
                        char *slave_passwd);             
void endp_mngt_c2c_peered(char *name, int num, int is_peered);
void endp_mngt_c2c_disconnect(char *name, int num);
void endp_mngt_add_attached_lan(int llid, char *name, int num,
                                int tidx, char *lan);
void endp_mngt_del_attached_lan(char *name, int num, int tidx, char *lan);
int endp_mngt_kvm_pid_clone(char *name, int num, int pid);
void endp_mngt_erase_eventfull_stats(void);

/*--------------------------------------------------------------------------*/

