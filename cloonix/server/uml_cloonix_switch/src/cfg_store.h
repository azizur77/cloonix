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
struct t_vm;
struct t_eth;
struct t_tux;

typedef struct t_wake_up_eths
{
  int llid;
  int tid;
  int state;
  int nb_reqs_with_no_resp;
  long long automate_abs_beat; 
  int automate_ref;
  char name[MAX_NAME_LEN];
  char error_report[MAX_PRINT_LEN];
  long long abs_beat; 
  int ref;
  int destroy_requested;
} t_wake_up_eths;


typedef struct t_zombie
{ 
  char name[MAX_NAME_LEN];
  int vm_id;
  struct t_zombie *next;
  struct t_zombie *prev;
} t_zombie;

typedef struct t_newborn
{
  char name[MAX_NAME_LEN];
  struct t_newborn *next;
  struct t_newborn *prev;
} t_newborn;

/*---------------------------------------------------------------------------*/
typedef struct t_lan_attached
  {
  int lan;
  int eventfull_rx_p;
  int eventfull_tx_p;
  } t_lan_attached;
/*---------------------------------------------------------------------------*/
typedef struct t_tux
  {
  int is_musat;
  int musat_type;
  char name[MAX_NAME_LEN];
  t_snf_info snf_info;
  t_c2c_info c2c_info;
  t_lan_attached lan_attached[2];
  struct t_tux *prev;
  struct t_tux *next;
  } t_tux;
/*---------------------------------------------------------------------------*/
typedef struct t_eth
  {
  int eth;
  struct t_vm  *vm;
  char data_path[MAX_PATH_LEN];
  t_lan_attached lan_attached;
  struct t_eth *prev;
  struct t_eth *next;
  } t_eth;
/*---------------------------------------------------------------------------*/
typedef struct t_vm
  {
  t_vm_params vm_params;
  int saved_pid;
  int pid_of_cp_clone;
  char binary_name[MAX_NAME_LEN];
  int  locked_vm;
  int  vm_to_be_killed;
  int tmux_launch;
  t_wake_up_eths *wake_up_eths;
  int pid;
  int ram;
  int mem_rss;
  int cpu;
  unsigned long previous_utime;
  unsigned long previous_cutime;
  unsigned long previous_stime;
  unsigned long previous_cstime;
  int vm_id;
  int nb_eth;
  t_eth *eth_head;
  struct t_vm *prev;
  struct t_vm *next;
  } t_vm;
/*---------------------------------------------------------------------------*/
typedef struct t_cfg
  {
  t_cloonix_config cloonix_config;
  int lock_fd;
  int nb_vm;
  int nb_tux;
  t_vm *vm_head;
  t_tux *tux_head;
  } t_cfg;
/*---------------------------------------------------------------------------*/
t_cloonix_config *cfg_get_cloonix_config(void);
char *cfg_get_work(void);
char *cfg_get_work_vm(int vm_id);
char *cfg_get_root_work(void);
char *cfg_get_bulk(void);
char *cfg_get_bin_dir(void);


void cfg_set_host_conf(t_cloonix_config *config);
int  cfg_get_server_port(void);

char *cfg_get_ctrl_doors_sock(void);

/*---------------------------------------------------------------------------*/
int cfg_set_vm(t_vm_params *vm_params, int vm_id, int llid); 
int cfg_set_tux(int is_musat, int musat_type, char *name, int llid);
int cfg_set_eth(t_vm_params *vm_params, int eth, char *data);
int cfg_set_eth_lan(char *name, int num, char *lan, int llid_req);
int cfg_set_tux_lan(char *name, int num, char *lan, int llid_req);

/*---------------------------------------------------------------------------*/
int cfg_unset_vm(t_vm *vm);
void cfg_unset_eth(t_vm *vm, t_eth *eth);
int cfg_unset_tux(char *tux);
int cfg_unset_eth_lan(char *name, int eth, char *lan);
int cfg_unset_tux_lan(char *name, int num, char *lan);

/*---------------------------------------------------------------------------*/

t_vm *find_vm_with_id(int vm_id);

t_vm   *cfg_get_vm(char *name);
int cfg_get_vm_locked(t_vm *vm);
void cfg_set_vm_locked(t_vm *vm);
void cfg_reset_vm_locked(t_vm *vm);

t_eth  *cfg_find_eth(t_vm *vm, int eth);
t_tux *cfg_get_tux(char *name);
t_tux *cfg_get_c2c_tux(char *name);
int    cfg_get_eth(char *name, int eth);
int    cfg_check_eth(int vm_id, int eth, char *path);
/*---------------------------------------------------------------------------*/
t_vm   *cfg_get_first_vm(int *nb);
t_tux *cfg_get_first_tux(int *nb);
t_eth  *cfg_get_first_eth(char *name, int *nb);
void cfg_inc_lan_stats_tx_idx(int delta);


void cfg_set_lock_fd(int fd);
int  cfg_get_lock_fd(void);
int  cfg_alloc_vm_id(void);
void cfg_free_vm_id(int vm_id);


t_zombie *cfg_is_a_zombie_with_vm_id(int vm_id);
t_zombie *cfg_is_a_zombie(char *name);

void cfg_del_zombie(char *name);
void cfg_add_zombie(int vm_id, char *name);

void cfg_add_newborn(char *name);
void cfg_del_newborn(char *name);
t_newborn *cfg_is_a_newborn(char *name);

char *cfg_get_cloonix_name(void);
char *cfg_get_version(void);

/*---------------------------------------------------------------------------*/
void cfg_init(void);
/*---------------------------------------------------------------------------*/


int cfg_compute_qty_elements(void);


int cfg_get_trace_fd_qty(int type);


t_topo_info *cfg_produce_topo_info(void);



/*****************************************************************************/
void recv_init(void);
void recv_coherency_lock(void);
void recv_coherency_unlock(void);
int  recv_coherency_locked(void);
/*---------------------------------------------------------------------------*/
int cfg_insert_c2c_to_topo(int local_is_master, char *name, 
                           char *master_cloonix, char *slave_cloonix);
int cfg_remove_c2c_from_topo(char *name);
/*---------------------------------------------------------------------------*/

int cfg_get_musat_type(char *name);
int cfg_exists_c2c_from_topo(char *name);
void topo_vlg(t_lan_group *vlg, int lan);
void cfg_c2c_is_peered(char *name, int is_peered);

t_vm   *cfg_get_first_vm(int *nb);
t_tux  *cfg_get_first_tux(int *nb);

int cfg_name_is_in_use(int is_lan, char *name, char *use);
/*---------------------------------------------------------------------------*/



