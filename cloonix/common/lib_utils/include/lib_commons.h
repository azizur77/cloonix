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

#define MAC_ADDR_LEN 6


#define VM_CONFIG_FLAG_PERSISTENT      0x0001
#define VM_CONFIG_FLAG_EVANESCENT      0x0002
#define VM_CONFIG_FLAG_9P_SHARED       0x0004
#define VM_CONFIG_FLAG_FULL_VIRT       0x0008
#define VM_CONFIG_FLAG_BALLOONING      0x0010
#define VM_CONFIG_FLAG_HAS_BDISK       0x0020
#define VM_CONFIG_FLAG_INSTALL_CDROM   0x0040

#define VM_FLAG_DERIVED_BACKING        0x10000
#define VM_FLAG_IS_INSIDE_CLOONIX      0x20000
#define VM_FLAG_CLOONIX_AGENT_PING_OK  0x80000


#define WIRESHARK_BINARY "/usr/bin/wireshark-qt"
#define FLAGS_CONFIG_WIRESHARK_QT_PRESENT 0x0001


/*---------------------------------------------------------------------------*/
typedef struct t_vm_config
{
  char name[MAX_NAME_LEN];
  char ip[MAX_NAME_LEN];
  char status[MAX_NAME_LEN];
  int vm_id;
  int vm_config_flags;
} t_vm_config;
/*---------------------------------------------------------------------------*/
typedef struct t_lan_group_item
{
  char name[MAX_NAME_LEN];
} t_lan_group_item;
/*---------------------------------------------------------------------------*/
typedef struct t_lan_group
{
  int nb_lan;
  t_lan_group_item *lan;
} t_lan_group;
/*---------------------------------------------------------------------------*/
typedef struct t_eth_params
{
  char mac_addr[MAC_ADDR_LEN];
  int is_promisc;
} t_eth_params;
/*---------------------------------------------------------------------------*/
typedef struct t_vm_params
{
  char name[MAX_NAME_LEN];
  int  vm_config_flags;
  int  cpu;
  int  mem;
  int  nb_eth;
  t_eth_params eth_params[MAX_ETH_VM];
  char linux_kernel[MAX_NAME_LEN];
  char rootfs_input[MAX_PATH_LEN];
  char rootfs_used[MAX_PATH_LEN];
  char rootfs_backing[MAX_PATH_LEN];
  char cdrom[MAX_PATH_LEN];
  char bdisk[MAX_PATH_LEN];
  char p9_host_share[MAX_PATH_LEN];
  int has_kvm_virt;
} t_vm_params;
/*---------------------------------------------------------------------------*/
typedef struct t_cloonix_config
{
  char version[MAX_NAME_LEN];
  char network_name[MAX_NAME_LEN];
  char username[MAX_NAME_LEN];
  char password[MSG_DIGEST_LEN];
  int  server_port;
  char work_dir[MAX_PATH_LEN];
  char bin_dir[MAX_PATH_LEN];
  char bulk_dir[MAX_PATH_LEN];
  int  flags_config;
} t_cloonix_config;
/*---------------------------------------------------------------------------*/
typedef struct t_vm_item
{
  t_vm_params vm_params;
  int  vm_id;
  t_lan_group lan_eth[MAX_ETH_VM+1];
} t_vm_item;
/*---------------------------------------------------------------------------*/
typedef struct t_c2c_req_info
  {
  char cloonix_slave[MAX_NAME_LEN];
  char passwd_slave[MSG_DIGEST_LEN];
  int ip_slave;
  int port_slave;
  } t_c2c_req_info;
/*---------------------------------------------------------------------------*/
typedef struct t_c2c_info
  {
  char req_cloonix_slave[MAX_NAME_LEN];
  int is_peered;
  int local_is_master;
  char master_cloonix[MAX_NAME_LEN];
  char slave_cloonix[MAX_NAME_LEN];
  int ip_slave;
  int port_slave;
  } t_c2c_info;
/*---------------------------------------------------------------------------*/
typedef struct t_snf_info
  {
  int capture_on;
  char recpath[MAX_PATH_LEN];
  } t_snf_info;
/*---------------------------------------------------------------------------*/
typedef struct t_sat_item
{
  char name[MAX_NAME_LEN];
  int  musat_type;
  t_snf_info snf_info;
  t_c2c_info c2c_info;
  t_lan_group lan0_sat;
  t_lan_group lan1_sat;
} t_sat_item;
/*---------------------------------------------------------------------------*/
typedef struct t_topo_info
{
  t_cloonix_config cloonix_config;
  int  nb_vm;
  t_vm_item *vmit;
  int  nb_sat;
  t_sat_item *sati;
} t_topo_info;
/*---------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------*/
typedef struct t_topo_node_chain
{
  char name[MAX_NAME_LEN];
  char ip[MAX_NAME_LEN];
  char kernel[MAX_NAME_LEN];
  char rootfs_used[MAX_PATH_LEN];
  char rootfs_backing[MAX_PATH_LEN];
  char node_cdrom[MAX_PATH_LEN];
  char node_bdisk[MAX_PATH_LEN];
  int num_eth;
  int vm_config_flags;
  int vm_id;
  struct t_topo_node_chain *prev;
  struct t_topo_node_chain *next;
} t_topo_node_chain;
/*--------------------------------------------------------------------------*/
typedef struct t_topo_sat_chain
{
  char name[MAX_NAME_LEN];
  int musat_type;
  t_snf_info snf_info;
  t_c2c_info c2c_info;
  struct t_topo_sat_chain *prev;
  struct t_topo_sat_chain *next;
} t_topo_sat_chain;
/*--------------------------------------------------------------------------*/
typedef struct t_topo_lan_chain
{
  char lan[MAX_NAME_LEN];
  struct t_topo_lan_chain *prev;
  struct t_topo_lan_chain *next;
} t_topo_lan_chain;
/*--------------------------------------------------------------------------*/
typedef struct t_topo_edge_eth_chain
{
  char name[MAX_NAME_LEN];
  int num;
  char lan[MAX_NAME_LEN];
  struct t_topo_edge_eth_chain *prev;
  struct t_topo_edge_eth_chain *next;
} t_topo_edge_eth_chain;
/*--------------------------------------------------------------------------*/
typedef struct t_topo_differences
{
  t_topo_node_chain      *add_nodes;
  t_topo_node_chain      *del_nodes;
  t_topo_sat_chain       *add_sats;
  t_topo_sat_chain       *del_sats;
  t_topo_lan_chain      *add_lans;
  t_topo_lan_chain      *del_lans;
  t_topo_edge_eth_chain *add_edge_eth;
  t_topo_edge_eth_chain *del_edge_eth;
  t_topo_edge_eth_chain  *add_edge_sat;
  t_topo_edge_eth_chain  *del_edge_sat;
} t_topo_differences;
/*--------------------------------------------------------------------------*/

void free_diffs(t_topo_differences *diffs);
t_topo_differences *get_topo_diffs(t_topo_info *topo, t_topo_info *old_topo);
/*--------------------------------------------------------------------------*/
int get_port_from_str(char *str_int);

int topo_find_vm_in_topo(char *name, t_topo_info *topo);
int topo_find_sat_in_topo(char *name, t_topo_info *topo);
int topo_find_lan_in_topo(char *lan, t_topo_info *topo);

t_topo_node_chain *topo_get_node_chain(t_topo_info *topo);
t_topo_sat_chain *topo_get_sat_chain(t_topo_info *topo);
t_topo_lan_chain *topo_get_lan_chain(t_topo_info *topo);
t_topo_edge_eth_chain *topo_get_edge_eth_node_chain(t_topo_info *topo);
t_topo_edge_eth_chain *topo_get_edge_eth_sat_chain(t_topo_info *topo);

void topo_free_node_chain(t_topo_node_chain *ch);
void topo_free_sat_chain(t_topo_sat_chain *ch);
void topo_free_lan_chain(t_topo_lan_chain *ch);
void topo_free_edge_eth_chain(t_topo_edge_eth_chain *ch);


/*****************************************************************************/
int found_in_lan_chain(t_topo_lan_chain *head, char *lan);


t_topo_info *random_topo_gen(void);
int topo_info_diff(t_topo_info *topo, t_topo_info *ref);
t_topo_info *topo_info_dup(t_topo_info *ref);
void topo_info_free(t_topo_info *topo);






