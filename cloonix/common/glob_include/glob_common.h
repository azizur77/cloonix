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
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <syslog.h>
#include <string.h>
long long cloonix_get_msec(void);
long long cloonix_get_usec(void);
void cloonix_set_pid(int pid);
int cloonix_get_pid(void);

#define KERR(format, a...)                               \
 do {                                                    \
    syslog(LOG_ERR | LOG_USER, "%07u %s"                 \
    " line:%d " format "\n", (unsigned int) cloonix_get_msec(),   \
    (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), \
     __LINE__, ## a);                                    \
    } while (0)

#define KOUT(format, a...)                               \
 do {                                                    \
    syslog(LOG_ERR | LOG_USER, "KILL %07u %s"            \
    " line:%d   " format "\n\n", (unsigned int) cloonix_get_msec(),  \
    (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__), \
     __LINE__, ## a);                                    \
    exit(-1);                                            \
    } while (0)

#define MAX_VM             100
#define MAX_ETH_VM         15

#define MAX_PATH_LEN       300 
#define MAX_NAME_LEN       64
#define CLOWNIX_MAX_CHANNELS 10000
#define MAX_SELECT_CHANNELS 500

#define MAX_TRAF_ENDPOINT 4

#define MAX_POLAR_COORD 314
#define NODE_DIA 75
#define A2B_DIA 30 
#define VAL_INTF_POS_NODE 0.5 
#define VAL_INTF_POS_A2B 0.7 
#define MAX_HOP_PRINT_LEN 2000
#define DOUT rpct_hop_print

#define FLAG_HOP_EVT    0x0001
#define FLAG_HOP_DIAG   0x0002
#define FLAG_HOP_APP    0x0004
#define FLAG_HOP_DOORS  0x0008

#define MAX_DOORWAYS_BUF_LEN 1000000
#define MAX_DOOR_CTRL_LEN 1000


#define MAX_RPC_MSG_LEN 5000

#define MAX_CLOWNIX_BOUND_LEN      64
#define MIN_CLOWNIX_BOUND_LEN      2


#define HEADER_BLKD_SIZE (4 + 8 + sizeof(long long))
#define PAYLOAD_BLKD_SIZE 1524
#define MAX_TOTAL_BLKD_SIZE (HEADER_BLKD_SIZE+PAYLOAD_BLKD_SIZE)
#define GROUP_BLKD_MAX_SIZE (40 * MAX_TOTAL_BLKD_SIZE)
#define MAX_QEMU_BLKD_IN_GROUP 10
#define MAX_TX_BLKD_QUEUED_BYTES (10 * GROUP_BLKD_MAX_SIZE)
#define MAX_GLOB_BLKD_QUEUED_BYTES (100 * GROUP_BLKD_MAX_SIZE)

#define MAC_ADDR_LEN 6
#define VM_CONFIG_FLAG_PERSISTENT      0x00001
#define VM_CONFIG_FLAG_EVANESCENT      0x00002
#define VM_CONFIG_FLAG_9P_SHARED       0x00004
#define VM_CONFIG_FLAG_FULL_VIRT       0x00008
#define VM_CONFIG_FLAG_BALLOONING      0x00010
#define VM_CONFIG_FLAG_INSTALL_CDROM   0x00020
#define VM_CONFIG_FLAG_NO_REBOOT       0x00040
#define VM_CONFIG_FLAG_ADDED_CDROM     0x00080
#define VM_CONFIG_FLAG_ADDED_DISK      0x00100
#define VM_CONFIG_FLAG_CISCO           0x00200
#define VM_CONFIG_FLAG_ARM             0x00400
#define VM_CONFIG_FLAG_AARCH64         0x00800
#define VM_CONFIG_FLAG_VHOST_VSOCK     0x01000

#define VM_FLAG_DERIVED_BACKING        0x10000
#define VM_FLAG_IS_INSIDE_CLOONIX      0x20000
#define VM_FLAG_CLOONIX_AGENT_PING_OK  0x80000


#define WIRESHARK_BINARY_QT "/usr/bin/wireshark-qt"
#define WIRESHARK_BINARY "/usr/bin/wireshark"
#define FLAGS_CONFIG_WIRESHARK_QT_PRESENT 0x0001
#define FLAGS_CONFIG_WIRESHARK_PRESENT 0x0002

#define MSG_DIGEST_LEN 32

enum {
  mutype_none = 0,
  mulan_type,
  endp_type_tap,
  endp_type_wif,
  endp_type_raw,
  endp_type_snf,
  endp_type_c2c,
  endp_type_a2b,
  endp_type_nat,
  endp_type_kvm,
};



enum{
  doors_type_min = 100,

  doors_type_listen_server,
  doors_type_server,

  doors_type_high_prio_begin,
  doors_type_switch,
  doors_type_c2c_init,
  doors_type_high_prio_end,

  doors_type_low_prio_begin,
  doors_type_dbssh,
  doors_type_openssh,
  doors_type_spice,
  doors_type_dbssh_x11_ctrl,
  doors_type_dbssh_x11_traf,
  doors_type_low_prio_end,

  doors_type_max,
};

enum{
  doors_val_min = 200,
  doors_val_none,
  doors_val_sig,
  doors_val_init_link,
  doors_val_init_link_ok,
  doors_val_init_link_ko,
  doors_val_max,
};
/*---------------------------------------------------------------------------*/
typedef struct t_topo_clc
{
  char version[MAX_NAME_LEN];
  char network[MAX_NAME_LEN];
  char username[MAX_NAME_LEN];
  int  server_port;
  char work_dir[MAX_PATH_LEN];
  char bin_dir[MAX_PATH_LEN];
  char bulk_dir[MAX_PATH_LEN];
  int  flags_config;
} t_topo_clc;
/*---------------------------------------------------------------------------*/
typedef struct t_lan_group_item
{
  char lan[MAX_NAME_LEN];
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
} t_eth_params;
/*---------------------------------------------------------------------------*/
typedef struct t_topo_kvm
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
  char install_cdrom[MAX_PATH_LEN];
  char added_cdrom[MAX_PATH_LEN];
  char added_disk[MAX_PATH_LEN];
  char p9_host_share[MAX_PATH_LEN];
  int vm_id;
} t_topo_kvm;
/*---------------------------------------------------------------------------*/
typedef struct t_topo_c2c
  {
  char name[MAX_NAME_LEN];
  char master_cloonix[MAX_NAME_LEN];
  char slave_cloonix[MAX_NAME_LEN];
  int local_is_master;
  int is_peered;
  int ip_slave;
  int port_slave;
  } t_topo_c2c;
/*---------------------------------------------------------------------------*/
typedef struct t_topo_snf
  {
  char name[MAX_NAME_LEN];
  char recpath[MAX_PATH_LEN];
  int capture_on;
  } t_topo_snf;
/*---------------------------------------------------------------------------*/
typedef struct t_topo_sat
  {
  char name[MAX_NAME_LEN];
  int  type;
  } t_topo_sat;
/*---------------------------------------------------------------------------*/
typedef struct t_topo_endp
{
  char name[MAX_NAME_LEN];
  int  num;
  int  type;
  t_lan_group lan;
} t_topo_endp;
/*---------------------------------------------------------------------------*/
typedef struct t_topo_info
{
  t_topo_clc clc;

  int nb_kvm;
  t_topo_kvm *kvm;

  int nb_c2c;
  t_topo_c2c *c2c;

  int nb_snf;
  t_topo_snf *snf;

  int nb_sat;
  t_topo_sat *sat;

  int nb_endp;
  t_topo_endp *endp;

} t_topo_info;
/*---------------------------------------------------------------------------*/






