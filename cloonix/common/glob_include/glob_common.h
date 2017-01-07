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
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <syslog.h>
#include <string.h>
void cloonix_set_sec_offset(int offset);
int cloonix_get_sec_offset(void);
unsigned int cloonix_get_msec(void);
long long cloonix_get_usec(void);
void cloonix_set_pid(int pid);
int cloonix_get_pid(void);
void cloonix_set_name(char *name);
char *cloonix_get_name(void);
char *cloonix_get_short(const char *full_name);



#define KERR(format, a...)                               \
 do {                                                    \
    syslog(LOG_ERR | LOG_USER, "%07u %d %s %s"           \
    " line:%d " format "\n", cloonix_get_msec(),         \
    cloonix_get_pid(), cloonix_get_name(),               \
    cloonix_get_short(__FILE__), __LINE__, ## a);        \
    } while (0)

#define KOUT(format, a...)                               \
 do {                                                    \
    syslog(LOG_ERR | LOG_USER, "KILL %07u %d %s %s"      \
    " line:%d   " format "\n\n", cloonix_get_msec(),     \
    cloonix_get_pid(), cloonix_get_name(),               \
    cloonix_get_short(__FILE__), __LINE__, ## a);        \
    exit(-1);                                            \
    } while (0)

#define MAX_VM             100
#define MAX_ETH_VM         15

#define MAX_PATH_LEN       300 
#define MAX_NAME_LEN       64
#define CLOWNIX_MAX_CHANNELS 10000
#define MAX_SELECT_CHANNELS 500


#define QEMU_ETH_FORMAT "%s_%d"

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

#define MAX_DOORWAYS_BUF_LEN    10000000
#define MAX_DOOR_CTRL_LEN 1000


#define MAX_CLOWNIX_BOUND_LEN      64
#define MIN_CLOWNIX_BOUND_LEN      2

#define MAX_MUTXT_LEN      2500

#define HEADER_BLKD_SIZE (4 + 8 + sizeof(long long))
#define PAYLOAD_BLKD_SIZE 1524
#define MAX_TOTAL_BLKD_SIZE (HEADER_BLKD_SIZE+PAYLOAD_BLKD_SIZE)
#define GROUP_BLKD_MAX_SIZE (20 * MAX_TOTAL_BLKD_SIZE)
#define MAX_QEMU_BLKD_IN_GROUP 10
#define MAX_TX_BLKD_QUEUED_BYTES (10 * GROUP_BLKD_MAX_SIZE)
#define MAX_GLOB_BLKD_QUEUED_BYTES (50 * GROUP_BLKD_MAX_SIZE)




enum {
  mutype_none = 0,
  mulan_type,
  musat_type_eth,
  musat_type_tap,
  musat_type_wif,
  musat_type_raw,
  musat_type_snf,
  musat_type_c2c,
  musat_type_a2b,
  musat_type_nat,
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
  doors_type_spice,
  doors_type_dbssh_x11_ctrl,
  doors_type_dbssh_x11_traf,
  doors_type_low_prio_end,

  doors_type_max,
};

enum{
  doors_val_min = 200,
  doors_val_none,
  doors_val_init_link,
  doors_val_init_link_ok,
  doors_val_init_link_ko,
  doors_val_max,
};


