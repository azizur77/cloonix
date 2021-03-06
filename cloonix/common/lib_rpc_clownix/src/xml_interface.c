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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "io_clownix.h"
#include "lib_topo.h"
#include "xml_interface.h"
#include "rpc_clownix.h"
#include "header_sock.h"

/*---------------------------------------------------------------------------*/
static char *sndbuf = NULL;

/*---------------------------------------------------------------------------*/


enum 
  {
  bnd_min = 0,

  bnd_hop_get_list,
  bnd_hop_list,
  bnd_hop_evt_doors_sub,
  bnd_hop_evt_doors_unsub,
  bnd_hop_evt_doors,

  bnd_status_ok,
  bnd_status_ko,
  bnd_add_vm,
  bnd_sav_vm,
  bnd_sav_vm_all,
  bnd_add_sat_c2c,
  bnd_add_sat_non_c2c,
  bnd_del_sat,
  bnd_add_lan_endp,
  bnd_del_lan_endp,
  bnd_kill_uml_clownix,
  bnd_del_all,
  bnd_list_pid_req,
  bnd_list_pid_resp,
  bnd_list_commands_req,
  bnd_list_commands_resp,
  bnd_topo_small_event_sub,
  bnd_topo_small_event_unsub,
  bnd_topo_small_event,
  bnd_event_topo_sub,
  bnd_event_topo_unsub,
  bnd_event_topo,
  bnd_evt_print_sub,
  bnd_evt_print_unsub,
  bnd_event_print,
  bnd_event_sys_sub,
  bnd_event_sys_unsub,
  bnd_event_sys,
  bnd_work_dir_req,
  bnd_work_dir_resp,
  bnd_vmcmd,
  bnd_eventfull_sub,
  bnd_eventfull,
  bnd_mucli_dialog_req,
  bnd_mucli_dialog_resp,
  bnd_sub_evt_stats_endp,
  bnd_evt_stats_endp,
  bnd_sub_evt_stats_sysinfo,
  bnd_evt_stats_sysinfo,
  bnd_blkd_reports,
  bnd_blkd_reports_sub,
  bnd_qmp_all_sub,
  bnd_qmp_sub,
  bnd_qmp_req,
  bnd_qmp_msg,
  bnd_max,
  };
static char bound_list[bnd_max][MAX_CLOWNIX_BOUND_LEN];
/*---------------------------------------------------------------------------*/
static t_llid_tx g_llid_tx;
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void my_msg_mngt_tx(int llid, int len, char *buf)
{
  if (len > MAX_SIZE_BIGGEST_MSG - 1000)
    KOUT("%d %d", len, MAX_SIZE_BIGGEST_MSG);
  if (len > MAX_SIZE_BIGGEST_MSG/2)
    KERR("WARNING LEN MSG %d %d", len, MAX_SIZE_BIGGEST_MSG);
  if (msg_exist_channel(llid))
    {
    if (!g_llid_tx)
      KOUT(" ");
    buf[len] = 0;
    g_llid_tx(llid, len + 1, buf);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void extract_boundary(char *input, char *output)
{
  int bound_len;
  if (input[0] != '<')
    KOUT("%s\n", input);
  bound_len = strcspn(input, ">");
  if (bound_len >= MAX_CLOWNIX_BOUND_LEN)
    KOUT("%s\n", input);
  if (bound_len < MIN_CLOWNIX_BOUND_LEN)
    KOUT("%s\n", input);
  memcpy(output, input, bound_len);
  output[bound_len] = 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int get_bnd_event(char *bound)
{
  int i, result = 0;
  for (i=bnd_min; i<bnd_max; i++) 
    if (!strcmp(bound, bound_list[i]))
      {
      result = i;
      break;
      }
  return result;
}
/*---------------------------------------------------------------------------*/
 
/*****************************************************************************/
static char *string_to_xml(char *info)
{
  static char buf[MAX_PRINT_LEN];
  char *ptr = buf;
  strncpy(buf, info, MAX_PRINT_LEN);
  buf[MAX_PRINT_LEN-1] = 0;
  if (strlen(buf) == 0)
    sprintf(buf, "error in error report, 0 len txt");
  while(ptr)
    {
    ptr = strchr(ptr, ' ');
    if (ptr)
      *ptr = '%';
    }
  ptr = buf;
  while(ptr)
    {
    ptr = strchr(ptr, '\n');
    if (ptr)
      *ptr = '?';
    }
  return buf;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static char *xml_to_string(char *info)
{
  static char buf[MAX_PRINT_LEN];
  char *ptr = buf;
  strncpy(buf, info, MAX_PRINT_LEN);
  buf[MAX_PRINT_LEN-1] = 0;
  while(ptr)
    {
    ptr = strchr(ptr, '%');
    if (ptr)
      *ptr = ' ';
    }
  ptr = buf;
  while(ptr)
    {
   ptr = strchr(ptr, '?');
    if (ptr)
      *ptr = '\n';
    }
  return buf;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void sys_info_free(t_sys_info *sys)
{
  if (sys->queue_tx)   
    clownix_free(sys->queue_tx, __FUNCTION__);
  clownix_free(sys, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int fill_stats(char *buf, int nb, t_stats_count_item *item)
{
  int i, len = 0;
  for (i=0; i<nb; i++)
    {  
    len += sprintf(buf+len, EVT_STATS_ITEM, item[i].time_ms,
                                            item[i].ptx, item[i].btx,
                                            item[i].prx, item[i].brx);
    }
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_stats(char *msg, int nb, t_stats_count_item *item)
{
  char *ptr;
  int i;
  memset(item, 0, MAX_STATS_ITEMS*sizeof(t_stats_count_item));
  if ((nb < 0) || (nb > MAX_STATS_ITEMS))
    KOUT("%d", nb);
  ptr = msg;
  for (i=0; i<nb; i++)
    {
    ptr = strstr(ptr, "<item>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, EVT_STATS_ITEM, &(item[i].time_ms), 
                                    &(item[i].ptx), 
                                    &(item[i].btx),
                                    &(item[i].prx), 
                                    &(item[i].brx)) != 5)
      KOUT("%s", msg);
    ptr = strstr(ptr, "</item>");
    if (!ptr)
      KOUT("%s", msg);
    }
  ptr = strstr(ptr, "<item>");
  if (ptr)
    KOUT("%s", msg);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void topo_config_check_str(t_topo_clc *cf, int line)
{
  if (strlen(cf->version)  >= MAX_NAME_LEN)
    KOUT("%d", line);
  if (strlen(cf->network)  >= MAX_NAME_LEN)
    KOUT("%d", line);
  if (strlen(cf->username) >= MAX_NAME_LEN)
    KOUT("%d", line);
  if (strlen(cf->work_dir) >= MAX_PATH_LEN)
    KOUT("%d", line);
  if (strlen(cf->bin_dir)  >= MAX_PATH_LEN)
    KOUT("%d", line);
  if (strlen(cf->bulk_dir) >= MAX_PATH_LEN)
    KOUT("%d", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void topo_config_swapon(t_topo_clc *cf, t_topo_clc *icf)
{
  memcpy(cf, icf, sizeof(t_topo_clc));
  if (strlen(cf->version) == 0)
    strcpy(cf->version, NO_DEFINED_VALUE);
  if (strlen(cf->network) == 0)
    strcpy(cf->network, NO_DEFINED_VALUE);
  if (strlen(cf->username) == 0)
    strcpy(cf->username, NO_DEFINED_VALUE);
  if (strlen(cf->work_dir) == 0)
    strcpy(cf->work_dir, NO_DEFINED_VALUE);
  if (strlen(cf->bin_dir) == 0)
    strcpy(cf->bin_dir, NO_DEFINED_VALUE);
  if (strlen(cf->bulk_dir) == 0)
    strcpy(cf->bulk_dir, NO_DEFINED_VALUE);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void topo_config_swapoff(t_topo_clc  *cf, t_topo_clc *icf)
{
  memcpy(cf, icf, sizeof(t_topo_clc));
  if (!strcmp(cf->version, NO_DEFINED_VALUE))
    memset(cf->version, 0, MAX_NAME_LEN);
  if (!strcmp(cf->network, NO_DEFINED_VALUE))
    memset(cf->network, 0, MAX_NAME_LEN);
  if (!strcmp(cf->username, NO_DEFINED_VALUE))
    memset(cf->username, 0, MAX_NAME_LEN);
  if (!strcmp(cf->work_dir, NO_DEFINED_VALUE))
    memset(cf->work_dir, 0, MAX_NAME_LEN);
  if (!strcmp(cf->bin_dir, NO_DEFINED_VALUE))
    memset(cf->bin_dir, 0, MAX_NAME_LEN);
  if (!strcmp(cf->bulk_dir, NO_DEFINED_VALUE))
    memset(cf->bulk_dir, 0, MAX_NAME_LEN);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void topo_kvm_check_str(t_topo_kvm *kvm, int line)
{
  if (strlen(kvm->name) >= MAX_NAME_LEN)
    KOUT("%d", line);
  if (strlen(kvm->linux_kernel) >= MAX_NAME_LEN)
    KOUT("%d", line);
  if (strlen(kvm->rootfs_input) >= MAX_PATH_LEN)
    KOUT("%d", line);
  if (strlen(kvm->rootfs_used) >= MAX_PATH_LEN)
    KOUT("%d", line);
  if (strlen(kvm->rootfs_backing) >= MAX_PATH_LEN)
    KOUT("%d", line);
  if (strlen(kvm->install_cdrom) >= MAX_PATH_LEN)
    KOUT("%d", line);
  if (strlen(kvm->added_cdrom) >= MAX_PATH_LEN)
    KOUT("%d", line);
  if (strlen(kvm->added_disk) >= MAX_PATH_LEN)
    KOUT("%d", line);
  if (strlen(kvm->p9_host_share) >= MAX_PATH_LEN)
    KOUT("%d", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void topo_kvm_swapon(t_topo_kvm *kvm, t_topo_kvm *ikvm)
{
  memcpy(kvm, ikvm, sizeof(t_topo_kvm));
  if (strlen(kvm->name) == 0)
    strcpy(kvm->name, NO_DEFINED_VALUE);
  if (strlen(kvm->linux_kernel) == 0)
    strcpy(kvm->linux_kernel, NO_DEFINED_VALUE);
  if (strlen(kvm->rootfs_input) == 0)
    strcpy(kvm->rootfs_input, NO_DEFINED_VALUE);
  if (strlen(kvm->rootfs_used) == 0)
    strcpy(kvm->rootfs_used, NO_DEFINED_VALUE);
  if (strlen(kvm->rootfs_backing) == 0)
    strcpy(kvm->rootfs_backing, NO_DEFINED_VALUE);
  if (strlen(kvm->install_cdrom) == 0)
    strcpy(kvm->install_cdrom, NO_DEFINED_VALUE);
  if (strlen(kvm->added_cdrom) == 0)
    strcpy(kvm->added_cdrom, NO_DEFINED_VALUE);
  if (strlen(kvm->added_disk) == 0)
    strcpy(kvm->added_disk, NO_DEFINED_VALUE);
  if (strlen(kvm->p9_host_share) == 0)
    strcpy(kvm->p9_host_share, NO_DEFINED_VALUE);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void topo_kvm_swapoff(t_topo_kvm *kvm, t_topo_kvm *ikvm)
{
  memcpy(kvm, ikvm, sizeof(t_topo_kvm));
  if (!strcmp(kvm->name, NO_DEFINED_VALUE))
    memset(kvm->name, 0, MAX_NAME_LEN);
  if (!strcmp(kvm->linux_kernel, NO_DEFINED_VALUE))
    memset(kvm->linux_kernel, 0, MAX_NAME_LEN);
  if (!strcmp(kvm->rootfs_input, NO_DEFINED_VALUE))
    memset(kvm->rootfs_input, 0, MAX_NAME_LEN);
  if (!strcmp(kvm->rootfs_used, NO_DEFINED_VALUE))
    memset(kvm->rootfs_used, 0, MAX_NAME_LEN);
  if (!strcmp(kvm->rootfs_backing, NO_DEFINED_VALUE))
    memset(kvm->rootfs_backing, 0, MAX_NAME_LEN);
  if (!strcmp(kvm->install_cdrom, NO_DEFINED_VALUE))
    memset(kvm->install_cdrom, 0, MAX_NAME_LEN);
  if (!strcmp(kvm->added_cdrom, NO_DEFINED_VALUE))
    memset(kvm->added_cdrom, 0, MAX_NAME_LEN);
  if (!strcmp(kvm->added_disk, NO_DEFINED_VALUE))
    memset(kvm->added_disk, 0, MAX_NAME_LEN);
  if (!strcmp(kvm->p9_host_share, NO_DEFINED_VALUE))
    memset(kvm->p9_host_share, 0, MAX_NAME_LEN);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_hop_evt_doors_sub(int llid, int tid, int flags_hop,
                            int nb, t_hop_list *list)
{
  int i, len;
  len = sprintf(sndbuf, HOP_EVT_DOORS_SUB_O, tid, flags_hop, nb);
  for (i=0; i<nb; i++)
    {
    if ((list[i].name == NULL) ||
        (strlen(list[i].name) == 0) ||
        (strlen(list[i].name) >= MAX_NAME_LEN))
      KOUT(" ");
    len += sprintf(sndbuf+len, HOP_LIST_NAME_I, list[i].type_hop,
                                                list[i].name, list[i].num);
    }
  len += sprintf(sndbuf+len, HOP_EVT_DOORS_SUB_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_hop_evt_doors_unsub(int llid, int tid)
{
  int len;
  len = sprintf(sndbuf, HOP_EVT_DOORS_UNSUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_hop_evt_doors(int llid, int tid, int type_evt_sub,
                        char *name, char *txt)
{
  int len;
  if ((!name) || (strlen(name)==0) || (strlen(name) >= MAX_NAME_LEN))
    KOUT(" ");
  if ((!txt) || (strlen(txt)==0) || (strlen(txt) >= MAX_RPC_MSG_LEN))
    KOUT(" ");
  len = sprintf(sndbuf, HOP_EVT_DOORS_O, tid, type_evt_sub, name);
  len += sprintf(sndbuf+len, HOP_FREE_TXT, txt);
  len += sprintf(sndbuf+len, HOP_EVT_DOORS_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_hop_get_name_list_doors(int llid, int tid)
{
  int len;
  len = sprintf(sndbuf, HOP_GET_LIST_NAME, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_hop_name_list_doors(int llid, int tid, int nb, t_hop_list *list)
{
  int i, len;
  len = sprintf(sndbuf, HOP_LIST_NAME_O, tid, nb);
  for (i=0; i<nb; i++)
    {
    if ((list[i].name == NULL) ||
        (strlen(list[i].name) == 0) ||
        (strlen(list[i].name) >= MAX_NAME_LEN))
      KOUT(" ");
    len += sprintf(sndbuf+len, HOP_LIST_NAME_I, list[i].type_hop,
                                                list[i].name, list[i].num);
    }
  len += sprintf(sndbuf+len, HOP_LIST_NAME_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_hop_list *helper_rx_hop_name_list(char *msg, int nb)
{
  int i;
  char *ptr = msg;
  t_hop_list *list = (t_hop_list *) clownix_malloc(nb * sizeof(t_hop_list), 7);
  memset(list, 0, nb * sizeof(t_hop_list));
  for (i=0; i<nb; i++)
    {
    ptr = strstr(ptr, "<hop_type_item>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, HOP_LIST_NAME_I, &(list[i].type_hop),
                                     list[i].name, &(list[i].num))!= 3)
      KOUT("%s", ptr);
    ptr = strstr(ptr, "</hop_type_item>");
    if (!ptr)
      KOUT("%s", msg);
    }
  ptr = strstr(ptr, "<hop_type_item>");
  if (ptr)
    KOUT("%s", msg);
  return list;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_stats_endp_sub(int llid, int tid, char *name, int num, int sub)
{
  int len;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  len = sprintf(sndbuf, SUB_EVT_STATS_ENDP, tid, name, num, sub);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_stats_endp(int llid, int tid, char *network, 
                         char *name, int num, 
                         t_stats_counts *sc, int status)
{
  int len;
  if (!sc)
    KOUT(" ");
  if (!network)
    KOUT(" ");
  if (strlen(network) < 1)
    KOUT(" ");
  if (strlen(network) >= MAX_NAME_LEN)
    network[MAX_NAME_LEN-1] = 0;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  if ((sc->nb_items < 0) || (sc->nb_items > MAX_STATS_ITEMS)) 
    KOUT("%d ", sc->nb_items);
  len = sprintf(sndbuf, EVT_STATS_ENDP_O, tid, network, name, num, status, 
                                         sc->nb_items);
  len += fill_stats(sndbuf+len, sc->nb_items, sc->item);
  len += sprintf(sndbuf+len, EVT_STATS_ENDP_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_stats_sysinfo_sub(int llid, int tid, char *name, int sub)
{
  int len;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  len = sprintf(sndbuf, SUB_EVT_STATS_SYSINFO, tid, name, sub);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_stats_sysinfo(int llid, int tid, char *network, char *name,
                            t_stats_sysinfo *si, char *df, int status)
{
  int len;
  if (!si)
    KOUT(" ");
  if (!network)
    KOUT(" ");
  if (strlen(network) < 1)
    KOUT(" ");
  if (strlen(network) >= MAX_NAME_LEN)
    network[MAX_NAME_LEN-1] = 0;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  if (df)
    {
    if (strlen(df) >= MAX_RPC_MSG_LEN)
      df[MAX_RPC_MSG_LEN-1] = 0;
    }
  len = sprintf(sndbuf, EVT_STATS_SYSINFOO, tid, network, name, status,
                                       si->time_ms,       si->uptime,
                                       si->load1,         si->load5,
                                       si->load15,        si->totalram,     
                                       si->freeram,       si->cachedram,
                                       si->sharedram,     si->bufferram,
                                       si->totalswap,     si->freeswap,
                                       si->procs,         si->totalhigh,
                                       si->freehigh,      si->mem_unit,
                                       si->process_utime, si->process_stime,    
                                       si->process_cutime,si->process_cstime,
                                       si->process_rss);
  if (df && (strlen(df) > 0))
    len += sprintf(sndbuf+len, "<bound_for_df_dumprd>%s</bound_for_df_dumprd>", df);
  else
    len += sprintf(sndbuf+len, "<bound_for_df_dumprd></bound_for_df_dumprd>");
  len += sprintf(sndbuf+len, EVT_STATS_SYSINFOC);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_mucli_dialog_req(int llid, int tid, char *name, int eth, char *line)
{
  int len;
  if ((!name) || (strlen(name)==0) || (strlen(name) >= MAX_NAME_LEN))
    KOUT(" ");
  if ((!line) || (strlen(line)==0) || (strlen(line) >= MAX_RPC_MSG_LEN))
    KOUT(" ");
  len = sprintf(sndbuf, MUCLI_DIALOG_REQ_O, tid, name, eth);
  len += sprintf(sndbuf+len, MUCLI_DIALOG_REQ_I, line);
  len += sprintf(sndbuf+len, MUCLI_DIALOG_REQ_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_mucli_dialog_resp(int llid, int tid, char *name, int eth, 
                            char *line, int status)
{
  int len;
  if ((!name) || (strlen(name)==0) || (strlen(name) >= MAX_NAME_LEN))
    KOUT(" ");
  if ((!line) || (strlen(line)==0) || (strlen(line) >= MAX_RPC_MSG_LEN))
    KOUT(" ");
  len = sprintf(sndbuf, MUCLI_DIALOG_RESP_O, tid, name, eth, status);
  len += sprintf(sndbuf+len, MUCLI_DIALOG_RESP_I, line);
  len += sprintf(sndbuf+len, MUCLI_DIALOG_RESP_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void send_work_dir_req(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, WORK_DIR_REQ, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_work_dir_resp(int llid, int tid, t_topo_clc *icf)
{
  t_topo_clc cf;
  int len = 0;
  topo_config_check_str(icf, __LINE__);
  topo_config_swapon(&cf, icf);
  len = sprintf(sndbuf, WORK_DIR_RESP, tid, 
                                       cf.version,
                                       cf.network,
                                       cf.username,
                                       cf.server_port,
                                       cf.work_dir,
                                       cf.bulk_dir,
                                       cf.bin_dir,
                                       cf.flags_config);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_topo_sub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, EVENT_TOPO_SUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_topo_unsub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, EVENT_TOPO_UNSUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_topo_small_event_sub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, TOPO_SMALL_EVENT_SUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_topo_small_event_unsub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, TOPO_SMALL_EVENT_UNSUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_topo_small_event(int llid, int tid, char *name, 
                           char *param1, char *param2, int vm_evt)
{
  int len = 0;
  char parm1[MAX_PATH_LEN];
  char parm2[MAX_PATH_LEN];
  if (name[0] == 0)
    KOUT(" "); 
  memset(parm1, 0, MAX_PATH_LEN);
  memset(parm2, 0, MAX_PATH_LEN);
  if ((!param1) || (param1[0] == 0))
    strncpy(parm1, "undefined_param1", MAX_PATH_LEN-1);
  else
    strncpy(parm1, param1, MAX_PATH_LEN-1);
  if ((!param2) || (param2[0] == 0))
    strncpy(parm2, "undefined_param2", MAX_PATH_LEN-1);
  else
    strncpy(parm2, param2, MAX_PATH_LEN-1);
  len = sprintf(sndbuf, TOPO_SMALL_EVENT, tid, name, parm1, parm2, vm_evt);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int topo_eth_format(char *buf, char mac[MAC_ADDR_LEN])
{
  int len = 0;
  len += sprintf(buf+len, ADD_VM_ETH_PARAMS, (mac[0]) & 0xFF,
                                             (mac[1]) & 0xFF,
                                             (mac[2]) & 0xFF,
                                             (mac[3]) & 0xFF,
                                             (mac[4]) & 0xFF,
                                             (mac[5]) & 0xFF);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int topo_kvm_format(char *buf, t_topo_kvm *ikvm)
{
  t_topo_kvm kvm;
  int i, len;

  topo_kvm_check_str(ikvm, __LINE__);
  topo_kvm_swapon(&kvm, ikvm); 

  len = sprintf(buf, EVENT_TOPO_KVM_O, kvm.name, 
                                       kvm.install_cdrom,  
                                       kvm.added_cdrom,  
                                       kvm.added_disk,  
                                       kvm.p9_host_share,  
                                       kvm.linux_kernel, 
                                       kvm.rootfs_used,  
                                       kvm.rootfs_backing,  
                                       kvm.vm_id, 
                                       kvm.vm_config_flags,  
                                       kvm.nb_eth,
                                       kvm.mem, 
                                       kvm.cpu); 
  for (i=0; i<kvm.nb_eth; i++)
    len += topo_eth_format(buf+len, kvm.eth_params[i].mac_addr);
  len += sprintf(buf+len, EVENT_TOPO_KVM_C);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int topo_c2c_format(char *buf, t_topo_c2c *c2c)
{
  int len;
  char master[MAX_NAME_LEN];
  char slave[MAX_NAME_LEN];
  if ((!c2c->name) || (!c2c->master_cloonix) || (!c2c->slave_cloonix))
    KOUT("%p %p %p", c2c->name, c2c->master_cloonix, c2c->slave_cloonix);
  if (!strlen(c2c->name))
     KOUT(" ");
  memset(master, 0, MAX_NAME_LEN);
  memset(slave, 0, MAX_NAME_LEN);
  strncpy(master, c2c->master_cloonix, MAX_NAME_LEN-1);
  strncpy(slave, c2c->slave_cloonix, MAX_NAME_LEN-1);
  if (strlen(master) == 0)
    strcpy(master, "undefined_xname");
  if (strlen(slave) == 0)
    strcpy(slave, "undefined_xname");

  len = sprintf(buf, EVENT_TOPO_C2C, c2c->name,
                                     master, slave,
                                     c2c->local_is_master,
                                     c2c->is_peered,
                                     c2c->ip_slave,
                                     c2c->port_slave);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int topo_snf_format(char *buf, t_topo_snf *snf)
{ 
  int len;
  if ((!snf->name) || (!snf->recpath))
    KOUT("%p %p", snf->name, snf->recpath);
  if ((!strlen(snf->name)) || (!strlen(snf->recpath)))
    KOUT("%d %d", (int)strlen(snf->name), (int)strlen(snf->recpath));

  len = sprintf(buf, EVENT_TOPO_SNF, snf->name,
                                     snf->recpath,
                                     snf->capture_on);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int topo_sat_format(char *buf, t_topo_sat *sat)
{
  int len;
  if (!sat->name)
    KOUT(" ");
  if (!strlen(sat->name))
    KOUT(" ");
  len = sprintf(buf, EVENT_TOPO_SAT, sat->name, sat->type);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int topo_endp_format(char *buf, t_topo_endp *endp)
{
  int i, len;
  if (!endp->name)
    KOUT(" ");
  if (!strlen(endp->name))
    KOUT(" ");
  len = sprintf(buf, EVENT_TOPO_ENDP_O, endp->name,
                                        endp->num,
                                        endp->type,
                                        endp->lan.nb_lan);
  for (i=0; i<endp->lan.nb_lan; i++)
    {
    if (!endp->lan.lan[i].lan)
      KOUT(" ");
    if (!strlen(endp->lan.lan[i].lan))
      KOUT(" ");
    len += sprintf(buf+len, EVENT_TOPO_LAN, endp->lan.lan[i].lan);
    }
  len += sprintf(buf+len, EVENT_TOPO_ENDP_C);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_topo(int llid, int tid, t_topo_info *topo)
{
  int i, len = 0;
  t_topo_clc cf;
  topo_config_check_str(&(topo->clc), __LINE__);
  topo_config_swapon(&cf, &(topo->clc));
  len = sprintf(sndbuf, EVENT_TOPO_O, tid,
                                      cf.version,
                                      cf.network,
                                      cf.username,
                                      cf.server_port,
                                      cf.work_dir,
                                      cf.bulk_dir,
                                      cf.bin_dir,
                                      cf.flags_config,
                                      topo->nb_kvm,
                                      topo->nb_c2c,
                                      topo->nb_snf,
                                      topo->nb_sat,
                                      topo->nb_endp);

  for (i=0; i<topo->nb_kvm; i++)
    len += topo_kvm_format(sndbuf+len, &(topo->kvm[i]));
  for (i=0; i<topo->nb_c2c; i++)
    len += topo_c2c_format(sndbuf+len, &(topo->c2c[i]));
  for (i=0; i<topo->nb_snf; i++)
    len += topo_snf_format(sndbuf+len, &(topo->snf[i]));
  for (i=0; i<topo->nb_sat; i++)
    len += topo_sat_format(sndbuf+len, &(topo->sat[i]));
  for (i=0; i<topo->nb_endp; i++)
    len += topo_endp_format(sndbuf+len, &(topo->endp[i]));

  len += sprintf(sndbuf+len, EVENT_TOPO_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_print_sub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, EVENT_PRINT_SUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_print_unsub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, EVENT_PRINT_UNSUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_print(int llid, int tid, char *info)
{
  int len = 0;
  char *buf = string_to_xml(info);
  len = sprintf(sndbuf, EVENT_PRINT, tid, buf);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_sys_sub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, EVENT_SYS_SUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_sys_unsub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, EVENT_SYS_UNSUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_sys(int llid, int tid, t_sys_info *sys)
{
  int i, len, nb  = sys->nb_queue_tx;
  t_queue_tx *Qtx = sys->queue_tx;
  len = sprintf(sndbuf, EVENT_SYS_O, tid, MAX_MALLOC_TYPES);

  for (i=0; i<MAX_MALLOC_TYPES; i++)
    len += sprintf(sndbuf+len, EVENT_SYS_M, sys->mallocs[i]);

  len += sprintf(sndbuf+len, EVENT_SYS_FN, type_llid_max);
  for (i=0; i<type_llid_max; i++)
    len += sprintf(sndbuf+len, EVENT_SYS_FU, sys->fds_used[i]);

  len += sprintf(sndbuf+len, EVENT_SYS_R, sys->selects,
             sys->cur_channels,
             sys->max_channels, sys->cur_channels_recv,
             sys->cur_channels_send,  
             sys->clients, 
             sys->max_time, sys->avg_time, 
             sys->above50ms, sys->above20ms, sys->above15ms,
             sys->nb_queue_tx);

  for (i=0; i<nb; i++)
    {
    len += sprintf(sndbuf+len, EVENT_SYS_ITEM_Q,  Qtx[i].peak_size, 
                   Qtx[i].size, Qtx[i].llid, Qtx[i].fd, 
                   Qtx[i].waked_count_in, Qtx[i].waked_count_out, 
                   Qtx[i].waked_count_err,
                   Qtx[i].out_bytes, Qtx[i].in_bytes, Qtx[i].name,
                   Qtx[i].id, Qtx[i].type); 
    }
  len += sprintf(sndbuf+len, EVENT_SYS_C); 
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/
                                                                        
/*****************************************************************************/
void send_status_ok(int llid, int tid, char *txt)
{
  int len = 0;
  char *buf = string_to_xml(txt);
  len = sprintf(sndbuf, STATUS_OK, tid, buf);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_status_ko(int llid, int tid, char *reason)
{
  int len = 0;
  char *buf = string_to_xml(reason);
  len = sprintf(sndbuf, STATUS_KO, tid, buf);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void get_one_eth_param(char *buf, char mac[MAC_ADDR_LEN])
{
  int i;
  char *ptr;
  int var[6];
  ptr = strstr(buf, "<eth_params>");
  if (!ptr)
    KOUT("%s\n", buf);
  if (sscanf(ptr, ADD_VM_ETH_PARAMS, &(var[0]), &(var[1]), &(var[2]),
                                     &(var[3]), &(var[4]), &(var[5])) != 6) 
      KOUT("%s\n", buf);
  for (i=0; i<6; i++)
    mac[i] = var[i] & 0xFF;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static void get_eth_params(char *buf, int nb, t_eth_params *eth_params)
{ 
  int i;
  char *ptr = buf;
  for (i=0; i < nb; i++)
    {
    ptr = strstr(ptr, "<eth_params>");
    if (!ptr)
      KOUT("%s\n%d\n", buf, nb);
    get_one_eth_param(ptr, eth_params[i].mac_addr); 
    ptr = strstr(ptr, "</eth_params>");
    if (!ptr)
      KOUT("%s\n%d\n", buf, nb);
    }
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static int make_eth_params(char *buf, int nb, t_eth_params *eth_params)
{
  int i, len = 0;
  char *mac;
  for (i=0; i<nb; i++)
    {
    mac = eth_params[i].mac_addr;
    len += sprintf(buf+len, ADD_VM_ETH_PARAMS, (mac[0]) & 0xFF,
                                               (mac[1]) & 0xFF,
                                               (mac[2]) & 0xFF,
                                               (mac[3]) & 0xFF,
                                               (mac[4]) & 0xFF,
                                               (mac[5]) & 0xFF);
    }
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_add_vm(int llid, int tid, t_topo_kvm *ikvm) 
{
  int len = 0;
  t_topo_kvm kvm;

  topo_kvm_check_str(ikvm, __LINE__);
  topo_kvm_swapon(&kvm, ikvm); 

  len = sprintf(sndbuf, ADD_VM_O, tid, kvm.name, 
                kvm.vm_config_flags, kvm.cpu,  
                kvm.mem, kvm.nb_eth);

  len += make_eth_params(sndbuf+len, kvm.nb_eth, kvm.eth_params);

  len += sprintf(sndbuf+len, ADD_VM_C, kvm.linux_kernel, 
                             kvm.rootfs_input, 
                             kvm.install_cdrom, kvm.added_cdrom,
                             kvm.added_disk, kvm.p9_host_share);

  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_sav_vm(int llid, int tid, char *name, int type, char *sav_rootfs_path)
{
  int len = 0;
  if (name[0] == 0)
    KOUT(" ");
  if (sav_rootfs_path[0] == 0)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    KOUT(" ");
  if (strlen(sav_rootfs_path) >= MAX_PATH_LEN)
    KOUT(" ");
  len = sprintf(sndbuf, SAV_VM, tid, name, type, sav_rootfs_path);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_sav_vm_all(int llid, int tid, int type, char *sav_rootfs_path)
{
  int len = 0;
  if (sav_rootfs_path[0] == 0)
    KOUT(" ");
  if (strlen(sav_rootfs_path) >= MAX_PATH_LEN)
    KOUT(" ");
  len = sprintf(sndbuf, SAV_VM_ALL, tid, type, sav_rootfs_path);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_add_sat(int llid, int tid, char *name, int type, t_c2c_req_info *c2c)
{
  int len = 0;
  if (name[0] == 0)
    KOUT(" "); 
  if (strlen(name) >= MAX_NAME_LEN)
    KOUT(" ");
  if (type == endp_type_c2c)
    {
    if (!c2c)
      KOUT(" ");
    if (strlen(c2c->cloonix_slave) >= MAX_NAME_LEN)
      KOUT(" ");
    if (strlen(c2c->cloonix_slave) == 0) 
      KOUT(" ");
    len = sprintf(sndbuf, ADD_SAT_C2C, tid, name, c2c->cloonix_slave,
                                       c2c->ip_slave, c2c->port_slave, 
                                       c2c->passwd_slave);
    }
  else
    len = sprintf(sndbuf, ADD_SAT_NON_C2C, tid, name, type);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_del_sat(int llid, int tid, char *name)
{
  int len = 0;
  if (name[0] == 0)
    KOUT(" "); 
  if (strlen(name) >= MAX_NAME_LEN)
    KOUT(" ");
  len = sprintf(sndbuf, DEL_SAT, tid, name);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_add_lan_endp(int llid, int tid, char *name, int num, char *lan)
{
  int len = 0;
  if (name[0] == 0)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    KOUT(" ");
  if (lan[0] == 0)
    KOUT(" ");
  if (strlen(lan) >= MAX_NAME_LEN)
    KOUT(" ");
  len = sprintf(sndbuf, ADD_LAN_ENDP, tid, name, num, lan);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_del_lan_endp(int llid, int tid, char *name, int num, char *lan)
{
  int len = 0;
  if (name[0] == 0)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    KOUT(" ");
  if (lan[0] == 0)
    KOUT(" ");
  if (strlen(lan) >= MAX_NAME_LEN)
    KOUT(" ");
  len = sprintf(sndbuf, DEL_LAN_ENDP, tid, name, num, lan);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_kill_uml_clownix(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, KILL_UML_CLOWNIX, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_del_all(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, DEL_ALL, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_list_pid_req(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, LIST_PID, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_list_pid_resp(int llid, int tid, int qty,  t_pid_lst *pid_lst)
{
  int i, len = 0;
  len = sprintf(sndbuf, LIST_PID_O, tid, qty);
  for (i=0; i<qty; i++)
    {
    if (strlen(pid_lst[i].name) == 0)
      KOUT(" ");
    len += sprintf(sndbuf+len, LIST_PID_ITEM, pid_lst[i].name, pid_lst[i].pid);
    }
  len += sprintf(sndbuf+len, LIST_PID_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_blkd_reports_sub(int llid, int tid, int sub)
{
  int len;
  len = sprintf(sndbuf, BLKD_REPORTS_SUB, tid, sub);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_blkd_reports(int llid, int tid, t_blkd_reports *blkd)
{
  int i, len = 0;
  t_blkd_item *it;
  if (!blkd)
    KOUT(" ");
  if ((blkd->nb_blkd_reports < 1) || (blkd->nb_blkd_reports >= 1000))
    KOUT("%d", blkd->nb_blkd_reports);
  len = sprintf(sndbuf, BLKD_REPORTS_O, tid, blkd->nb_blkd_reports);
  for (i=0; i<blkd->nb_blkd_reports; i++)
    {
    it = &(blkd->blkd_item[i]);
    if (strlen(it->sock) == 0)
      KOUT(" ");
    if (strlen(it->sock) >= MAX_PATH_LEN)
      KOUT("%s %d", it->sock, (int)strlen(it->sock));
    if (strlen(it->rank_name) == 0)
      KOUT(" ");
    if (strlen(it->rank_name) >= MAX_NAME_LEN)
      KOUT("%s %d", it->rank_name, (int)strlen(it->rank_name));

    len += sprintf(sndbuf+len, BLKD_ITEM, it->sock, it->rank_name, 
                                          it->rank_num, it->rank_tidx,
                                          it->rank, it->pid, it->llid, it->fd,
                                          it->sel_tx, it->sel_rx,
                                          it->fifo_tx, it->fifo_rx,
                                          it->queue_tx, it->queue_rx,
                                          it->bandwidth_tx, it->bandwidth_rx,
                                          it->stop_tx, it->stop_rx,
                                          it->dist_flow_ctrl_tx, 
                                          it->dist_flow_ctrl_rx,
                                          it->drop_tx, it->drop_rx);
    }
  len += sprintf(sndbuf+len, BLKD_REPORTS_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_list_commands_req(int llid, int tid)
{ 
  int len = 0;
  len = sprintf(sndbuf, LIST_COMMANDS, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_list_commands_resp(int llid, int tid, int qty, t_list_commands *list)
{
  int i, len = 0;
  len = sprintf(sndbuf, LIST_COMMANDS_O, tid, qty);
  for (i=0; i<qty; i++)
    {
    if (strlen(list[i].cmd) == 0)
      KOUT(" ");
    if (strlen(list[i].cmd) >= MAX_LIST_COMMANDS_LEN)
      KOUT("%d", (int) strlen(list[i].cmd));
    len += sprintf(sndbuf+len, LIST_COMMANDS_ITEM, list[i].cmd);
    } 
  len += sprintf(sndbuf+len, LIST_COMMANDS_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_vmcmd(int llid, int tid, char *name, int vmcmd, int param)
{
  int len = 0;
  if ((!name) || (strlen(name)==0) || (strlen(name) >= MAX_NAME_LEN))
    KOUT(" ");
  len = sprintf(sndbuf, VMCMD, tid, name, vmcmd, param);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_list_pid_resp(char *msg, int qty, t_pid_lst **lst)
{
  int i;
  char *ptr = msg;
  if (qty)
    {
    *lst = (t_pid_lst *)clownix_malloc(qty * sizeof(t_pid_lst), 5);
    memset ((*lst), 0, qty * sizeof(t_pid_lst));
    }
  else
    *lst = NULL;
  ptr = msg;
  for (i=0; i<qty; i++)
    {
    if (!ptr)
      KOUT(" ");
    ptr = strstr(ptr, "<pid>");
    if (!ptr)
      KOUT("\n\n%s\n\n%s\n\n", msg, ptr);
    if (sscanf(ptr, LIST_PID_ITEM, ((*lst)[i].name), &((*lst)[i].pid)) != 2)
      KOUT(" ");
    ptr = strstr(ptr, "</pid>");
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_list_commands_resp(char *msg, int qty, t_list_commands **list)
{
  int i, len;
  char *ptre, *ptrs = msg;
  if (qty)
    {
    *list = (t_list_commands *)clownix_malloc(qty * sizeof(t_list_commands), 5);
    memset ((*list), 0, qty * sizeof(t_list_commands));
    }
  else
    *list = NULL;
  ptrs = msg;
  for (i=0; i<qty; i++)
    {
    if (!ptrs)
      KOUT(" ");
    ptrs = strstr(ptrs, "<item_list_command_delimiter>");
    if (!ptrs)
      KOUT("%s", msg);
    ptrs += strlen("<item_list_command_delimiter>");
    ptre = strstr(ptrs, "</item_list_command_delimiter>");
    if (!ptre)
      KOUT("%s", msg);
    len = ptre - ptrs;
    if (len >= MAX_LIST_COMMANDS_LEN) 
      KOUT("%d", len);
    memcpy((*list)[i].cmd, ptrs, len);
    (*list)[i].cmd[len] = 0;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_event_sys(char *msg, t_sys_info *sys, int *tid)
{
  int i, nb_malloc_types, nb_fds_types, len;
  char *ptr = msg;
  t_queue_tx *Qtx;
  memset (sys, 0, sizeof(t_sys_info));
  if (sscanf(msg, EVENT_SYS_O, tid, &nb_malloc_types) != 2)
    KOUT("%s", msg);
  if (nb_malloc_types != MAX_MALLOC_TYPES)
    KOUT(" ");
  for (i=0; i<MAX_MALLOC_TYPES; i++)
    {
    ptr = strstr(ptr, "<m>");
    if (!ptr)
      KOUT(" ");
    if (sscanf(ptr, EVENT_SYS_M, &(sys->mallocs[i])) != 1)
      KOUT(" ");
    ptr = strstr(ptr, "</m>");
    if (!ptr)
      KOUT(" ");
    }
  ptr = strstr(ptr, "<m>");
  if (ptr)
    KOUT(" ");
  ptr = strstr(msg, "<nb_fds_used>"); 
  if (sscanf(ptr, EVENT_SYS_FN, &nb_fds_types) != 1)
    KOUT(" ");
  if (nb_fds_types != type_llid_max)
    KOUT(" ");
  for (i=0; i<type_llid_max; i++)
    {
    ptr = strstr(ptr, "<fd>");
    if (!ptr)
      KOUT(" ");
    if (sscanf(ptr, EVENT_SYS_FU, &(sys->fds_used[i])) != 1)
      KOUT(" ");
    ptr = strstr(ptr, "</fd>");
    if (!ptr)
      KOUT(" ");
    }
  ptr = strstr(ptr, "<fd>");
  if (ptr)
    KOUT(" ");
  ptr = strstr(msg, "<r>");
  if (!ptr)
    KOUT(" ");
  if (sscanf(ptr, EVENT_SYS_R, &(sys->selects),  
       &(sys->cur_channels), &(sys->max_channels), &(sys->cur_channels_recv),
       &(sys->cur_channels_send),  &(sys->clients), &(sys->max_time), 
       &(sys->avg_time), &(sys->above50ms), &(sys->above20ms), 
       &(sys->above15ms), &(sys->nb_queue_tx)) != 12)
        KOUT("%s ", ptr);
  ptr = strstr(ptr, "</r>");
  if (sys->nb_queue_tx)
    {
    len = sys->nb_queue_tx * sizeof(t_queue_tx);
    Qtx=(t_queue_tx *)clownix_malloc(len, 6); 
    memset(Qtx, 0, sys->nb_queue_tx * sizeof(t_queue_tx));
    for (i=0; i<sys->nb_queue_tx; i++)
      {
      ptr = strstr(ptr, "<Qtx>");
      if (!ptr)
        KOUT(" ");
      if (sscanf(ptr, EVENT_SYS_ITEM_Q, &(Qtx[i].peak_size), &(Qtx[i].size), 
                 &(Qtx[i].llid), &(Qtx[i].fd), 
                 &(Qtx[i].waked_count_in), &(Qtx[i].waked_count_out),
                 &(Qtx[i].waked_count_err),
                 &(Qtx[i].out_bytes), &(Qtx[i].in_bytes), Qtx[i].name,
                 &(Qtx[i].id), &(Qtx[i].type)) != 12) 
        KOUT("%s", ptr);
      ptr = strstr(ptr, "</Qtx>");
      if (!ptr)
        KOUT(" ");
      }
    sys->queue_tx = Qtx;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_topo_kvm(char *msg, t_topo_kvm *kvm)
{
  t_topo_kvm ikvm;
  memset(&ikvm, 0, sizeof(t_topo_kvm));
  if (sscanf(msg, EVENT_TOPO_KVM_O, ikvm.name, 
                                    ikvm.install_cdrom,  
                                    ikvm.added_cdrom,  
                                    ikvm.added_disk,  
                                    ikvm.p9_host_share,  
                                    ikvm.linux_kernel,  
                                    ikvm.rootfs_used,  
                                    ikvm.rootfs_backing,  
                                    &(ikvm.vm_id), 
                                    &(ikvm.vm_config_flags),  
                                    &(ikvm.nb_eth),
                                    &(ikvm.mem), 
                                    &(ikvm.cpu)) != 13)
    KOUT("%s", msg);
  get_eth_params(msg, ikvm.nb_eth, ikvm.eth_params);
  topo_kvm_swapoff(kvm, &ikvm); 
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_topo_c2c(char *msg, t_topo_c2c *c2c)
{
  if (sscanf(msg, EVENT_TOPO_C2C, c2c->name,
                                  c2c->master_cloonix,
                                  c2c->slave_cloonix,
                                  &(c2c->local_is_master),
                                  &(c2c->is_peered),
                                  &(c2c->ip_slave),
                                  &(c2c->port_slave)) != 7) 
    KOUT("%s", msg);
  if (!strcmp(c2c->master_cloonix, "undefined_xname"))
    memset(c2c->master_cloonix, 0, MAX_NAME_LEN);
  if (!strcmp(c2c->slave_cloonix, "undefined_xname"))
    memset(c2c->slave_cloonix, 0, MAX_NAME_LEN);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_topo_snf(char *msg, t_topo_snf *snf)
{
  if (sscanf(msg, EVENT_TOPO_SNF, snf->name,
                                  snf->recpath,
                                  &(snf->capture_on)) != 3)
    KOUT("%s", msg);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_topo_sat(char *msg, t_topo_sat *sat)
{
  if (sscanf(msg, EVENT_TOPO_SAT, sat->name,
                                  &(sat->type)) != 2)
    KOUT("%s", msg);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_topo_lan(char *msg, t_lan_group *vlg)
{
  int i, len; 
  char *ptr = msg;
  len = vlg->nb_lan * sizeof(t_lan_group_item);
  vlg->lan = (t_lan_group_item *) clownix_malloc(len, 9);
  memset(vlg->lan, 0, len);
  for (i=0; i<vlg->nb_lan; i++)
    {
    ptr = strstr(ptr, "<lan>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, EVENT_TOPO_LAN, vlg->lan[i].lan) != 1)
      KOUT(" ");
    ptr = strstr(ptr, "</lan>");
    if (!ptr)
      KOUT("%s", msg);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_topo_endp(char *msg, t_topo_endp *endp)
{
  if (sscanf(msg, EVENT_TOPO_ENDP_O, endp->name,
                                     &(endp->num),
                                     &(endp->type),
                                     &(endp->lan.nb_lan)) != 4)
    KOUT("%s", msg);
  helper_fill_topo_lan(msg, &(endp->lan));
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_topo_info *helper_event_topo (char *msg, int *tid)
{
  int i;
  char *ptr = msg;
  t_topo_clc icf;
  t_topo_info *topo;
  topo = (t_topo_info *)clownix_malloc(sizeof(t_topo_info), 22);
  memset(topo, 0, sizeof(t_topo_info));
  memset(&icf, 0, sizeof(t_topo_clc));
  if (sscanf(msg, EVENT_TOPO_O, tid, icf.version,
                                     icf.network,
                                     icf.username,
                                     &(icf.server_port),
                                     icf.work_dir,
                                     icf.bulk_dir,
                                     icf.bin_dir,
                                     &(icf.flags_config),
                                     &(topo->nb_kvm),
                                     &(topo->nb_c2c),
                                     &(topo->nb_snf),
                                     &(topo->nb_sat),
                                     &(topo->nb_endp)) != 14)
    KOUT("%s", msg);
  topo_config_swapoff(&(topo->clc), &icf);
  topo->kvm= (t_topo_kvm *) clownix_malloc(topo->nb_kvm*sizeof(t_topo_kvm),16);
  memset(topo->kvm, 0, topo->nb_kvm*sizeof(t_topo_kvm));
  topo->c2c= (t_topo_c2c *) clownix_malloc(topo->nb_c2c*sizeof(t_topo_c2c),16);
  memset(topo->c2c, 0, topo->nb_c2c*sizeof(t_topo_c2c));
  topo->snf= (t_topo_snf *) clownix_malloc(topo->nb_snf*sizeof(t_topo_snf),16);
  memset(topo->snf, 0, topo->nb_snf*sizeof(t_topo_snf));
  topo->sat= (t_topo_sat *) clownix_malloc(topo->nb_sat*sizeof(t_topo_sat),16);
  memset(topo->sat, 0, topo->nb_sat*sizeof(t_topo_sat));
  topo->endp= (t_topo_endp *) clownix_malloc(topo->nb_endp*sizeof(t_topo_endp),16);
  memset(topo->endp, 0, topo->nb_endp*sizeof(t_topo_endp));

  for (i=0; i<topo->nb_kvm; i++)
    {
    ptr = strstr(ptr, "<kvm>");
    if (!ptr)
      KOUT("%d,%d\n%s\n", topo->nb_kvm, i, msg);
    helper_fill_topo_kvm(ptr, &(topo->kvm[i]));
    ptr = strstr(ptr, "</kvm>");
    if (!ptr)
      KOUT(" ");
    }
  for (i=0; i<topo->nb_c2c; i++)
    {
    ptr = strstr(ptr, "<c2c>");
    if (!ptr)
      KOUT("%d,%d\n%s\n", topo->nb_c2c, i, msg);
    helper_fill_topo_c2c(ptr, &(topo->c2c[i]));
    ptr = strstr(ptr, "</c2c>");
    if (!ptr)
      KOUT(" ");
    }
  for (i=0; i<topo->nb_snf; i++)
    {
    ptr = strstr(ptr, "<snf>");
    if (!ptr)
      KOUT("%d,%d\n%s\n", topo->nb_snf, i, msg);
    helper_fill_topo_snf(ptr, &(topo->snf[i]));
    ptr = strstr(ptr, "</snf>");
    if (!ptr)
      KOUT(" ");
    }
  for (i=0; i<topo->nb_sat; i++)
    {
    ptr = strstr(ptr, "<sat>");
    if (!ptr)
      KOUT("%d,%d\n%s\n", topo->nb_sat, i, msg);
    helper_fill_topo_sat(ptr, &(topo->sat[i]));
    ptr = strstr(ptr, "</sat>");
    if (!ptr)
      KOUT(" ");
    }
  for (i=0; i<topo->nb_endp; i++)
    {
    ptr = strstr(ptr, "<endp>");
    if (!ptr)
      KOUT("%d,%d\n%s\n", topo->nb_endp, i, msg);
    helper_fill_topo_endp(ptr, &(topo->endp[i]));
    ptr = strstr(ptr, "</endp>");
    if (!ptr)
      KOUT(" ");
    }

  return topo;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_eventfull_sub(int llid, int tid)
{
  int len = 0;
  len = sprintf(sndbuf, EVENTFULL_SUB, tid);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_eventfull(int llid, int tid, int nb_endp, t_eventfull_endp *endp)
{
  int i, len = 0;
  len += sprintf(sndbuf+len, EVENTFULL_O, tid, nb_endp);
  for (i=0; i<nb_endp; i++)
    len += sprintf(sndbuf+len, EVENTFULL_ENDP, endp[i].name, endp[i].num,
                                               endp[i].type, endp[i].ram,
                                               endp[i].cpu, endp[i].ok,
                                               endp[i].ptx, endp[i].prx,
                                               endp[i].btx, endp[i].brx,
                                               endp[i].ms);
  len += sprintf(sndbuf+len, EVENTFULL_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_eventfull_endp(char *msg, int nb, t_eventfull_endp *endp)
{
  char *ptr = msg;
  int i;
  for (i=0; i<nb; i++)
    {
    ptr = strstr (ptr, "<eventfull_endp>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, EVENTFULL_ENDP,  endp[i].name,
                                     &(endp[i].num),
                                     &(endp[i].type),
                                     &(endp[i].ram),
                                     &(endp[i].cpu),
                                     &(endp[i].ok),
                                     &(endp[i].ptx),
                                     &(endp[i].prx),
                                     &(endp[i].btx),
                                     &(endp[i].brx),
                                     &(endp[i].ms)) != 11)
      KOUT("%s", msg);
    ptr = strstr (ptr, "</eventfull_endp>");
    if (!ptr)
      KOUT("%s", msg);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_blkd_reports(char *msg, t_blkd_reports *blkd)
{
  char *ptr = msg;
  t_blkd_item *it;
  int i;
  for (i=0; i<blkd->nb_blkd_reports; i++)
    {
    it = &(blkd->blkd_item[i]);
    ptr = strstr(ptr, "<blkd_item>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, BLKD_ITEM,      it->sock, 
                                    it->rank_name, 
                                    &(it->rank_num),
                                    &(it->rank_tidx),
                                    &(it->rank),
                                    &(it->pid),
                                    &(it->llid),
                                    &(it->fd),
                                    &(it->sel_tx),
                                    &(it->sel_rx),
                                    &(it->fifo_tx),
                                    &(it->fifo_rx),
                                    &(it->queue_tx),
                                    &(it->queue_rx),
                                    &(it->bandwidth_tx),
                                    &(it->bandwidth_rx),
                                    &(it->stop_tx),
                                    &(it->stop_rx),
                                    &(it->dist_flow_ctrl_tx),
                                    &(it->dist_flow_ctrl_rx),
                                    &(it->drop_tx),
                                    &(it->drop_rx))
                                    != 22)
      KOUT("%s", msg);
    ptr = strstr(ptr, "</blkd_item>");
    if (!ptr)
      KOUT("%s", msg);
    } 
  ptr = strstr (ptr, "<blkd_item>");
  if (ptr)
    KOUT("%d\n%s", blkd->nb_blkd_reports, msg);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_qmp_sub(int llid, int tid, char *name)
{
  int len = 0;
  if (!name)
    {
    len = sprintf(sndbuf, QMP_ALL_SUB, tid);
    }
  else
    {
    if ((strlen(name)==0) || (strlen(name) >= MAX_NAME_LEN))
      KOUT(" ");
    len = sprintf(sndbuf, QMP_SUB, tid, name);
    }
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_qmp_req(int llid, int tid, char *name, char *line)
{
  int len = 0;
  if ((!name) || (strlen(name)==0) || (strlen(name) >= MAX_NAME_LEN))
    KOUT(" ");
  if ((!line) || (strlen(line)==0) || (strlen(line) >= MAX_RPC_MSG_LEN))
    KOUT(" ");
  len = sprintf(sndbuf, QMP_REQ_O, tid, name);
  len += sprintf(sndbuf+len, QMP_LINE, line);
  len += sprintf(sndbuf+len, QMP_REQ_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_qmp_resp(int llid, int tid, char *name, char *line, int status)
{
  int len = 0;
  if ((!name) || (strlen(name)==0) || (strlen(name) >= MAX_NAME_LEN))
    KOUT(" ");
  if ((!line) || (strlen(line)==0) || (strlen(line) >= MAX_RPC_MSG_LEN))
    KOUT(" ");
  len = sprintf(sndbuf, QMP_MSG_O, tid, name, status);
  len += sprintf(sndbuf+len, QMP_LINE, line);
  len += sprintf(sndbuf+len, QMP_MSG_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static char *extract_rpc_msg(char *msg, char *bound)
{
  int len;
  char *ptrs, *ptre, *line = NULL;
  char searchbound[MAX_CLOWNIX_BOUND_LEN];
  memset(searchbound, 0, MAX_CLOWNIX_BOUND_LEN); 
  snprintf(searchbound, MAX_CLOWNIX_BOUND_LEN-1, "<%s>", bound);
  ptrs = strstr(msg, searchbound);
  if (!ptrs)
    KOUT("%s", msg);
  ptrs += strlen(searchbound);
  memset(searchbound, 0, MAX_CLOWNIX_BOUND_LEN); 
  snprintf(searchbound, MAX_CLOWNIX_BOUND_LEN-1, "</%s>", bound);
  ptre = strstr(msg, searchbound);
  len = (int) (ptre - ptrs);
  if (ptrs && ptre && (len>0))
    {
    if (len >= MAX_RPC_MSG_LEN)
      len = MAX_RPC_MSG_LEN-1;
    line = (char *) clownix_malloc(MAX_RPC_MSG_LEN, 10);
    memcpy(line, ptrs, len);
    line[len] = 0;
    }
  return line;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void dispatcher(int llid, int bnd_evt, char *msg)
{
  int len, nb_endp, flags_hop, num;
  int vmcmd, param, status, sub;
  int mutype, type, eth, qty, tid; 
  t_topo_clc  icf;
  t_topo_clc  cf;
  t_eventfull_endp *eventfull_endp;
  char *parm1, *parm2;
  t_topo_kvm ikvm;
  t_topo_kvm kvm;
  char network[MAX_NAME_LEN];
  char name[MAX_NAME_LEN];
  char path[MAX_PATH_LEN];
  char param1[MAX_PATH_LEN];
  char param2[MAX_PATH_LEN];
  char lan[MAX_NAME_LEN];
  char info[MAX_PRINT_LEN];
  char *ptr, *line;
  t_pid_lst *pid_lst;
  t_sys_info *sys;
  t_topo_info *topo;
  t_list_commands *list_commands;
  t_stats_counts stats_counts;
  t_stats_sysinfo stats_sysinfo;
  t_c2c_req_info c2c;
  t_blkd_reports blkd;
  t_hop_list *list;

  switch(bnd_evt)
    {

    case bnd_hop_evt_doors_sub:
      if (sscanf(msg, HOP_EVT_DOORS_SUB_O, &tid, &flags_hop, &qty) != 3)
        KOUT("%s", msg);
      list = helper_rx_hop_name_list(msg, qty);
      recv_hop_evt_doors_sub(llid, tid, flags_hop, qty, list);
      clownix_free(list, __FUNCTION__);
      break;

    case bnd_hop_evt_doors_unsub:
      if (sscanf(msg, HOP_EVT_DOORS_UNSUB, &tid) != 1)
        KOUT("%s", msg);
      recv_hop_evt_doors_unsub(llid, tid);
      break;


    case bnd_hop_evt_doors:
      if (sscanf(msg, HOP_EVT_DOORS_O, &tid, &flags_hop, name) != 3)
        KOUT("%s", msg);
      line = extract_rpc_msg(msg, "hop_free_txt_joker");
      recv_hop_evt_doors(llid, tid, flags_hop, name, line);
      clownix_free(line, __FUNCTION__);
      break;

   case bnd_hop_get_list:
      if (sscanf(msg, HOP_GET_LIST_NAME, &tid) != 1)
        KOUT("%s", msg);
      recv_hop_get_name_list_doors(llid, tid);
      break;

    case bnd_hop_list:
      if (sscanf(msg, HOP_LIST_NAME_O, &tid, &qty) != 2)
        KOUT("%s", msg);
      list = helper_rx_hop_name_list(msg, qty);
      recv_hop_name_list_doors(llid, tid, qty, list);
      clownix_free(list, __FUNCTION__);
      break;

    case bnd_sub_evt_stats_endp:
      if (sscanf(msg, SUB_EVT_STATS_ENDP, &tid, name, &num, &sub) != 4)
        KOUT("%s", msg);
      recv_evt_stats_endp_sub(llid, tid, name, num, sub);
      break;

    case bnd_evt_stats_endp:
      if (sscanf(msg, EVT_STATS_ENDP_O, &tid, network, name, &num,
                                        &status, &(stats_counts.nb_items)) != 6) 
        KOUT("%s", msg);
      helper_stats(msg, stats_counts.nb_items, stats_counts.item);
      recv_evt_stats_endp(llid, tid, network, name, num, &stats_counts,status);
      break;

    case bnd_sub_evt_stats_sysinfo:
      if (sscanf(msg, SUB_EVT_STATS_SYSINFO, &tid, name, &sub) != 3)
        KOUT("%s", msg);
      recv_evt_stats_sysinfo_sub(llid, tid, name, sub);
      break;

    case bnd_evt_stats_sysinfo:
      if (sscanf(msg, EVT_STATS_SYSINFOO, &tid, network, name,
             &status, &(stats_sysinfo.time_ms), &(stats_sysinfo.uptime),
             &(stats_sysinfo.load1), &(stats_sysinfo.load5),
             &(stats_sysinfo.load15), &(stats_sysinfo.totalram), 
             &(stats_sysinfo.freeram), &(stats_sysinfo.cachedram),
             &(stats_sysinfo.sharedram), &(stats_sysinfo.bufferram),
             &(stats_sysinfo.totalswap), &(stats_sysinfo.freeswap),
             &(stats_sysinfo.procs), &(stats_sysinfo.totalhigh),
             &(stats_sysinfo.freehigh), &(stats_sysinfo.mem_unit),
             &(stats_sysinfo.process_utime), &(stats_sysinfo.process_stime),          
             &(stats_sysinfo.process_cutime), &(stats_sysinfo.process_cstime),
             &(stats_sysinfo.process_rss)) != 25)
        KOUT("%s", msg);
      line = extract_rpc_msg(msg, "bound_for_df_dumprd");
      recv_evt_stats_sysinfo(llid, tid, network, name,
                             &stats_sysinfo, line, status);
      clownix_free(line, __FUNCTION__);
      break;

    case bnd_mucli_dialog_req:
      if (sscanf(msg, MUCLI_DIALOG_REQ_O, &tid, name, &eth) != 3)
        KOUT("%s", msg);
      line = extract_rpc_msg(msg, "mucli_dialog_req_bound");
      recv_mucli_dialog_req(llid, tid, name, eth, line);
      clownix_free(line, __FUNCTION__);
      break;

    case bnd_mucli_dialog_resp:
      if (sscanf(msg, MUCLI_DIALOG_RESP_O, &tid, name, &eth, 
                                           &status) != 4)
        KOUT("%s", msg);
      line = extract_rpc_msg(msg, "mucli_dialog_resp_bound");
      recv_mucli_dialog_resp(llid, tid, name, eth, line, status);
      clownix_free(line, __FUNCTION__);
      break;

    case bnd_event_sys_sub:
      if (sscanf(msg, EVENT_SYS_SUB, &tid) != 1)
        KOUT("%s", msg);
      recv_event_sys_sub(llid, tid);
      break;
    case bnd_event_sys_unsub:
      if (sscanf(msg, EVENT_SYS_UNSUB, &tid) != 1)
        KOUT("%s", msg);
      recv_event_sys_unsub(llid, tid);
      break;
    case bnd_event_sys:
      sys = (t_sys_info *) clownix_malloc(sizeof(t_sys_info), 21);
      helper_event_sys(msg, sys, &tid);
      recv_event_sys(llid, tid, sys);
      sys_info_free(sys);
      break;

    case bnd_blkd_reports_sub:
      if (sscanf(msg, BLKD_REPORTS_SUB, &tid, &sub) != 2)
        KOUT("%s", msg);
      recv_blkd_reports_sub(llid, tid, sub);
      break;

    case bnd_blkd_reports:
      if (sscanf(msg, BLKD_REPORTS_O, &tid, &(blkd.nb_blkd_reports)) != 2)
        KOUT("%s", msg);
      if ((blkd.nb_blkd_reports > 1000) || (blkd.nb_blkd_reports < 1))
        KOUT("%s %d", msg, blkd.nb_blkd_reports);
      len = blkd.nb_blkd_reports * sizeof(t_blkd_item);
      blkd.blkd_item = (t_blkd_item *) clownix_malloc(len, 21);
      memset(blkd.blkd_item, 0, len);
      helper_fill_blkd_reports(msg, &blkd);
      recv_blkd_reports(llid, tid, &blkd);
      clownix_free(blkd.blkd_item, __FUNCTION__);
      break;

    case bnd_event_topo_sub:
      if (sscanf(msg, EVENT_TOPO_SUB, &tid) != 1)
        KOUT("%s", msg);
      recv_event_topo_sub(llid, tid);
      break;
    case bnd_event_topo_unsub:
      if (sscanf(msg, EVENT_TOPO_UNSUB, &tid) != 1)
        KOUT("%s", msg);
      recv_event_topo_unsub(llid, tid);
      break;
    case bnd_event_topo:
      topo = helper_event_topo(msg, &tid);
      recv_event_topo(llid, tid, topo);
      topo_free_topo(topo);
      break;

    case bnd_topo_small_event_sub:
      if (sscanf(msg, TOPO_SMALL_EVENT_SUB, &tid) != 1)
        KOUT("%s", msg);
      recv_topo_small_event_sub(llid, tid);
      break;
    case bnd_topo_small_event_unsub:
      if (sscanf(msg, TOPO_SMALL_EVENT_UNSUB, &tid) != 1)
        KOUT("%s", msg);
      recv_topo_small_event_unsub(llid, tid);
      break;
    case bnd_topo_small_event:
      if (sscanf(msg, TOPO_SMALL_EVENT, &tid, name, 
                 param1, param2, &type) != 5)
        KOUT("%s", msg);
      if (!strcmp(param1, "undefined_param1"))
        parm1 = NULL;
      else
        parm1 = param1; 
      if (!strcmp(param2, "undefined_param2"))
        parm2 = NULL;
      else
        parm2 = param2;
      recv_topo_small_event(llid, tid, name, parm1, parm2, type);
      break;

    case bnd_evt_print_sub:
      if (sscanf(msg, EVENT_PRINT_SUB, &tid) != 1)
        KOUT("%s", msg);
      recv_evt_print_sub(llid, tid);
      break;
    case bnd_evt_print_unsub:
      if (sscanf(msg, EVENT_PRINT_UNSUB, &tid) != 1)
        KOUT("%s", msg);
      recv_evt_print_unsub(llid, tid);
      break;
    case bnd_event_print:
      if (sscanf(msg, EVENT_PRINT, &tid, info) != 2)
        KOUT("%s", msg);
      recv_evt_print(llid, tid, xml_to_string(info));
      break;

    case bnd_status_ok:
      if (sscanf(msg, STATUS_OK, &tid, info) != 2)
        KOUT("%s", msg);
      recv_status_ok(llid, tid, xml_to_string(info));
      break;
    case bnd_status_ko:
      if (sscanf(msg, STATUS_KO, &tid, info) != 2)
        KOUT("%s", msg);
      recv_status_ko(llid, tid, xml_to_string(info));
      break;

    case bnd_add_vm:
      memset(&ikvm, 0, sizeof(t_topo_kvm));
      if (sscanf(msg, ADD_VM_O, &tid, ikvm.name, 
                 &(ikvm.vm_config_flags),
                 &(ikvm.cpu), &(ikvm.mem), 
                 &(ikvm.nb_eth)) != 6)
        KOUT("%s", msg);
      get_eth_params(msg, ikvm.nb_eth, ikvm.eth_params);
      ptr = strstr(msg, "<linux_kernel>");
      if (!ptr)
        KOUT("%s", msg);
      if (sscanf(ptr, ADD_VM_C, ikvm.linux_kernel, 
                                ikvm.rootfs_input, 
                                ikvm.install_cdrom, 
                                ikvm.added_cdrom, 
                                ikvm.added_disk, 
                                ikvm.p9_host_share) != 6) 
        KOUT("%s", msg);
      topo_kvm_swapoff(&kvm, &ikvm); 
      recv_add_vm(llid, tid, &kvm);
      break;
    case bnd_sav_vm:
      if (sscanf(msg, SAV_VM, &tid, name, &type, path) != 4)
        KOUT("%s", msg);
      recv_sav_vm(llid, tid, name, type, path);
      break;

    case bnd_sav_vm_all:
      if (sscanf(msg, SAV_VM_ALL, &tid, &type, path) != 3)
        KOUT("%s", msg);
      recv_sav_vm_all(llid, tid, type, path);
      break;


    case bnd_add_sat_c2c:
      memset(&(c2c), 0, sizeof(t_c2c_req_info));
      if (sscanf(msg, ADD_SAT_C2C, &tid, name, 
                                   c2c.cloonix_slave,
                                   &(c2c.ip_slave),
                                   &(c2c.port_slave),
                                   c2c.passwd_slave) != 6)
        KOUT("%s", msg);
      if (!strcmp(c2c.cloonix_slave, NO_DEFINED_VALUE))
        memset(c2c.cloonix_slave, 0, MAX_NAME_LEN);
      mutype = endp_type_c2c;
      recv_add_sat(llid, tid, name, mutype, &c2c);
      break;

    case bnd_add_sat_non_c2c:
      if (sscanf(msg, ADD_SAT_NON_C2C, &tid, name, &mutype) != 3)
        KOUT("%s", msg);
      recv_add_sat(llid, tid, name, mutype, NULL);
      break;

    case bnd_del_sat:
      if (sscanf(msg, DEL_SAT, &tid, name) != 2)
        KOUT("%s", msg);
      recv_del_sat(llid, tid, name);
      break;

    case bnd_add_lan_endp:
      if (sscanf(msg, ADD_LAN_ENDP, &tid, name, &num, lan) != 4)
        KOUT("%s", msg);
      recv_add_lan_endp(llid, tid, name, num, lan);
      break;

    case bnd_del_lan_endp:
      if (sscanf(msg, DEL_LAN_ENDP, &tid, name,  &num, lan) != 4)
        KOUT("%s", msg);
      recv_del_lan_endp(llid, tid, name, num, lan);
      break;

    case bnd_kill_uml_clownix:
      if (sscanf(msg, KILL_UML_CLOWNIX, &tid) != 1)
        KOUT("%s", msg);
      recv_kill_uml_clownix(llid, tid);
      break;
    case bnd_del_all:
      if (sscanf(msg, DEL_ALL, &tid) != 1)
        KOUT("%s", msg);
      recv_del_all(llid, tid);
      break;
    case bnd_list_pid_req:
      if (sscanf(msg, LIST_PID, &tid) != 1)
        KOUT("%s", msg);
      recv_list_pid_req(llid, tid);
      break;
    case bnd_list_pid_resp:
      if (sscanf(msg, LIST_PID_O, &tid, &qty) != 2)
        KOUT("%s", msg);
      helper_list_pid_resp(msg, qty, &pid_lst);
      recv_list_pid_resp(llid, tid, qty, pid_lst);
      if (qty)
        clownix_free(pid_lst, __FUNCTION__);
      break;

    case bnd_list_commands_req:
      if (sscanf(msg, LIST_COMMANDS, &tid) != 1)
        KOUT("%s", msg);
      recv_list_commands_req(llid, tid);
      break;

    case bnd_list_commands_resp:
      if (sscanf(msg, LIST_COMMANDS_O, &tid, &qty) != 2)
        KOUT("%s", msg);
      helper_list_commands_resp(msg, qty, &list_commands);
      recv_list_commands_resp(llid, tid, qty, list_commands);
      if (qty)
        clownix_free(list_commands, __FUNCTION__);
      break;

    case bnd_work_dir_req:
      if (sscanf(msg, WORK_DIR_REQ, &tid) != 1)
        KOUT("%s", msg);
      recv_work_dir_req(llid, tid);
      break;
    case bnd_work_dir_resp:
      memset(&icf, 0, sizeof(t_topo_clc));
      if (sscanf(msg, WORK_DIR_RESP, &tid, 
                                     icf.version,
                                     icf.network,
                                     icf.username,
                                     &(icf.server_port),
                                     icf.work_dir,
                                     icf.bulk_dir,
                                     icf.bin_dir,
                                     &(icf.flags_config)) != 9)
        KOUT("%s", msg);
      topo_config_swapoff(&cf, &icf);
      recv_work_dir_resp(llid, tid, &cf);
      break;

    case bnd_vmcmd:
      if (sscanf(msg, VMCMD, &tid, name, &vmcmd, &param) != 4)
        KOUT("%s", msg);
      recv_vmcmd(llid, tid, name, vmcmd, param);
      break;


    case bnd_eventfull_sub:
      if (sscanf(msg, EVENTFULL_SUB, &tid) != 1)
        KOUT("%s", msg);
      recv_eventfull_sub(llid, tid);
      break;

    case bnd_eventfull:
      if (sscanf(msg, EVENTFULL_O, &tid, &nb_endp) != 2)
        KOUT("%s", msg);
      len = nb_endp * sizeof(t_eventfull_endp);
      eventfull_endp = (t_eventfull_endp *)clownix_malloc(len, 23); 
      memset(eventfull_endp, 0, len);
      helper_eventfull_endp(msg, nb_endp, eventfull_endp);
      recv_eventfull(llid, tid, nb_endp, eventfull_endp); 
      clownix_free(eventfull_endp, __FUNCTION__);
      break;

    case bnd_qmp_all_sub:
      if (sscanf(msg, QMP_ALL_SUB, &tid) != 1)
        KOUT("%s", msg);
      recv_qmp_sub(llid, tid, NULL);
      break;

    case bnd_qmp_sub:
      if (sscanf(msg, QMP_SUB, &tid, name) != 2)
        KOUT("%s", msg);
      recv_qmp_sub(llid, tid, name);
      break;

    case bnd_qmp_req:
      if (sscanf(msg, QMP_REQ_O, &tid, name) != 2)
        KOUT("%s", msg);
      line = extract_rpc_msg(msg, "msgqmp_req_boundyzzy");
      recv_qmp_req(llid, tid, name, line);
      break;

    case bnd_qmp_msg:
      if (sscanf(msg, QMP_MSG_O, &tid, name, &status) != 3)
        KOUT("%s", msg);
      line = extract_rpc_msg(msg, "msgqmp_req_boundyzzy");
      recv_qmp_resp(llid, tid, name, line, status);
      break;

    default:
      KOUT("%s", msg);
    }
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
char *llid_trace_lib(int type)
{
  char *result;
  switch(type)
    {
    case type_llid_trace_client_unix:
      result = "client";
      break;
    case type_llid_trace_listen_client_unix:
      result = "listen client server";
      break;
    case type_llid_trace_clone:
      result = " ";
      break;
    case type_llid_trace_listen_clone:
      result = "clone process server";
      break;
    case type_llid_trace_mulan:
      result = "mulan";
      break;
    case type_llid_trace_endp_kvm:
      result = "mueth";
      break;
    case type_llid_trace_endp_tap:
      result = "mutap";
      break;
    case type_llid_trace_endp_snf:
      result = "musnf";
      break;
    case type_llid_trace_endp_c2c:
      result = "muc2c";
      break;
    case type_llid_trace_endp_a2b:
      result = "mua2b";
      break;
    case type_llid_trace_endp_wif:
      result = "muwif";
      break;
    case type_llid_trace_jfs:
      result = "jfs";
      break;
    case type_llid_trace_unix_qmonitor:
      result = "unix qemu monitor";
      break;
    case type_llid_trace_doorways:
      result = "doorways";
      break;
    default:
      KOUT("Error llid type %d", type);
      break;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *prop_flags_ascii_get(int prop_flags)
{
  static char resp[500];
  memset(resp, 0, 500);
  if (prop_flags & VM_CONFIG_FLAG_PERSISTENT)
    strcat(resp, "persistent_write_rootfs ");
  else if (prop_flags & VM_CONFIG_FLAG_EVANESCENT)
    strcat(resp, "evanescent_write_rootfs ");
  else
    KOUT("%X", prop_flags);
  return resp;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int doors_io_basic_decoder (int llid, int len, char *chunk)
{
  int result = -1;
  int bnd_event;
  char bound[MAX_CLOWNIX_BOUND_LEN];
  if ((size_t) len != strlen(chunk) + 1)
    KOUT(" %d %d %s\n", len, (int)strlen(chunk), chunk);
  extract_boundary(chunk, bound);
  bnd_event = get_bnd_event(bound);
  if (bnd_event)
    {
    dispatcher(llid, bnd_event, chunk);
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void doors_io_basic_xml_init(t_llid_tx llid_tx)
{
  g_llid_tx = llid_tx;
  if (!g_llid_tx)
    KOUT(" ");
  sndbuf = get_bigbuf();
  memset (bound_list, 0, bnd_max * MAX_CLOWNIX_BOUND_LEN);
  extract_boundary (STATUS_OK,      bound_list[bnd_status_ok]);
  extract_boundary (STATUS_KO,      bound_list[bnd_status_ko]);
  extract_boundary (ADD_VM_O,       bound_list[bnd_add_vm]);
  extract_boundary (SAV_VM,         bound_list[bnd_sav_vm]);
  extract_boundary (SAV_VM_ALL,     bound_list[bnd_sav_vm_all]);
  extract_boundary (ADD_SAT_C2C,     bound_list[bnd_add_sat_c2c]);
  extract_boundary (ADD_SAT_NON_C2C, bound_list[bnd_add_sat_non_c2c]);
  extract_boundary (DEL_SAT,     bound_list[bnd_del_sat]);
  extract_boundary (ADD_LAN_ENDP, bound_list[bnd_add_lan_endp]);
  extract_boundary (DEL_LAN_ENDP, bound_list[bnd_del_lan_endp]);
  extract_boundary (KILL_UML_CLOWNIX,bound_list[bnd_kill_uml_clownix]);
  extract_boundary (DEL_ALL,        bound_list[bnd_del_all]);
  extract_boundary (LIST_PID,       bound_list[bnd_list_pid_req]);
  extract_boundary (LIST_PID_O,     bound_list[bnd_list_pid_resp]);
  extract_boundary (LIST_COMMANDS,   bound_list[bnd_list_commands_req]);
  extract_boundary (LIST_COMMANDS_O, bound_list[bnd_list_commands_resp]);
  extract_boundary (TOPO_SMALL_EVENT_SUB, bound_list[bnd_topo_small_event_sub]);
  extract_boundary (TOPO_SMALL_EVENT_UNSUB, bound_list[bnd_topo_small_event_unsub]);
  extract_boundary (TOPO_SMALL_EVENT,   bound_list[bnd_topo_small_event]);
  extract_boundary (EVENT_TOPO_SUB, bound_list[bnd_event_topo_sub]);
  extract_boundary (EVENT_TOPO_UNSUB, bound_list[bnd_event_topo_unsub]);
  extract_boundary (EVENT_TOPO_O,   bound_list[bnd_event_topo]);
  extract_boundary (EVENT_PRINT_SUB,bound_list[bnd_evt_print_sub]);
  extract_boundary (EVENT_PRINT_UNSUB,bound_list[bnd_evt_print_unsub]);
  extract_boundary (EVENT_PRINT,    bound_list[bnd_event_print]);
  extract_boundary (EVENT_SYS_SUB, bound_list[bnd_event_sys_sub]);
  extract_boundary (EVENT_SYS_UNSUB, bound_list[bnd_event_sys_unsub]);
  extract_boundary (EVENT_SYS_O, bound_list[bnd_event_sys]);
  extract_boundary (WORK_DIR_REQ,  bound_list[bnd_work_dir_req]);
  extract_boundary (WORK_DIR_RESP, bound_list[bnd_work_dir_resp]);
  extract_boundary (VMCMD, bound_list[bnd_vmcmd]);
  extract_boundary (EVENTFULL_SUB, bound_list[bnd_eventfull_sub]);
  extract_boundary (EVENTFULL_O, bound_list[bnd_eventfull]);
  extract_boundary (MUCLI_DIALOG_REQ_O, bound_list[bnd_mucli_dialog_req]);
  extract_boundary (MUCLI_DIALOG_RESP_O, bound_list[bnd_mucli_dialog_resp]);
  extract_boundary (SUB_EVT_STATS_ENDP, bound_list[bnd_sub_evt_stats_endp]);
  extract_boundary (EVT_STATS_ENDP_O, bound_list[bnd_evt_stats_endp]);
  extract_boundary (SUB_EVT_STATS_SYSINFO, bound_list[bnd_sub_evt_stats_sysinfo]);
  extract_boundary (EVT_STATS_SYSINFOO, bound_list[bnd_evt_stats_sysinfo]);
  extract_boundary (BLKD_REPORTS_O, bound_list[bnd_blkd_reports]);
  extract_boundary (BLKD_REPORTS_SUB, bound_list[bnd_blkd_reports_sub]);

  extract_boundary (HOP_GET_LIST_NAME, bound_list[bnd_hop_get_list]);
  extract_boundary (HOP_LIST_NAME_O, bound_list[bnd_hop_list]);
  extract_boundary (HOP_EVT_DOORS_SUB_O, bound_list[bnd_hop_evt_doors_sub]);
  extract_boundary (HOP_EVT_DOORS_UNSUB, bound_list[bnd_hop_evt_doors_unsub]);
  extract_boundary (HOP_EVT_DOORS_O,   bound_list[bnd_hop_evt_doors]);

  extract_boundary (QMP_ALL_SUB, bound_list[bnd_qmp_all_sub]);
  extract_boundary (QMP_SUB, bound_list[bnd_qmp_sub]);
  extract_boundary (QMP_REQ_O, bound_list[bnd_qmp_req]);
  extract_boundary (QMP_MSG_O, bound_list[bnd_qmp_msg]);
}
/*---------------------------------------------------------------------------*/





