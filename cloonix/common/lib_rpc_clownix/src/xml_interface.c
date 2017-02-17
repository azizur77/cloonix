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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "io_clownix.h"
#include "lib_commons.h"
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
  bnd_add_sat,
  bnd_del_sat,
  bnd_add_lan_sat,
  bnd_del_lan_sat,
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
  bnd_intf_list_req,
  bnd_intf_list_resp,
  bnd_event_spy_sub,
  bnd_event_spy_unsub,
  bnd_event_spy,
  bnd_work_dir_req,
  bnd_work_dir_resp,
  bnd_vmcmd,
  bnd_eventfull_sub,
  bnd_eventfull,
  bnd_mucli_dialog_req,
  bnd_mucli_dialog_resp,
  bnd_sub_evt_stats_eth,
  bnd_evt_stats_eth,
  bnd_sub_evt_stats_sat,
  bnd_evt_stats_sat,
  bnd_sub_evt_stats_sysinfo,
  bnd_evt_stats_sysinfo,
  bnd_blkd_reports,
  bnd_blkd_reports_sub,
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
void send_evt_stats_eth_sub(int llid, int tid, char *name, int eth, int sub)
{
  int len;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  len = sprintf(sndbuf, SUB_EVT_STATS_ETH, tid, name, eth, sub);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int fill_tx_stats(char *buf, int nb, t_stats_count_item *item)
{
  int i, len = 0;
  for (i=0; i<nb; i++)
    {  
    len += sprintf(buf+len, EVT_STATS_TX_ITEM, item[i].time_ms,
                                            item[i].pkts, item[i].bytes);
    }
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int fill_rx_stats(char *buf, int nb, t_stats_count_item *item)
{
  int i, len = 0;
  for (i=0; i<nb; i++)
    {
    len += sprintf(buf+len, EVT_STATS_RX_ITEM, item[i].time_ms,
                                            item[i].pkts, item[i].bytes);
    }
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_tx_stats(char *msg, int nb, t_stats_count_item *item)
{
  char *ptr;
  int i;
  memset(item, 0, MAX_STATS_ITEMS*sizeof(t_stats_count_item));
  if ((nb < 0) || (nb > MAX_STATS_ITEMS))
    KOUT("%d", nb);
  ptr = msg;
  for (i=0; i<nb; i++)
    {
    ptr = strstr(ptr, "<tx_item>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, EVT_STATS_TX_ITEM, &(item[i].time_ms), 
                                       &(item[i].pkts), 
                                       &(item[i].bytes)) != 3)
      KOUT("%s", msg);
    ptr = strstr(ptr, "</tx_item>");
    if (!ptr)
      KOUT("%s", msg);
    }
  ptr = strstr(ptr, "<tx_item>");
  if (ptr)
    KOUT("%s", msg);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_rx_stats(char *msg, int nb, t_stats_count_item *item)
{
  char *ptr;
  int i;
  memset(item, 0, MAX_STATS_ITEMS*sizeof(t_stats_count_item));
  if ((nb < 0) || (nb > MAX_STATS_ITEMS))
    KOUT("%d", nb);
  ptr = msg;
  for (i=0; i<nb; i++)
    {
    ptr = strstr(ptr, "<rx_item>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, EVT_STATS_RX_ITEM, &(item[i].time_ms),  
                                       &(item[i].pkts),  
                                       &(item[i].bytes)) != 3)
      KOUT("%s", msg);
    ptr = strstr(ptr, "</rx_item>");
    if (!ptr)
      KOUT("%s", msg);
    }
  ptr = strstr(ptr, "<rx_item>");
  if (ptr)
    KOUT("%s", msg);
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
                                                list[i].name, list[i].eth);
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
                                                list[i].name, list[i].eth);
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
                                     list[i].name, &(list[i].eth))!= 3)
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
static char *get_hop_free_txt(char *msg)
{
  int len;
  char *ptrs, *ptre, *txt;
  ptrs = strstr(msg, "<hop_free_txt_joker>");
  if (!ptrs)
    KOUT("%s", msg);
  ptrs += strlen("<hop_free_txt_joker>");
  ptre = strstr(ptrs, "</hop_free_txt_joker>");
  if (!ptre)
    KOUT("%s", msg);
  len = ptre - ptrs;
  txt = (char *) clownix_malloc(len+1, 10);
  memcpy(txt, ptrs, len);
  txt[len] = 0;
  return txt;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void send_evt_stats_eth(int llid, int tid, char *network_name,
                        char *name, int eth, 
                        t_stats_counts *sc, int status) 
{
  int len;
  if (!sc)
    KOUT(" ");
  if (!network_name)
    KOUT(" ");
  if (strlen(network_name) < 1)
    KOUT(" ");
  if (strlen(network_name) >= MAX_NAME_LEN)
    network_name[MAX_NAME_LEN-1] = 0;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  if ((sc->nb_tx_items < 0) || (sc->nb_tx_items > MAX_STATS_ITEMS) ||
      (sc->nb_rx_items < 0) || (sc->nb_rx_items > MAX_STATS_ITEMS))
    KOUT("%d %d", sc->nb_tx_items, sc->nb_rx_items);
  len = sprintf(sndbuf, EVT_STATS_ETH_O, tid, network_name, name, eth, status, 
                                         sc->nb_tx_items, sc->nb_rx_items); 
  len += fill_tx_stats(sndbuf+len, sc->nb_tx_items, sc->tx_item); 
  len += fill_rx_stats(sndbuf+len, sc->nb_rx_items, sc->rx_item); 
  len += sprintf(sndbuf+len, EVT_STATS_ETH_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_stats_sat_sub(int llid, int tid, char *name, int sub)
{
  int len;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  len = sprintf(sndbuf, SUB_EVT_STATS_SAT, tid, name, sub);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_evt_stats_sat(int llid, int tid, char *network_name, char *name, 
                        t_stats_counts *sc, int status)
{
  int len;
  if (!sc)
    KOUT(" ");
  if (!network_name)
    KOUT(" ");
  if (strlen(network_name) < 1)
    KOUT(" ");
  if (strlen(network_name) >= MAX_NAME_LEN)
    network_name[MAX_NAME_LEN-1] = 0;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  if ((sc->nb_tx_items < 0) || (sc->nb_tx_items > MAX_STATS_ITEMS) ||
      (sc->nb_rx_items < 0) || (sc->nb_rx_items > MAX_STATS_ITEMS))
    KOUT("%d %d", sc->nb_tx_items, sc->nb_rx_items);
  len = sprintf(sndbuf, EVT_STATS_SAT_O, tid, network_name, name, status, 
                                         sc->nb_tx_items, sc->nb_rx_items);
  len += fill_tx_stats(sndbuf+len, sc->nb_tx_items, sc->tx_item);
  len += fill_rx_stats(sndbuf+len, sc->nb_rx_items, sc->rx_item);
  len += sprintf(sndbuf+len, EVT_STATS_SAT_C);
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
void send_evt_stats_sysinfo(int llid, int tid, char *network_name, char *name,
                            t_stats_sysinfo *si, char *df, int status)
{
  int len;
  if (!si)
    KOUT(" ");
  if (!network_name)
    KOUT(" ");
  if (strlen(network_name) < 1)
    KOUT(" ");
  if (strlen(network_name) >= MAX_NAME_LEN)
    network_name[MAX_NAME_LEN-1] = 0;
  if (!name)
    KOUT(" ");
  if (strlen(name) < 1)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
    name[MAX_NAME_LEN-1] = 0;
  if (df)
    {
    if (strlen(df) >= MAX_STATS_SYSDF)
      df[MAX_STATS_SYSDF-1] = 0;
    }
  len = sprintf(sndbuf, EVT_STATS_SYSINFOO, tid, network_name, name, status,
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
  if (!line)
    KOUT(" ");
  if (strlen(line) < 1)
    KOUT(" ");
  if (strlen(line) >= MAX_MUTXT_LEN)
    line[MAX_MUTXT_LEN-1] = 0;
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
  if (!line)
    KOUT(" ");
  if (strlen(line) < 1)
    KOUT(" ");
  if (strlen(line) >= MAX_MUTXT_LEN)
    line[MAX_MUTXT_LEN-1] = 0;
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
void send_work_dir_resp(int llid, int tid, t_cloonix_config *cloonix_config)
{
  int len = 0;
  len = sprintf(sndbuf, WORK_DIR_RESP, tid, 
                cloonix_config->version,
                cloonix_config->network_name,
                cloonix_config->username,
                cloonix_config->server_port,
                cloonix_config->work_dir,
                cloonix_config->bulk_dir,
                cloonix_config->bin_dir,
                cloonix_config->flags_config);
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
static int topo_lan_format(char *buf, int nb, t_lan_group_item *lan)
{
  int i, tmp, len = 0;
  for (i=0; i<nb; i++)
    {
    tmp = sprintf(buf+len, TOPO_LAN, lan[i].name);
    if (tmp <= 0)
      KOUT(" ");
    len += tmp;
    }
  return len;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static int make_one_eth_param(char *buf, char mac[MAC_ADDR_LEN], int promisc)
{
  int len = 0;
  len += sprintf(buf+len, ADD_VM_ETH_PARAMS, (mac[0]) & 0xFF,
                                             (mac[1]) & 0xFF,
                                             (mac[2]) & 0xFF,
                                             (mac[3]) & 0xFF,
                                             (mac[4]) & 0xFF,
                                             (mac[5]) & 0xFF,
                                             promisc);
  return len;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static int topo_vmit_format(char *buf, t_vm_item *vmit)
{
  int i, nb, len;

  if (vmit->vm_params.rootfs_used[0] == 0)
    strcpy(vmit->vm_params.rootfs_used, NO_DEFINED_VALUE);
  if (vmit->vm_params.rootfs_backing[0] == 0)
    strcpy(vmit->vm_params.rootfs_backing, NO_DEFINED_VALUE);

  len = sprintf(buf, TOPO_VM_O, vmit->vm_params.name, 
                                vmit->vm_params.install_cdrom,  
                                vmit->vm_params.added_cdrom,  
                                vmit->vm_params.added_disk,  
                                vmit->vm_params.p9_host_share,  
                                vmit->vm_params.linux_kernel, 
                                vmit->vm_params.rootfs_used,  
                                vmit->vm_params.rootfs_backing,  
                                vmit->vm_id, 
                                vmit->vm_params.vm_config_flags,  
                                vmit->vm_params.nb_eth,
                                vmit->vm_params.mem, vmit->vm_params.cpu); 
  for (i=0; i<vmit->vm_params.nb_eth; i++)
    {
    nb = vmit->lan_eth[i].nb_lan;
    len += sprintf(buf+len, TOPO_ETH_O, i, nb);
    len += make_one_eth_param(buf+len, vmit->vm_params.eth_params[i].mac_addr,
                                      vmit->vm_params.eth_params[i].is_promisc);
    len += topo_lan_format(buf+len, nb, vmit->lan_eth[i].lan); 
    len += sprintf(buf+len, TOPO_ETH_C);
    }
  len += sprintf(buf+len, TOPO_VM_C);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void fill_names(t_sat_item *sati, char *name, 
                       char *recpath, char *master, char *slave)
{
  memset(name, 0, MAX_NAME_LEN);
  if (!strlen(sati->name))
    strcpy(name, NO_DEFINED_VALUE);
  else
    strncpy(name, sati->name, MAX_NAME_LEN-1);

  memset(recpath, 0, MAX_PATH_LEN);
  if (!strlen(sati->snf_info.recpath))
    strcpy(recpath, NO_DEFINED_VALUE);
  else
    strncpy(recpath, sati->snf_info.recpath, MAX_PATH_LEN-1);

  memset(master, 0, MAX_NAME_LEN);
  if (!strlen(sati->c2c_info.master_cloonix))
    strcpy(master, NO_DEFINED_VALUE);
  else
    strncpy(master, sati->c2c_info.master_cloonix, MAX_NAME_LEN-1);

  memset(slave, 0, MAX_NAME_LEN);
  if (!strlen(sati->c2c_info.slave_cloonix))
    strcpy(slave, NO_DEFINED_VALUE);
  else
    strncpy(slave, sati->c2c_info.slave_cloonix, MAX_NAME_LEN-1);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int topo_sat_format(char *buf, t_sat_item *sati)
{
  int nb0, nb1, len;
  char name[MAX_NAME_LEN];
  char recpath[MAX_PATH_LEN];
  char master[MAX_NAME_LEN];
  char slave[MAX_NAME_LEN];

  nb0 = sati->lan0_sat.nb_lan;
  nb1 = sati->lan1_sat.nb_lan;
  fill_names(sati, name, recpath, master, slave);

  len = sprintf(buf, TOPO_SAT_O, name, sati->musat_type,
                                 recpath, 
                                 sati->snf_info.capture_on, 
                                 master, slave, 
                                 sati->c2c_info.local_is_master,
                                 sati->c2c_info.is_peered,
                                 sati->c2c_info.ip_slave,
                                 sati->c2c_info.port_slave,
                                 nb0, nb1);

  if (len <= 0)
    KOUT(" ");
  len += topo_lan_format(buf+len, nb0, sati->lan0_sat.lan);
  len += topo_lan_format(buf+len, nb1, sati->lan1_sat.lan);
  len += sprintf(buf+len, TOPO_SAT_C);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_topo(int llid, int tid, t_topo_info *topo)
{
  int i, len = 0;
  len = sprintf(sndbuf, EVENT_TOPO_O, tid,
                topo->cloonix_config.network_name,
                topo->cloonix_config.username,
                topo->cloonix_config.server_port,
                topo->cloonix_config.work_dir,
                topo->cloonix_config.bulk_dir,
                topo->cloonix_config.bin_dir,
                topo->nb_vm, topo->nb_sat);

  for (i=0; i<topo->nb_vm; i++)
    len += topo_vmit_format(sndbuf+len, &(topo->vmit[i]));
  for (i=0; i<topo->nb_sat; i++)
    len += topo_sat_format(sndbuf+len, &(topo->sati[i]));
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
static void replace_name(char *name1, char **rname1)
{
  static char name1_replace[MAX_NAME_LEN];
  memset(name1_replace, 0, MAX_NAME_LEN);
  *rname1 = name1_replace;
  if (name1)
    {
    if (strlen(name1) == 0)
      strcpy(name1_replace, NO_DEFINED_VALUE);
    else
      strncpy(name1_replace, name1, MAX_NAME_LEN);
    }
  else
    strcpy(name1_replace, NO_DEFINED_VALUE);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void send_event_spy_sub(int llid, int tid, char *iname, 
                        char *intf, char *dir)
{
  int len = 0;
  char *name;
  replace_name(iname, &name); 
  len = sprintf(sndbuf, EVENT_SPY_SUB, tid, name, intf, dir);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_spy_unsub(int llid, int tid, char *iname, 
                          char *intf, char *dir)
{
  int len = 0;
  char *name;
  replace_name(iname, &name); 
  len = sprintf(sndbuf, EVENT_SPY_UNSUB, tid, name, intf, dir);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_event_spy(int llid, int tid, char *iname, char *intf, char *dir, 
                    int secs, int usecs, int qty, char *msg)
{
  int i, len = 0;
  char *name;
  replace_name(iname, &name); 
  if (qty > MAX_BUF_SIZE)
    KOUT(" ");
  len = sprintf(sndbuf, EVENT_SPY_O, tid, name, intf, dir, secs, usecs, qty);
  for (i=0; i<qty; i++)
    len += sprintf(sndbuf+len, "%02X ", (msg[i] & 0xFF));
  len += sprintf(sndbuf+len, EVENT_SPY_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static char *helper_event_spy(char *msg, int qty)
{
  int i, val;
  char *ptr, *buf = NULL;
  if (qty > MAX_BUF_SIZE)
    KOUT(" ");
  if (qty != -1)
    {
    buf = clownix_malloc(qty * sizeof(char), 4);
    ptr = strstr(msg, "<msg>");
    if (!ptr)
      KOUT(" ");
    ptr += strlen("<msg>");
    for (i=0; i<qty; i++)
      {
      if (sscanf(ptr, "%02X ", &val) != 1)
        KOUT("%s", ptr);
      buf[i] = val & 0xFF;
      ptr += 3;
      }
    if (strncmp(ptr, "</msg>", strlen("</msg>")))
      KOUT("%s", ptr);
    }
  return buf;
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
static void get_one_eth_param(char *buf, char mac[MAC_ADDR_LEN], int *promisc)
{
  int i;
  char *ptr;
  int var[MAC_ADDR_LEN];
  ptr = strstr(buf, "<eth_params>");
  if (!ptr)
    KOUT("%s\n", buf);
  if (sscanf(ptr, ADD_VM_ETH_PARAMS, &(var[0]), &(var[1]), &(var[2]),
                                     &(var[3]), &(var[4]), &(var[5]), 
                                     promisc) != 7)
      KOUT("%s\n", buf);
  for (i=0; i<MAC_ADDR_LEN; i++)
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
    get_one_eth_param(ptr, eth_params[i].mac_addr, 
                           &(eth_params[i].is_promisc));
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
  for (i=0; i<nb; i++)
    len += make_one_eth_param(buf+len, eth_params[i].mac_addr, 
                                       eth_params[i].is_promisc);
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_add_vm(int llid, int tid, t_vm_params *vm_params) 
{
  int len = 0;
  char install_cdrom[MAX_PATH_LEN];
  char added_cdrom[MAX_PATH_LEN];
  char added_disk[MAX_PATH_LEN];
  char p9_host_share[MAX_PATH_LEN];
  char linux_kernel[MAX_NAME_LEN];
  memset(install_cdrom, 0, MAX_PATH_LEN);
  memset(added_cdrom, 0, MAX_PATH_LEN);
  memset(added_disk, 0, MAX_PATH_LEN);
  memset(p9_host_share, 0, MAX_PATH_LEN);
  memset(linux_kernel, 0, MAX_NAME_LEN);
  if ((vm_params->name[0] == 0) || (strlen(vm_params->name) >= MAX_NAME_LEN))
    KOUT(" ");
  if ((vm_params->rootfs_input[0] == 0) || 
      (strlen(vm_params->rootfs_input) >= MAX_PATH_LEN))
    KOUT(" ");
  if (strlen(vm_params->linux_kernel) >= MAX_NAME_LEN)
    KOUT(" ");
  if (strlen(vm_params->install_cdrom) >= MAX_PATH_LEN)
    KOUT(" ");
  if (strlen(vm_params->added_cdrom) >= MAX_PATH_LEN)
    KOUT(" ");
  if (strlen(vm_params->added_disk) >= MAX_PATH_LEN)
    KOUT(" ");
  if (strlen(vm_params->p9_host_share) >= MAX_PATH_LEN)
    KOUT(" ");

  if (vm_params->rootfs_used[0] != 0) 
    KOUT(" ");
  if (vm_params->rootfs_backing[0] != 0) 
    KOUT(" ");

  if (vm_params->linux_kernel[0] == 0) 
    strcpy(linux_kernel, NO_DEFINED_VALUE);
  else
    strcpy(linux_kernel, vm_params->linux_kernel);

  if (vm_params->install_cdrom[0] == 0)
    strcpy(install_cdrom, NO_DEFINED_VALUE);
  else
    strcpy(install_cdrom, vm_params->install_cdrom);

  if (vm_params->added_cdrom[0] == 0)
    strcpy(added_cdrom, NO_DEFINED_VALUE);
  else
    strcpy(added_cdrom, vm_params->added_cdrom);

  if (vm_params->added_disk[0] == 0)
    strcpy(added_disk, NO_DEFINED_VALUE);
  else
    strcpy(added_disk, vm_params->added_disk);

  if (vm_params->p9_host_share[0] == 0)
    strcpy(p9_host_share, NO_DEFINED_VALUE);
  else
    strcpy(p9_host_share, vm_params->p9_host_share);

  len = sprintf(sndbuf, ADD_VM_O, tid, vm_params->name, 
                vm_params->vm_config_flags, vm_params->cpu,  
                vm_params->mem, vm_params->nb_eth);
  len += make_eth_params(sndbuf+len,vm_params->nb_eth, vm_params->eth_params);
  len += sprintf(sndbuf+len, ADD_VM_C, linux_kernel, 
                             vm_params->rootfs_input, 
                             install_cdrom, added_cdrom,
                             added_disk, p9_host_share);
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
void send_add_sat(int llid, int tid, char *name, 
                  int mutype, t_c2c_req_info *c2c_req_info)
{
  int len = 0;
  t_c2c_req_info c2c_req_info_zero;
  t_c2c_req_info *c2c;
  char replace[MAX_NAME_LEN];
  memset(replace, 0, MAX_NAME_LEN);
  memset(&c2c_req_info_zero, 0, sizeof(t_c2c_req_info));
  if (name[0] == 0)
    KOUT(" "); 
  if (strlen(name) >= MAX_NAME_LEN)
    KOUT(" ");
  if (c2c_req_info)
    c2c = c2c_req_info;
  else
    c2c = &c2c_req_info_zero;
  if (strlen(c2c->cloonix_slave) >= MAX_NAME_LEN)
    KOUT(" ");
  if (strlen(c2c->cloonix_slave) == 0) 
    strcpy(replace, NO_DEFINED_VALUE);
  else
    strncpy(replace, c2c->cloonix_slave, MAX_NAME_LEN);
  len = sprintf(sndbuf, ADD_SAT, tid, name, mutype, replace,
                                            c2c->ip_slave,
                                            c2c->port_slave, 
                                            c2c->passwd_slave);
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
void send_add_lan_sat(int llid, int tid, char *name, char *lan, int num)
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
  len = sprintf(sndbuf, ADD_LAN_SAT, tid, name, lan, num);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_del_lan_sat(int llid, int tid, char *name, char *lan, int num)
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
  len = sprintf(sndbuf, DEL_LAN_SAT, tid, name, lan, num);
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
    if (strlen(it->name) == 0)
      KOUT(" ");
    if (strlen(it->name) >= MAX_NAME_LEN)
      KOUT("%s %d", it->name, (int)strlen(it->name));
    if (strlen(it->sock) == 0)
      KOUT(" ");
    if (strlen(it->sock) >= MAX_PATH_LEN)
      KOUT("%s %d", it->sock, (int)strlen(it->sock));
    if (strlen(it->rank_name) == 0)
      KOUT(" ");
    if (strlen(it->rank_name) >= MAX_NAME_LEN)
      KOUT("%s %d", it->rank_name, (int)strlen(it->rank_name));

    len += sprintf(sndbuf+len, BLKD_ITEM, it->name, it->sock, it->rank_name,
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
  if (name[0] == 0)
    KOUT(" ");
  if (strlen(name) >= MAX_NAME_LEN)
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
static void helper_fill_topo_lan_item(char *msg, 
                                      t_lan_group *vlg0, 
                                      t_lan_group *vlg1)
{
  int i, len;
  char *ptr = msg;
  len = vlg0->nb_lan * sizeof(t_lan_group_item);
  vlg0->lan = (t_lan_group_item *) clownix_malloc(len, 9);
  memset(vlg0->lan, 0, len);
  for (i=0; i<vlg0->nb_lan; i++)
    {
    ptr = strstr(ptr, "<lan>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, TOPO_LAN, vlg0->lan[i].name) != 1)
      KOUT(" ");
    ptr = strstr(ptr, "</lan>");
    if (!ptr)
      KOUT("%s", msg);
    }
  if (vlg1)
    {
    len = vlg1->nb_lan * sizeof(t_lan_group_item);
    vlg1->lan = (t_lan_group_item *) clownix_malloc(len, 9);
    memset(vlg1->lan, 0, len);
    for (i=0; i<vlg1->nb_lan; i++)
      {
      ptr = strstr(ptr, "<lan>");
      if (!ptr)
        KOUT("%s", msg);
      if (sscanf(ptr, TOPO_LAN, vlg1->lan[i].name) != 1)
        KOUT(" ");
      ptr = strstr(ptr, "</lan>");
      if (!ptr)
        KOUT("%s", msg);
      }
    }

}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_topo_vm_item(char *msg, t_vm_item *vmit)
{
  int i, unused;
  char *ptr = msg;
  if (sscanf(msg, TOPO_VM_O, vmit->vm_params.name, 
                             vmit->vm_params.install_cdrom,  
                             vmit->vm_params.added_cdrom,  
                             vmit->vm_params.added_disk,  
                             vmit->vm_params.p9_host_share,  
                             vmit->vm_params.linux_kernel,  
                             vmit->vm_params.rootfs_used,  
                             vmit->vm_params.rootfs_backing,  
                             &(vmit->vm_id), 
                             &(vmit->vm_params.vm_config_flags),  
                             &(vmit->vm_params.nb_eth),
                             &(vmit->vm_params.mem), 
                             &(vmit->vm_params.cpu)) != 13)
    KOUT("%s ", msg);
  for (i=0; i<vmit->vm_params.nb_eth; i++)
    {
    ptr = strstr(ptr, "<eth_infos>");
    if (!ptr)
      KOUT(" ");
    if (sscanf(ptr, TOPO_ETH_O, &unused, &(vmit->lan_eth[i].nb_lan)) != 2)
    KOUT(" ");
    if (unused != i)
      KOUT(" ");
    get_one_eth_param(ptr, vmit->vm_params.eth_params[i].mac_addr,
                      &(vmit->vm_params.eth_params[i].is_promisc));
    helper_fill_topo_lan_item(ptr, &(vmit->lan_eth[i]), NULL);
    ptr = strstr(ptr, "</eth_infos>");
    if (!ptr)
      KOUT(" ");
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_fill_topo_sat_item(char *msg, t_sat_item *sati)
{
  char *ptr = msg;
  if (sscanf(msg, TOPO_SAT_O, sati->name, 
                              &(sati->musat_type), 
                              sati->snf_info.recpath, 
                              &(sati->snf_info.capture_on), 
                              sati->c2c_info.master_cloonix, 
                              sati->c2c_info.slave_cloonix, 
                              &(sati->c2c_info.local_is_master),
                              &(sati->c2c_info.is_peered),
                              &(sati->c2c_info.ip_slave),
                              &(sati->c2c_info.port_slave),
                              &(sati->lan0_sat.nb_lan),
                              &(sati->lan1_sat.nb_lan)) != 12)

    KOUT("%s", msg);
  if (!strcmp(sati->name, NO_DEFINED_VALUE))
    memset(sati->name, 0, MAX_NAME_LEN);
  if (!strcmp(sati->snf_info.recpath, NO_DEFINED_VALUE))
    memset(sati->snf_info.recpath, 0, MAX_PATH_LEN);
  if (!strcmp(sati->c2c_info.master_cloonix, NO_DEFINED_VALUE))
    memset(sati->c2c_info.master_cloonix, 0, MAX_NAME_LEN);
  if (!strcmp(sati->c2c_info.slave_cloonix, NO_DEFINED_VALUE))
    memset(sati->c2c_info.slave_cloonix, 0, MAX_NAME_LEN);
  helper_fill_topo_lan_item(ptr, &(sati->lan0_sat), &(sati->lan1_sat));
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_topo_info *helper_event_topo (char *msg, int *tid)
{
  int i;
  char *ptr = msg;
  t_topo_info *topo;
  topo = (t_topo_info *)clownix_malloc(sizeof(t_topo_info), 15);
  memset(topo, 0, sizeof(t_topo_info));
  if (sscanf(msg, EVENT_TOPO_O, tid, topo->cloonix_config.network_name,
                                     topo->cloonix_config.username,
                                     &(topo->cloonix_config.server_port),
                                     topo->cloonix_config.work_dir,
                                     topo->cloonix_config.bulk_dir,
                                     topo->cloonix_config.bin_dir,
                                     &(topo->nb_vm),  
                                     &(topo->nb_sat)) != 9)
    KOUT("%s", msg);
  topo->vmit= (t_vm_item *) clownix_malloc(topo->nb_vm*sizeof(t_vm_item),16);
  memset(topo->vmit, 0, topo->nb_vm*sizeof(t_vm_item));
  topo->sati= (t_sat_item *) clownix_malloc(topo->nb_sat*sizeof(t_sat_item),17);
  memset(topo->sati, 0, topo->nb_sat*sizeof(t_sat_item));

  for (i=0; i<topo->nb_vm; i++)
    {
    ptr = strstr(ptr, "<vm>");
    if (!ptr)
      KOUT("%d,%d\n%s\n", topo->nb_vm, i, msg);
    helper_fill_topo_vm_item(ptr, &(topo->vmit[i]));
    ptr = strstr(ptr, "</vm>");
    if (!ptr)
      KOUT(" ");
    }

  for (i=0; i<topo->nb_sat; i++)
    {
    ptr = strstr(ptr, "<sat>");
    if (!ptr)
      KOUT(" ");
    helper_fill_topo_sat_item(ptr, &(topo->sati[i]));
    ptr = strstr(ptr, "</sat>");
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
static int add_eventfull_vm(char *buf, t_eventfull_vm *vm)
{
  int i, result = 0;
  result += sprintf(buf+result, EVENTFULL_VM_O, vm->name, 
                    vm->ram, vm->cpu, vm->nb_eth);
  for (i=0; i<vm->nb_eth; i++)
    result += sprintf(buf+result, EVENTFULL_ETH, vm->eth[i].eth, 
                                  vm->eth[i].pkt_rx, vm->eth[i].pkt_tx);
  result += sprintf(buf+result, EVENTFULL_VM_C);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void send_eventfull(int llid, int tid, 
                    int nb_vm, t_eventfull_vm *vm,
                    int nb_sat, t_eventfull_sat *sat)
{
  int i, len = 0;
  len += sprintf(sndbuf+len, EVENTFULL_O, tid, nb_vm, nb_sat);
  for (i=0; i<nb_vm; i++)
    len += add_eventfull_vm(sndbuf+len, &(vm[i]));
  for (i=0; i<nb_sat; i++)
    len += sprintf(sndbuf+len,EVENTFULL_SAT, sat[i].name, sat[i].sat_is_ok,
                                             sat[i].pkt_rx0,sat[i].pkt_tx0,
                                             sat[i].pkt_rx1,sat[i].pkt_tx1);
  len += sprintf(sndbuf+len, EVENTFULL_C);
  my_msg_mngt_tx(llid, len, sndbuf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_eventfull_sat(char *msg, int nb, t_eventfull_sat *sat)
{
  char *ptr = msg;
  int i;
  for (i=0; i<nb; i++)
    {
    ptr = strstr (ptr, "<eventfull_sat>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, EVENTFULL_SAT,  sat[i].name,
                                    &(sat[i].sat_is_ok),
                                    &(sat[i].pkt_rx0),
                                    &(sat[i].pkt_tx0),
                                    &(sat[i].pkt_rx1),
                                    &(sat[i].pkt_tx1)) != 6)
      KOUT("%s", msg);
    ptr = strstr (ptr, "</eventfull_sat>");
    if (!ptr)
      KOUT("%s", msg);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_eventfull_eth(char *msg, int nb, t_eventfull_eth *eth)
{
  char *ptr = msg;
  int i;
  for (i=0; i<nb; i++)
    {
    ptr = strstr (ptr, "<eventfull_eth>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, EVENTFULL_ETH, &(eth[i].eth),
                                    &(eth[i].pkt_rx),
                                    &(eth[i].pkt_tx)) != 3)
      KOUT("%s", msg);
    ptr = strstr (ptr, "</eventfull_eth>");
    if (!ptr)
      KOUT("%s", msg);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_eventfull_vm(char *msg, int nb, t_eventfull_vm *vm)
{
  char *ptr = msg;
  int i;
  for (i=0; i<nb; i++)
    {
    ptr = strstr (ptr, "<eventfull_vm>");
    if (!ptr)
      KOUT("%s", msg);
    if (sscanf(ptr, EVENTFULL_VM_O, vm[i].name, 
               &(vm[i].ram), &(vm[i].cpu), &(vm[i].nb_eth)) != 4) 
      KOUT("%s", msg);
    helper_eventfull_eth(ptr, vm[i].nb_eth, vm[i].eth);
    ptr = strstr (ptr, "</eventfull_vm>");
    if (!ptr)
      KOUT("%s", msg);
    }
  ptr = strstr (ptr, "<eventfull_vm>");
  if (ptr)
    KOUT("%d\n%s", nb, msg);
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
    if (sscanf(ptr, BLKD_ITEM, it->name, it->sock, it->rank_name, 
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
                                    != 21)
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
static void dispatcher(int llid, int bnd_evt, char *msg)
{
  int len, nb_vm, nb_sat, flags_hop, num;
  int vmcmd, param, status, sub;
  int mutype, type, eth, qty, secs, usecs, tid; 
  t_cloonix_config *cloonix_config;
  t_eventfull_vm *eventfull_vm;
  t_eventfull_sat *eventfull_sat;
  char *pname, *parm1, *parm2;
  t_vm_params vm_params;
  char network_name[MAX_NAME_LEN];
  char name[MAX_NAME_LEN];
  char path[MAX_PATH_LEN];
  char name2[MAX_NAME_LEN];
  char param1[MAX_PATH_LEN];
  char param2[MAX_PATH_LEN];
  char lan[MAX_NAME_LEN];
  char info[MAX_PRINT_LEN];
  char *ptr, *ptrs, *ptre, *line, *txt;
  t_pid_lst *pid_lst;
  t_sys_info *sys;
  t_topo_info *topo;
  t_list_commands *list_commands;
  t_stats_counts stats_counts;
  t_stats_sysinfo stats_sysinfo;
  t_c2c_req_info c2c_req_info;
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
      txt = get_hop_free_txt(msg);
      recv_hop_evt_doors(llid, tid, flags_hop, name, txt);
      clownix_free(txt, __FUNCTION__);
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


    case bnd_sub_evt_stats_eth:
      if (sscanf(msg, SUB_EVT_STATS_ETH, &tid, name, &eth, &sub) != 4)
        KOUT("%s", msg);
      recv_evt_stats_eth_sub(llid, tid, name, eth, sub);
      break;

    case bnd_evt_stats_eth:
      if (sscanf(msg, EVT_STATS_ETH_O, &tid, network_name, name, &eth,
                 &status, &(stats_counts.nb_tx_items),
                 &(stats_counts.nb_rx_items)) != 7)
        KOUT("%s", msg);
      helper_tx_stats(msg, stats_counts.nb_tx_items, stats_counts.tx_item);
      helper_rx_stats(msg, stats_counts.nb_rx_items, stats_counts.rx_item);
      recv_evt_stats_eth(llid, tid, network_name,
                         name, eth, &stats_counts, status);
      break;

    case bnd_sub_evt_stats_sat:
      if (sscanf(msg, SUB_EVT_STATS_SAT, &tid, name, &sub) != 3)
        KOUT("%s", msg);
      recv_evt_stats_sat_sub(llid, tid, name, sub);
      break;

    case bnd_evt_stats_sat:
      if (sscanf(msg, EVT_STATS_SAT_O, &tid, network_name, name,
                 &status, &(stats_counts.nb_tx_items), 
                 &(stats_counts.nb_rx_items)) != 6)
        KOUT("%s", msg);
      helper_tx_stats(msg, stats_counts.nb_tx_items, stats_counts.tx_item);
      helper_rx_stats(msg, stats_counts.nb_rx_items, stats_counts.rx_item);
      recv_evt_stats_sat(llid,tid,network_name,name,&stats_counts,status);
      break;

    case bnd_sub_evt_stats_sysinfo:
      if (sscanf(msg, SUB_EVT_STATS_SYSINFO, &tid, name, &sub) != 3)
        KOUT("%s", msg);
      recv_evt_stats_sysinfo_sub(llid, tid, name, sub);
      break;

    case bnd_evt_stats_sysinfo:
      if (sscanf(msg, EVT_STATS_SYSINFOO, &tid, network_name, name,
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
      line = NULL;
      ptre = NULL;
      ptrs = strstr(msg, "<bound_for_df_dumprd>");
      if (ptrs)
        ptrs += strlen("<bound_for_df_dumprd>");
      ptre = strstr(msg, "</bound_for_df_dumprd>");
      len = (int) (ptre - ptrs);
      if (ptrs && ptre && (len>0))
        {
        if (len >= MAX_STATS_SYSDF)
          len = MAX_STATS_SYSDF-1;
        line = malloc(MAX_STATS_SYSDF);
        memcpy(line, ptrs, len);
        line[len] = 0;
        }
      recv_evt_stats_sysinfo(llid, tid, network_name, name,
                             &stats_sysinfo, line, status);
      break;

    case bnd_mucli_dialog_req:
      if (sscanf(msg, MUCLI_DIALOG_REQ_O, &tid, name, &eth) != 3)
        KOUT("%s", msg);
      ptrs = strstr(msg, "<mucli_dialog_req_bound>");
      if (!ptrs)
        KOUT("%s", msg);
      ptrs += strlen("<mucli_dialog_req_bound>");
      ptre = strstr(ptrs, "</mucli_dialog_req_bound>");
      if (!ptre)
        KOUT("%s", msg);
      len = ptre - ptrs;
      line = (char *) clownix_malloc(len+1, 10);
      memset(line, 0, len+1);
      memcpy(line, ptrs, len);
      recv_mucli_dialog_req(llid, tid, name, eth, line);
      clownix_free(line, __FUNCTION__);
      break;

    case bnd_mucli_dialog_resp:
      if (sscanf(msg, MUCLI_DIALOG_RESP_O, &tid, name, &eth, 
                                           &status) != 4)
        KOUT("%s", msg);
      ptrs = strstr(msg, "<mucli_dialog_resp_bound>");
      if (!ptrs)
        KOUT("%s", msg);
      ptrs += strlen("<mucli_dialog_resp_bound>");
      ptre = strstr(ptrs, "</mucli_dialog_resp_bound>");
      if (!ptre)
        KOUT("%s", msg);
      len = ptre - ptrs;
      line = (char *) clownix_malloc(len+1, 10);
      memset(line, 0, len+1);
      memcpy(line, ptrs, len);
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
      topo_info_free(topo);
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
      memset(&vm_params, 0, sizeof(t_vm_params));
      if (sscanf(msg, ADD_VM_O, &tid, vm_params.name, 
                 &(vm_params.vm_config_flags),
                 &(vm_params.cpu), &(vm_params.mem), 
                 &(vm_params.nb_eth)) != 6)
        KOUT("%s", msg);
      get_eth_params(msg, vm_params.nb_eth, vm_params.eth_params);
      ptr = strstr(msg, "<linux_kernel>");
      if (!ptr)
        KOUT("%s", msg);
      if (sscanf(ptr, ADD_VM_C, vm_params.linux_kernel, 
                                vm_params.rootfs_input, 
                                vm_params.install_cdrom, 
                                vm_params.added_cdrom, 
                                vm_params.added_disk, 
                                vm_params.p9_host_share) != 6) 
        KOUT("%s", msg);
      recv_add_vm(llid, tid, &vm_params);
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


    case bnd_add_sat:
      memset(&(c2c_req_info), 0, sizeof(t_c2c_req_info));
      if (sscanf(msg, ADD_SAT, &tid, name, &mutype,
                               c2c_req_info.cloonix_slave,
                               &(c2c_req_info.ip_slave),
                               &(c2c_req_info.port_slave),
                               c2c_req_info.passwd_slave) != 7)
        KOUT("%s", msg);
      if (!strcmp(c2c_req_info.cloonix_slave, NO_DEFINED_VALUE))
        memset(c2c_req_info.cloonix_slave, 0, MAX_NAME_LEN);
      recv_add_sat(llid, tid, name, mutype, &c2c_req_info);
      break;
    case bnd_del_sat:
      if (sscanf(msg, DEL_SAT, &tid, name) != 2)
        KOUT("%s", msg);
      recv_del_sat(llid, tid, name);
      break;

    case bnd_add_lan_sat:
      if (sscanf(msg, ADD_LAN_SAT, &tid, name, lan, &num) != 4)
        KOUT("%s", msg);
      recv_add_lan_sat(llid, tid, name, lan, num);
      break;
    case bnd_del_lan_sat:
      if (sscanf(msg, DEL_LAN_SAT, &tid, name, lan, &num) != 4)
        KOUT("%s", msg);
      recv_del_lan_sat(llid, tid, name, lan, num);
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

    case bnd_event_spy_sub:
      if (sscanf(msg, EVENT_SPY_SUB, &tid, name, name2, info) != 4)
        KOUT("%s", msg);
      if (!strcmp(name, NO_DEFINED_VALUE))
        pname = NULL;
      else
        pname = name;
      recv_event_spy_sub(llid, tid, pname, name2, info);
      break;
    case bnd_event_spy_unsub:
      if (sscanf(msg, EVENT_SPY_UNSUB, &tid, name, name2, info) != 4)
        KOUT("%s", msg);
      if (!strcmp(name, NO_DEFINED_VALUE))
        pname = NULL;
      else
        pname = name;
      recv_event_spy_unsub(llid, tid, pname, name2, info);
      break;
    case bnd_event_spy:
      if (sscanf(msg, EVENT_SPY_O, &tid, name, name2, info, 
                                   &secs, &usecs, &qty) != 7)
        KOUT("%s", msg);
      if (!strcmp(name, NO_DEFINED_VALUE))
        pname = NULL;
      else
        pname = name;
      ptr = helper_event_spy(msg, qty);
      recv_event_spy(llid,tid,pname,name2, info, secs, usecs, qty, ptr);
      if (ptr)
        clownix_free(ptr, __FUNCTION__);
      break;
    case bnd_work_dir_req:
      if (sscanf(msg, WORK_DIR_REQ, &tid) != 1)
        KOUT("%s", msg);
      recv_work_dir_req(llid, tid);
      break;
    case bnd_work_dir_resp:
      cloonix_config = 
      (t_cloonix_config *) clownix_malloc(sizeof(t_cloonix_config), 5);
      memset(cloonix_config, 0, sizeof(t_cloonix_config));
      if (sscanf(msg, WORK_DIR_RESP, &tid, 
                                     cloonix_config->version,
                                     cloonix_config->network_name,
                                     cloonix_config->username,
                                     &(cloonix_config->server_port),
                                     cloonix_config->work_dir,
                                     cloonix_config->bulk_dir,
                                     cloonix_config->bin_dir,
                                     &(cloonix_config->flags_config)) != 9)


        KOUT("%s", msg);
      recv_work_dir_resp(llid, tid, cloonix_config);
      clownix_free(cloonix_config, __FUNCTION__);
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
      if (sscanf(msg, EVENTFULL_O, &tid, &nb_vm, &nb_sat) != 3)
        KOUT("%s", msg);

      len = nb_vm * sizeof(t_eventfull_vm);
      eventfull_vm = (t_eventfull_vm *)clownix_malloc(len, 22); 
      memset(eventfull_vm, 0, len);
      helper_eventfull_vm(msg, nb_vm, eventfull_vm);

      len = nb_sat * sizeof(t_eventfull_sat);
      eventfull_sat = (t_eventfull_sat *)clownix_malloc(len, 23); 
      memset(eventfull_sat, 0, len);
      helper_eventfull_sat(msg, nb_sat, eventfull_sat);

      recv_eventfull(llid, tid, nb_vm, eventfull_vm, 
                                nb_sat, eventfull_sat);
      clownix_free(eventfull_vm, __FUNCTION__);
      clownix_free(eventfull_sat, __FUNCTION__);
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
    case type_llid_trace_musat_eth:
      result = "mueth";
      break;
    case type_llid_trace_musat_tap:
      result = "mutap";
      break;
    case type_llid_trace_musat_snf:
      result = "musnf";
      break;
    case type_llid_trace_musat_c2c:
      result = "muc2c";
      break;
    case type_llid_trace_musat_a2b:
      result = "mua2b";
      break;
    case type_llid_trace_musat_wif:
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
  extract_boundary (ADD_SAT,     bound_list[bnd_add_sat]);
  extract_boundary (DEL_SAT,     bound_list[bnd_del_sat]);
  extract_boundary (ADD_LAN_SAT, bound_list[bnd_add_lan_sat]);
  extract_boundary (DEL_LAN_SAT, bound_list[bnd_del_lan_sat]);
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
  extract_boundary (EVENT_SPY_SUB,  bound_list[bnd_event_spy_sub]);
  extract_boundary (EVENT_SPY_UNSUB,  bound_list[bnd_event_spy_unsub]);
  extract_boundary (EVENT_SPY_O,  bound_list[bnd_event_spy]);
  extract_boundary (WORK_DIR_REQ,  bound_list[bnd_work_dir_req]);
  extract_boundary (WORK_DIR_RESP, bound_list[bnd_work_dir_resp]);
  extract_boundary (VMCMD, bound_list[bnd_vmcmd]);
  extract_boundary (EVENTFULL_SUB, bound_list[bnd_eventfull_sub]);
  extract_boundary (EVENTFULL_O, bound_list[bnd_eventfull]);
  extract_boundary (MUCLI_DIALOG_REQ_O, bound_list[bnd_mucli_dialog_req]);
  extract_boundary (MUCLI_DIALOG_RESP_O, bound_list[bnd_mucli_dialog_resp]);
  extract_boundary (SUB_EVT_STATS_ETH, bound_list[bnd_sub_evt_stats_eth]);
  extract_boundary (EVT_STATS_ETH_O, bound_list[bnd_evt_stats_eth]);
  extract_boundary (SUB_EVT_STATS_SAT, bound_list[bnd_sub_evt_stats_sat]);
  extract_boundary (EVT_STATS_SAT_O, bound_list[bnd_evt_stats_sat]);
  extract_boundary (SUB_EVT_STATS_SYSINFO, bound_list[bnd_sub_evt_stats_sysinfo]);
  extract_boundary (EVT_STATS_SYSINFOO, bound_list[bnd_evt_stats_sysinfo]);
  extract_boundary (BLKD_REPORTS_O, bound_list[bnd_blkd_reports]);
  extract_boundary (BLKD_REPORTS_SUB, bound_list[bnd_blkd_reports_sub]);

  extract_boundary (HOP_GET_LIST_NAME, bound_list[bnd_hop_get_list]);
  extract_boundary (HOP_LIST_NAME_O, bound_list[bnd_hop_list]);
  extract_boundary (HOP_EVT_DOORS_SUB_O, bound_list[bnd_hop_evt_doors_sub]);
  extract_boundary (HOP_EVT_DOORS_UNSUB, bound_list[bnd_hop_evt_doors_unsub]);
  extract_boundary (HOP_EVT_DOORS_O,   bound_list[bnd_hop_evt_doors]);

}
/*---------------------------------------------------------------------------*/





