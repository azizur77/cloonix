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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "hop_event.h"
#include "cfg_store.h"
#include "musat_mngt.h"
#include "mueth_mngt.h"
#include "mulan_mngt.h"


/****************************************************************************/
typedef struct t_mutimeout
{
  int llid;
  int cli_llid;
  int cli_tid;
  char name[MAX_NAME_LEN];
  int num;
  struct t_mutimeout *prev;
  struct t_mutimeout *next;
} t_mutimeout;
/*--------------------------------------------------------------------------*/

static t_mutimeout *g_head;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void snf_globtopo_small_event(char *name, int num_evt, char *path)
{
  t_small_evt evt;
  memset(&evt, 0, sizeof(t_small_evt));
  strncpy(evt.name, name, MAX_NAME_LEN-1);
  evt.evt = num_evt;
  if (num_evt == snf_evt_recpath_change)
    strncpy(evt.param1, path, MAX_PATH_LEN-1);
  event_subscriber_send(topo_small_event, (void *) &evt);
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static t_mutimeout *mutimeout_find(int llid, int cli_llid, int cli_tid)
{
  t_mutimeout *cur = g_head;
  while(cur)
    {
    if ((cur->llid == llid) && 
        (cur->cli_llid == cli_llid) && 
        (cur->cli_tid == cli_tid))
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int mutimeout_unchain(int llid, int cli_llid, int cli_tid)
{
  int result = 0;
  t_mutimeout *cur = mutimeout_find(llid, cli_llid, cli_tid);
  if (cur)
    {
    result = 1;
    if (cur->prev)
      cur->prev->next = cur->next;
    if (cur->next)
      cur->next->prev = cur->prev;
    if (cur == g_head)
      g_head = cur->next;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void muresp_timeout(void *data)
{
  t_mutimeout *mut = (t_mutimeout *) data;
  if (mutimeout_unchain(mut->llid, mut->cli_llid, mut->cli_tid))
    {
    KERR(" ");
    if (msg_exist_channel(mut->cli_llid))
      {
      send_mucli_dialog_resp(mut->cli_llid, mut->cli_tid,
                             mut->name, mut->num, "KO TIMEOUT", 1);
      }
    }
  clownix_free(mut, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void mutimeout_chain(int llid, int cli_llid, int cli_tid, 
                            char *name, int num)
{
  t_mutimeout *cur; 
  cur = (t_mutimeout *) clownix_malloc(sizeof(t_mutimeout), 4);
  memset(cur, 0, sizeof(t_mutimeout));
  cur->llid = llid;
  cur->cli_llid = cli_llid;
  cur->cli_tid = cli_tid;
  cur->num = num;
  strncpy(cur->name, name, MAX_NAME_LEN-1);
  if (g_head)
    g_head->prev = cur;
  cur->next = g_head;
  g_head = cur;
  clownix_timeout_add(2000, muresp_timeout, (void *) cur, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_mucli_dialog_req(int llid, int tid, 
                           char *name, int num, char *line)
{
  int musat_type;
  int mullid = 0;
  if (!mullid)
    mullid = mulan_can_be_found_with_name(name);
  if (!mullid)
    mullid = mueth_can_be_found_with_name(name, num);
  if (!mullid)
    mullid = musat_mngt_can_be_found_with_name(name, &musat_type);
  if (!mullid)
    send_mucli_dialog_resp(llid, tid, name, num, "KO NOT FOUND", 1);
  else
    {
    mutimeout_chain(mullid, llid, tid, name, num);
    rpct_send_cli_req(NULL, mullid, 0, llid, tid, line);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_mucli_dialog_resp(int llid, int tid, 
                            char *name, int num, char *line, int status)
{
  KOUT(" ");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void rpct_recv_cli_req(void *ptr, int llid, int tid, 
                    int cli_llid, int cli_tid, char *line)
{
  KOUT(" ");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void update_sat_tux(char *name, char *line)
{
  t_tux *tux;
  tux = cfg_get_tux(name);
  char *ptr;
  if (tux)
    {
    if (tux->musat_type == musat_type_snf)
      {
      if (!strcmp(line, "REC_START_OK"))
        {
        tux->snf_info.capture_on = 1;
        snf_globtopo_small_event(tux->name, snf_evt_capture_on, NULL);
        }
      else if (!strcmp(line, "REC_STOP_OK"))
        {
        tux->snf_info.capture_on = 0;
        snf_globtopo_small_event(tux->name, snf_evt_capture_off, NULL);
        }
      else if (!strncmp(line, "SET_CONF_OK", strlen("SET_CONF_OK")))
        {
        memset(tux->snf_info.recpath, 0, MAX_PATH_LEN);
        strncpy(tux->snf_info.recpath, 
                line + strlen("SET_CONF_OK"), MAX_PATH_LEN - 1);
        snf_globtopo_small_event(tux->name, snf_evt_recpath_change, 
                                 tux->snf_info.recpath);
        }
      else if (!strncmp(line, "GET_CONF_RESP", strlen("GET_CONF_RESP")))
        {
        memset(tux->snf_info.recpath, 0, MAX_PATH_LEN);
        strncpy(tux->snf_info.recpath, 
                line + strlen("GET_CONF_RESP"), MAX_PATH_LEN - 1);
        ptr = strchr(tux->snf_info.recpath, ' ');
        if (!ptr)
          KERR("%s", tux->snf_info.recpath); 
        else
          {
          *ptr = 0;
          ptr += 1;
          snf_globtopo_small_event(tux->name, snf_evt_recpath_change, 
                                   tux->snf_info.recpath);
          if (ptr[0] == '1')
            snf_globtopo_small_event(tux->name, snf_evt_capture_on, NULL);
          else
            snf_globtopo_small_event(tux->name, snf_evt_capture_off, NULL);
          }
        }
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void rpct_recv_cli_resp(void *ptr, int llid, int tid, 
                        int cli_llid,int cli_tid, char *line)
{
  char name[MAX_NAME_LEN];
  int mutype, num = 0;
  hop_event_hook(llid, FLAG_HOP_DIAG, line);
  if (cli_llid)
    {
    if (!mutimeout_unchain(llid, cli_llid, cli_tid))
      KERR("%d %s", tid, line);
    }
  if ((!mueth_can_be_found_with_llid(llid, name, &num)) &&
      (!musat_mngt_can_be_found_with_llid(llid, name, &mutype)) &&
      (!mulan_can_be_found_with_llid(llid, name)))
    KERR("CANNOT BE %s", line);
  if (musat_mngt_can_be_found_with_llid(llid, name, &mutype))
    {
    update_sat_tux(name, line);
    }
  send_mucli_dialog_resp(cli_llid, cli_tid, name, num, line, 0);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void rpct_recv_evt_msg(void *ptr, int llid, int tid, char *line)
{
  char name[MAX_NAME_LEN];
  int num, mutype;
  if (mueth_can_be_found_with_llid(llid, name, &num))
    {
    mueth_rpct_recv_evt_msg(llid, tid, line);
    hop_event_hook(llid, FLAG_HOP_EVT, line);
    }
  else if (musat_mngt_can_be_found_with_llid(llid, name, &mutype))
    {
    musat_mngt_rpct_recv_evt_msg(llid, tid, line);
    hop_event_hook(llid, FLAG_HOP_EVT, line);
    }
  else if (mulan_can_be_found_with_llid(llid, name))
    {
    mulan_rpct_recv_evt_msg(llid, tid, line);
    hop_event_hook(llid, FLAG_HOP_EVT, line);
    }
  else
    KERR("CANNOT DISPATCH %s", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void rpct_recv_app_msg(void *ptr, int llid, int tid, char *line)
{
  KERR("%s", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void rpct_recv_diag_msg(void *ptr, int llid, int tid, char *line)
{
  char name[MAX_NAME_LEN];
  int num, mutype;
  hop_event_hook(llid, FLAG_HOP_DIAG, line);
  if (mueth_can_be_found_with_llid(llid, name, &num))
    mueth_rpct_recv_diag_msg(llid, tid, line);
  else if (musat_mngt_can_be_found_with_llid(llid, name, &mutype))
    musat_mngt_rpct_recv_diag_msg(llid, tid, line);
  else if (mulan_can_be_found_with_llid(llid, name))
    mulan_rpct_recv_diag_msg(llid, tid, line);
  else
    KERR("CANNOT DISPATCH %s", line);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void murpc_dispatch_send_tx_flow_control(int llid, int rank, int stop)
{
  char line[MAX_PATH_LEN];
  memset(line, 0, MAX_PATH_LEN);
  snprintf(line, MAX_PATH_LEN-1, 
  "cloonix_evt_peer_flow_control_tx rank=%d stop=%d", rank, stop);
  rpct_send_evt_msg(NULL, llid, 0, line);
}
/*---------------------------------------------------------------------------*/

