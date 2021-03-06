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
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <errno.h>
#include "io_clownix.h"
#include "rpc_clownix.h"
#include "layout_rpc.h"
#include "cfg_store.h"
#include "pid_clone.h"
#include "lan_to_name.h"
#include "doors_rpc.h"
#include "event_subscriber.h"
#include "llid_trace.h"
#include "layout_topo.h"
#include "utils_cmd_line_maker.h"
#include "system_callers.h"
#include "automates.h"
#include "doorways_mngt.h"
#include "qhvc0.h"
#include "qmp.h"
#include "timeout_service.h"
#include "c2c.h"
#include "hop_event.h"
#include "header_sock.h"
#include "stats_counters.h"
#include "stats_counters_sysinfo.h"

void uml_clownix_switch_error_cb(void *ptr, int llid, int err, int from);
void uml_clownix_switch_rx_cb(int llid, int len, char *buf);
void timer_utils_finish_vm_init(char *name, int val);


static void doorways_start(void);
static int g_killed;


void last_action_self_destruction(void *data);

static int g_nb_pid_resp;
static int g_nb_pid_resp_warning;
static int g_this_is_a_restart;
static int g_doorways_pid;
static int g_doorways_llid = 0;
static long long g_abs_beat_timer;
static int  g_ref_timer;
static char g_bin_doorways[MAX_PATH_LEN];
static char g_root_work[MAX_PATH_LEN];
static char g_server_port[MAX_NAME_LEN];
static char g_password[MSG_DIGEST_LEN];



/*****************************************************************************/
void doors_timeout_service_cb(int job_idx, int is_timeout, void *opaque)
{
  char msg[3*MAX_NAME_LEN];
  t_opaque_agent_req *agent_req = (t_opaque_agent_req *) opaque;
  memset(msg, 0, 3*MAX_NAME_LEN);
  if (is_timeout)
    {
    snprintf(msg, 3*MAX_NAME_LEN - 1, "TIMEOUT REACHING %s for %s", 
             agent_req->name, agent_req->action);
    send_status_ko(agent_req->llid, agent_req->tid, msg);
    }
  else
    {
    snprintf(msg, 3*MAX_NAME_LEN - 1, "%s for %s OK", 
             agent_req->action, agent_req->name);
    send_status_ok(agent_req->llid, agent_req->tid, msg);
    }
  clownix_free(opaque, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void doors_recv_c2c_resp_idx(int llid, int tid, char *name, int local_idx)
{
  rx_c2c_resp_idx_from_doors(name, local_idx);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void doors_recv_c2c_resp_conx(int llid, int tid, char *name, int fd, int status)
{
  rx_c2c_event_conx_from_doors(name, fd, status);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static int get_sysinfo_vals(char *msg, unsigned long *uptime,
                            unsigned long *load1, unsigned long *load5,
                            unsigned long *load15, unsigned long *totalram,
                            unsigned long *freeram, unsigned long *cachedram, 
                            unsigned long *sharedram,
                            unsigned long *bufferram, unsigned long *totalswap,
                            unsigned long *freeswap, unsigned long *procs,
                            unsigned long *totalhigh, unsigned long *freehigh,
                            unsigned long *mem_unit)
{
  int result = -1;
  if (sscanf(msg, SYSINFOFORMAT,
                  uptime, load1, load5, load15, 
                  totalram, freeram, cachedram, sharedram,
                  bufferram, totalswap, freeswap, procs, 
                  totalhigh, freehigh,
                  mem_unit) == 15)
    result = 0;
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void recv_sysinfo_vals(char *name, char *line)
{
  unsigned long used_mem;
  unsigned long uptime, load1, load5, load15, totalram, freeram;
  unsigned long cachedram, sharedram, bufferram, totalswap, freeswap;
  unsigned long procs, totalhigh, freehigh, mem_unit;
  if (get_sysinfo_vals(line, &uptime, &load1, &load5, &load15, &totalram,
                       &freeram, &cachedram, &sharedram, &bufferram, 
                       &totalswap, &freeswap, &procs, &totalhigh, &freehigh,
                       &mem_unit))
    {
    KERR("%s %s", name, line);
    used_mem = 0;
    }
  else
    {
    used_mem = totalram - freeram;
    used_mem /= 1000;
    }
  qmp_agent_sysinfo(name, (int) used_mem);
  stats_counters_sysinfo_update(name, uptime, load1, load5, load15,
                                totalram, freeram, cachedram, sharedram, 
                                bufferram, totalswap, freeswap, procs,
                                totalhigh, freehigh, mem_unit);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void doors_recv_event(int llid, int tid, char *name, char *line)
{
  int job_idx;
  if (!strcmp(line, BACKDOOR_CONNECTED))
    {
    qhvc0_event_backdoor(name, backdoor_evt_connected);
    }
  else if (!strcmp(line, BACKDOOR_DISCONNECTED))
    {
    qhvc0_event_backdoor(name, backdoor_evt_disconnected);
    }
  else if (!strncmp(line, AGENT_SYSINFO, strlen(AGENT_SYSINFO)))
    {
    recv_sysinfo_vals(name, line + strlen(AGENT_SYSINFO) + 1);
    }
  else if (!strncmp(line, AGENT_SYSINFO_DF, strlen(AGENT_SYSINFO_DF)))
    {
    stats_counters_sysinfo_update_df(name,line+strlen(AGENT_SYSINFO_DF)+1);
    }
  else if (!strcmp(line, PING_OK))
    {
    timer_utils_finish_vm_init(name, 1);
    qhvc0_event_backdoor(name, backdoor_evt_ping_ok);
    }
  else if (!strcmp(line, PING_KO))
    qhvc0_event_backdoor(name, backdoor_evt_ping_ko);
  else if (sscanf(line, REBOOT_REQUEST, &job_idx) == 1)
    timeout_service_trigger(job_idx);
  else if (sscanf(line, HALT_REQUEST, &job_idx) == 1)
    timeout_service_trigger(job_idx);
  else
    KOUT("%s", line);
  

}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void killed(void *unused_data, int status, char *name)
{
  g_killed = 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void doorways_err_cb (int llid)
{
  if (llid == g_doorways_llid)
    {
    g_doorways_llid = 0;
    g_this_is_a_restart = 1;
    if (!get_glob_req_self_destruction())
      {
      KERR("Ctrl access to cloonix_doorways broken, re-launching\n");
      doorways_start();
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void monitoring_doorways(void *data)
{
  static int old_nb_pid_resp;
  if (old_nb_pid_resp == g_nb_pid_resp)
    g_nb_pid_resp_warning++;
  else
    g_nb_pid_resp_warning = 0;
  if (g_nb_pid_resp_warning > 4) 
    {
    event_print("DOORWAY CONTACT LOSS");
    KERR("TRY KILLING DOORWAYS");
    if (!kill(old_nb_pid_resp, SIGKILL));
      KERR("NO SUCCESS KILLING DOORWAYS");
    }
  g_abs_beat_timer = 0;
  g_ref_timer = 0;
  clownix_timeout_add(500, monitoring_doorways, NULL, 
                   &(g_abs_beat_timer), &(g_ref_timer));
  rpct_send_pid_req(NULL, g_doorways_llid, type_hop_doors, "doors", 0);
  old_nb_pid_resp = g_nb_pid_resp;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void doors_pid_resp(int llid, char *name, int pid)
{
  if (strcmp(name, "doors"))
    KERR("%s", name); 
  if (g_doorways_pid != pid)
    event_print("DOORWAYS PID CHANGE: %d to %d", g_doorways_pid, pid);
  g_doorways_pid = pid;
  g_nb_pid_resp++;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timer_doorways_protect(void *data)
{
  if (!g_killed)
    KERR(" ");
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void timer_doorways_connect(void *data)
{
  int llid;
  static int count = 0;
  char *ctrl = (char *) data;
  llid = string_client_unix(ctrl, uml_clownix_switch_error_cb,
                                  uml_clownix_switch_rx_cb, "doorways");
  if (llid)
    {
    g_doorways_llid = llid;
    if (hop_event_alloc(llid, type_hop_doors, "doors", 0))
      KERR(" ");
    llid_trace_alloc(llid, "DOORWAYS", 0,0,type_llid_trace_doorways);
    qhvc0_reinit_vm_in_doorways();
    rpct_send_pid_req(NULL, llid, type_hop_doors, "doors", 0);
    if (g_abs_beat_timer)
      clownix_timeout_del(g_abs_beat_timer, g_ref_timer, __FILE__, __LINE__);
    clownix_timeout_add(500, monitoring_doorways, NULL, 
                   &(g_abs_beat_timer), &(g_ref_timer));
    g_doorways_pid = 0;
    g_nb_pid_resp_warning = 0;
    }
  else
    {
    count++;
    if (count < 100)
      clownix_timeout_add(50, timer_doorways_connect, data, NULL, NULL);
    else
      {
      KERR("doorswaitgivingup");
      last_action_self_destruction(NULL);
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void dump_doors_creation_info(char *name, char **argv)
{
  char info[MAX_PRINT_LEN];
  utils_format_gene("CREATION", info, name, argv);
  event_print("%s", info);

//VIP
//  KERR("%s", info);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void doorways_start()
{
  static char *argv[] ={
                       g_bin_doorways,
                       g_root_work,
                       g_server_port,
                       g_password,
                       NULL
                       };
  char *ctrl_doors_sock = cfg_get_ctrl_doors_sock();

  if (!get_glob_req_self_destruction())
    {
    g_killed = 0;
//VIP
    pid_clone_launch(utils_execve, killed, NULL, (void *) argv,
                     NULL, NULL, "doorways", -1, 1);

    clownix_timeout_add(500, timer_doorways_protect, NULL, NULL, NULL); 
    clownix_timeout_add(50, timer_doorways_connect, 
                        (void *) ctrl_doors_sock, NULL, NULL);

    dump_doors_creation_info("doors", argv);

//VIP
//    clownix_timeout_add(5000, timer_doorways_protect, NULL, NULL, NULL); 
//    clownix_timeout_add(1000, timer_doorways_connect, 
//                        (void *) ctrl_doors_sock, NULL, NULL);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int doorways_get_distant_pid(void)
{
  return g_doorways_pid;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int get_doorways_llid(void)
{
  return g_doorways_llid;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
char *get_doorways_bin(void)
{
  return g_bin_doorways;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void doorways_first_start(void)
{
  g_this_is_a_restart = 0;
  doorways_start();
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void doorways_init(char *root_work, int server_port, char *password)
{
  memset(g_bin_doorways, 0, MAX_PATH_LEN);
  memset(g_root_work, 0, MAX_PATH_LEN);
  memset(g_server_port, 0, MAX_NAME_LEN);
  memset(g_password, 0, MSG_DIGEST_LEN);
  sprintf(g_bin_doorways, 
          "%s/server/doorways/cloonix_doorways", cfg_get_bin_dir());
  strncpy(g_root_work, root_work, MAX_PATH_LEN-1);
  snprintf(g_server_port, MAX_PATH_LEN-1, "%d", server_port);
  strncpy(g_password, password, MSG_DIGEST_LEN-1);
  doors_xml_init();
}
/*---------------------------------------------------------------------------*/



