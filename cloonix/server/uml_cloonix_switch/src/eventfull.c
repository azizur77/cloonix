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
#include <unistd.h>
#include <sys/sysinfo.h>

#include "io_clownix.h"
#include "lib_commons.h"
#include "commun_daemon.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "event_subscriber.h"
#include "machine_create.h"
#include "utils_cmd_line_maker.h"
#include "musat_mngt.h"


/*****************************************************************************/
typedef struct t_eventfull_subs
{
  int llid;
  int tid;
  struct t_eventfull_subs *prev;
  struct t_eventfull_subs *next;
} t_eventfull_subs;

static t_eventfull_subs *head_eventfull_subs;
static int glob_rss_shift;
static unsigned long glob_total_ram;
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static int get_rss_shift(void)
{
  int shift = 0;
  long size;
  if ((size = sysconf(_SC_PAGESIZE)) == -1)
    {
    printf("ERROR SYSCONF\n");
    KERR(" ");
    exit(-1);
    }
  size >>= 10;
  while (size > 1)
    {
    shift++;
    size >>= 1;
    }
  return shift;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static unsigned long get_totalram_kb(void)
{
  unsigned long result;
  struct sysinfo sys_info;
  if (sysinfo(&sys_info))
    {
    printf("ERROR %s\n", __FUNCTION__);
    KERR(" ");
    exit(-1);
    }
  result = (unsigned long) sys_info.totalram;
  result >>= 10;
  result *= sys_info.mem_unit;
  return result;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static t_pid_info *read_proc_pid_stat(int pid)
{
  static t_pid_info pid_info;
  t_pid_info *result = NULL;
  FILE *fp;
  char filename[MAX_PATH_LEN];
  char *ptr;
  memset(&pid_info, 0, sizeof(t_pid_info));
  sprintf(filename,  "/proc/%u/stat", pid);
  if ((fp = fopen(filename, "r")) != NULL)
    {
    fscanf(fp, STAT_FORMAT, pid_info.comm,
                            &(pid_info.utime),  &(pid_info.stime),
                            &(pid_info.cutime), &(pid_info.cstime),
                            &(pid_info.rss));
    fclose(fp);
    pid_info.rss = ((pid_info.rss) << glob_rss_shift);
    ptr = strchr(pid_info.comm, ')');
    if (ptr)
      {
      *ptr = 0;
      result = &pid_info;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timeout_delete_vm(void *data)
{
  char *name = data;
  t_vm *vm = cfg_get_vm(name);
  if (vm)
    {
    if (!vm->vm_to_be_killed)
      {
      event_print("The pid was not found in the /proc, KILLING machine %s", 
                  vm->vm_params.name);
      KERR("PID NOT FOUND %s", vm->vm_params.name);
      machine_death(vm->vm_params.name, error_death_nopid);
      }
    }
  clownix_free(data, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_pid_info *read_proc_all_pids_stat(t_vm *vm)
{
  t_pid_info *pifo;
  pifo = read_proc_pid_stat(vm->pid);
  return pifo;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int update_pid_infos(t_vm *vm)
{
  static int not_first_time = 0;
  int result = -1;
  char *name;
  unsigned long mem, tot_utime;
  t_pid_info *pid_info;
  if (!vm->pid)
    result = 0;
  else
    {
    pid_info = read_proc_all_pids_stat(vm);
    if (!pid_info)
      {
      name = (char *) clownix_malloc(MAX_NAME_LEN, 13);
      memset(name, 0, MAX_NAME_LEN);
      strncpy(name, vm->vm_params.name, MAX_NAME_LEN-1);
      clownix_timeout_add(1, timeout_delete_vm, (void *)name, NULL, NULL);
      }
    else
      {
      result = 0;
      mem = pid_info->rss;
      tot_utime =  (pid_info->utime  - vm->previous_utime)  +
                   (pid_info->cutime - vm->previous_cutime) +
                   (pid_info->stime  - vm->previous_stime)  +
                   (pid_info->cstime - vm->previous_cstime) ;
      vm->previous_utime   = pid_info->utime;
      vm->previous_cutime  = pid_info->cutime;
      vm->previous_stime   = pid_info->stime;
      vm->previous_cstime  = pid_info->cstime;
      if (not_first_time) 
        {
        vm->ram = (mem*40)/(glob_total_ram/100);
        vm->cpu = (int) 2*tot_utime;
        vm->mem_rss = mem;
        }
      else
        not_first_time = 1;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int helper_collect_sat(t_eventfull_sat *eventfull, int nb, t_tux *tux)
{
  int i, j;
  t_tux *cur = tux;
  for (i=0, j=0; i<nb; i++)
    {
    if (!cur)
      KOUT(" ");
    if (cur->is_musat)
      {
      strncpy(eventfull[j].name, cur->name, MAX_NAME_LEN-1);
      eventfull[j].sat_is_ok = cur->c2c_info.is_peered;
      eventfull[j].pkt_rx0 = cur->lan_attached[0].eventfull_rx_p;
      eventfull[j].pkt_tx0 = cur->lan_attached[0].eventfull_tx_p;
      eventfull[j].pkt_rx1 = cur->lan_attached[1].eventfull_rx_p;
      eventfull[j].pkt_tx1 = cur->lan_attached[1].eventfull_tx_p;
      j++;
      cur->lan_attached[0].eventfull_rx_p = 0;
      cur->lan_attached[0].eventfull_tx_p = 0;
      cur->lan_attached[1].eventfull_rx_p = 0;
      cur->lan_attached[1].eventfull_tx_p = 0;
      }
    cur = cur->next;
    }
  if (cur)
    KOUT(" ");
  return j;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void helper_collect(t_eventfull_vm *eventfull, int nb, t_vm *head_vm) 
{
  int i, j;
  t_vm *cur = head_vm;
  t_eth *cur_eth;
  for (i=0; i<nb; i++)
    {
    if (!cur)
      KOUT(" ");
    strncpy(eventfull[i].name, cur->vm_params.name, MAX_NAME_LEN-1);
    eventfull[i].nb_eth = cur->nb_eth;
    eventfull[i].ram = cur->ram;
    eventfull[i].cpu = cur->cpu;
    cur_eth = cur->eth_head;
    for (j=0; j<cur->nb_eth; j++)
      {
      if (!cur_eth)
        KOUT(" ");
      eventfull[i].eth[j].eth = cur_eth->eth;
      eventfull[i].eth[j].pkt_rx = cur_eth->lan_attached.eventfull_rx_p; 
      eventfull[i].eth[j].pkt_tx = cur_eth->lan_attached.eventfull_tx_p;
      cur_eth->lan_attached.eventfull_rx_p = 0;
      cur_eth->lan_attached.eventfull_tx_p = 0;
      cur_eth = cur_eth->next;  
      }
    if (cur_eth)
      KOUT(" ");
    cur = cur->next;
    }
  if (cur)
    KOUT(" ");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void refresh_ram_cpu_vm(int nb, t_vm *head_vm)
{
  int i;
  t_vm *cur = head_vm;
  for (i=0; i<nb; i++)
    {
    if (!cur)
      KOUT(" ");
    if (!cur->vm_to_be_killed)
      {
      if (update_pid_infos(cur))
        event_print("PROBLEM FOR %s", cur->vm_params.name);
      }
    cur = cur->next;
    }
  if (cur)
    KOUT(" ");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void timeout_collect_eventfull(void *data)
{
  static int count = 0;
  t_eventfull_vm *eventfull_vm;
  t_eventfull_sat *eventfull_sat;
  int nb_vm, nb_tux, nb_sat, llid, tid;
  t_vm *vm   = cfg_get_first_vm(&nb_vm);
  t_tux *tux = cfg_get_first_tux(&nb_tux);
  t_eventfull_subs *cur = head_eventfull_subs;
  eventfull_vm = 
      (t_eventfull_vm *) clownix_malloc(nb_vm * sizeof(t_eventfull_vm), 13);
  memset(eventfull_vm, 0, nb_vm * sizeof(t_eventfull_vm));
  eventfull_sat = 
      (t_eventfull_sat *) clownix_malloc(nb_tux * sizeof(t_eventfull_sat), 13);
  memset(eventfull_sat, 0, nb_tux * sizeof(t_eventfull_sat));
  count++;
  if (count == 10)
    {
    refresh_ram_cpu_vm(nb_vm, vm);
    count = 0;
    }
  helper_collect(eventfull_vm, nb_vm, vm); 
  nb_sat = helper_collect_sat(eventfull_sat, nb_tux, tux); 
  while (cur)
    {
    llid = cur->llid;
    tid = cur->tid;
    if (msg_exist_channel(llid))
      {
      send_eventfull(llid, tid, nb_vm, eventfull_vm, 
                                nb_sat, eventfull_sat);
      }
    else
      event_print ("EVENTFULL ERROR!!!!!!");
    cur = cur->next;
    }
  clownix_timeout_add(20, timeout_collect_eventfull, NULL, NULL, NULL);
  clownix_free(eventfull_vm, __FUNCTION__); 
  clownix_free(eventfull_sat, __FUNCTION__); 
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_eventfull_sub(int llid, int tid)
{
  t_eventfull_subs *sub;
  sub = (t_eventfull_subs *) clownix_malloc(sizeof(t_eventfull_subs), 13);
  memset(sub, 0, sizeof(t_eventfull_subs));
  sub->llid = llid;
  sub->tid = tid;
  if (head_eventfull_subs)
    head_eventfull_subs->prev = sub;
  sub->next = head_eventfull_subs;
  head_eventfull_subs = sub;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void eventfull_llid_delete(int llid)
{
  t_eventfull_subs *next, *cur = head_eventfull_subs;
  while(cur)
    {
    next = cur->next;
    if (cur->llid == llid)
      {
      if (cur->prev)
        cur->prev->next = cur->next;
      if (cur->next)
        cur->next->prev = cur->prev;
      if (cur == head_eventfull_subs)
        head_eventfull_subs = cur->next;
      clownix_free(cur, __FUNCTION__);
      }
    cur = next;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void eventfull_init(void)
{
  head_eventfull_subs = NULL;
  clownix_timeout_add(500, timeout_collect_eventfull, NULL, NULL, NULL);
  glob_rss_shift = get_rss_shift();
  glob_total_ram = get_totalram_kb();
}
/*---------------------------------------------------------------------------*/



