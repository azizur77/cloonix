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
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>


#include "io_clownix.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "commun_daemon.h"
#include "heartbeat.h"
#include "machine_create.h"
#include "event_subscriber.h"
#include "pid_clone.h"
#include "system_callers.h"
#include "lan_to_name.h"
#include "doors_rpc.h"
#include "utils_cmd_line_maker.h"
#include "automates.h"
#include "llid_trace.h"
#include "cdrom_creation_clone.h"
#include "qmonitor.h"
#include "qmp.h"
#include "qhvc0.h"
#include "doorways_mngt.h"
#include "c2c.h"
#include "endp_mngt.h"
#include "stats_counters.h"
#include "stats_counters_sysinfo.h"





void uml_vm_automaton(void *unused_data, int status, char *name);
void qemu_vm_automaton(void *unused_data, int status, char *name);


/*****************************************************************************/
typedef struct t_action_rm_dir
{
  int llid;
  int tid;
  int vm_id;
  char name[MAX_NAME_LEN];
} t_action_rm_dir;
/*---------------------------------------------------------------------------*/
typedef struct t_vm_building
{
  int llid;
  int tid;
  t_topo_kvm kvm;
  int vm_id;
  int ref_jfs;
  void *jfs;
  int type_eth;
  int llid_eth[MAX_ETH_VM+2];
} t_vm_building;
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void death_of_rmdir_clone(void *data, int status, char *name)
{
  t_action_rm_dir *act = (t_action_rm_dir *) data;
  int result;
  if (cfg_is_a_zombie(act->name))
    {
    cfg_del_zombie(act->name);
    result = status;
    }
  else
    KOUT(" ");
  event_print("End erasing %s data status %d", act->name, result);
  event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
  dec_lock_self_destruction_dir();
  clownix_free(act, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int rmdir_clone(void *data)
{
  int result = 0;
  char info[MAX_PRINT_LEN];
  t_action_rm_dir *act = (t_action_rm_dir *) data;
  info[0] = 0;
  if (rm_machine_dirs(act->vm_id, info))
    {
    sleep(1);
    if (rm_machine_dirs(act->vm_id, info))
      {
      sleep(1);
      if (rm_machine_dirs(act->vm_id, info))
        {
        KERR(" %s ", info);
        result = -1;
        }
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void action_rm_dir_timed(void *data)
{
  t_action_rm_dir *act = (t_action_rm_dir *) data;
  pid_clone_launch(rmdir_clone, death_of_rmdir_clone, NULL,
                   (void *) act, (void *) act, NULL, act->name, -1, 1);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static void timeout_erase_dir_zombie(int vm_id, char *name)
{
  t_action_rm_dir *act;
  act = (t_action_rm_dir *) clownix_malloc(sizeof(t_action_rm_dir),12);
  memset(act, 0, sizeof(t_action_rm_dir));
  act->vm_id = vm_id; 
  strcpy(act->name, name);
  clownix_timeout_add(500, action_rm_dir_timed, (void *) act, NULL, NULL);
  inc_lock_self_destruction_dir();
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void delayed_vm_cutoff(void *data)
{
  int pid;
  char *name = (char *) data;
  t_vm *vm = cfg_get_vm(name);
  int vm_id;
  if (vm)
    {
    pid = utils_get_pid_of_machine(vm);
    if (pid)
      {
      KERR("Brutal kill of %s", vm->kvm.name);
      kill(pid, SIGTERM);
      }
    vm_id = cfg_unset_vm(vm);
    cfg_free_vm_id(vm_id);
    event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    }
  clownix_free(data, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void arm_delayed_vm_cutoff(char *name)
{
  char *vmn;
  vmn = clownix_malloc(MAX_NAME_LEN, 13);
  memset (vmn, 0, MAX_NAME_LEN);
  strncpy(vmn, name, MAX_NAME_LEN-1);
  clownix_timeout_add(400, delayed_vm_cutoff,(void *)vmn, NULL, NULL);
}
/*---------------------------------------------------------------------------*/
    
/*****************************************************************************/
void timeout_start_vm_create_automaton(void *data)
{
  char *vm_name = (char *) data;
  t_vm   *vm = cfg_get_vm(vm_name);
  t_wake_up_eths *wake_up_eths;
  if (vm)
    {
    wake_up_eths = vm->wake_up_eths;
    if (wake_up_eths)
      {
      if (strcmp(wake_up_eths->name, vm_name))
        KOUT("%s %s", wake_up_eths->name, vm_name);
      else 
        qemu_vm_automaton(NULL, 0, vm->kvm.name);
      }
    }
  clownix_free(data, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void start_lock_and_watchdog(int llid, int tid, t_vm *vm, char *err)
{
  t_wake_up_eths *data;
  if (!vm)
    KOUT(" ");
  utils_chk_my_dirs(vm);
  event_print("Making cmd line for %s", vm->kvm.name);
  data = (t_wake_up_eths *) clownix_malloc(sizeof(t_wake_up_eths), 13);
  memset(data, 0, sizeof(t_wake_up_eths));
  data->state = 0;
  data->llid = llid;
  data->tid = tid;
  strcpy(data->name, vm->kvm.name);
  vm->wake_up_eths = data;
  cfg_set_vm_locked(vm);
  cdrom_config_creation_request(vm, vm->kvm.nb_eth, 
                               vm->kvm.vm_config_flags);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int run_linux_virtual_machine(int llid, int tid, char *name, 
                              t_vm *vm, char *err)
{
  int result = -1;
  if (umid_pid_already_exists(vm->kvm.vm_id))
    {
    sprintf( err, "Machine %s seems to be running already", name);
    event_print("Machine %s seems to be running already", name);
    KERR(" ");
    }
  else
    {
    start_lock_and_watchdog(llid, tid, vm, err);
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int kerr_upon_missing_dir(char *name, char *dir)
{
  int result = 0;
  struct stat stat_file;
  if (stat(dir, &stat_file))
    {
    KERR("%s %s %d", name, dir, errno);
    result = -1;
    }
  else if (!S_ISDIR(stat_file.st_mode))
    {
    KERR("%s %s", name, dir);
    result = -1;
    }
  else if ((stat_file.st_mode & S_IRWXU) != S_IRWXU)
    {
    KERR("%s %s %X", name, dir, stat_file.st_mode);
    result = -1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int missing_dir(char *name, int vm_id)
{
  int result = 0;
  char path[MAX_PATH_LEN];
  snprintf(path, MAX_PATH_LEN-1, "%s", cfg_get_work_vm(vm_id));
  if (kerr_upon_missing_dir(name, path))
    result = 1;
  snprintf(path, MAX_PATH_LEN-1, "%s/%s", cfg_get_work_vm(vm_id), DIR_CONF);
  if (kerr_upon_missing_dir(name, path))
    result = 1;
  snprintf(path, MAX_PATH_LEN-1, "%s", utils_dir_conf_tmp(vm_id));
  if (kerr_upon_missing_dir(name, path))
    result = 1;
  snprintf(path, MAX_PATH_LEN-1, "%s", utils_get_disks_path_name(vm_id));
  if (kerr_upon_missing_dir(name, path))
    result = 1;
  snprintf(path, MAX_PATH_LEN-1, "%s/%s", cfg_get_work_vm(vm_id),  DIR_UMID);
  if (kerr_upon_missing_dir(name, path))
    result = 1;
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void death_of_mkdir_clone(void *data, int status, char *name)
{
  char err[MAX_PATH_LEN];
  t_vm *vm;
  t_vm_building *vm_building = (t_vm_building *) data;
  cfg_del_newborn(name);
  if (status)
    {
    sprintf(err,"Path: \"%s\" pb creating directory", 
                cfg_get_work_vm(vm_building->vm_id));
    send_status_ko(vm_building->llid, vm_building->tid, err);
    clownix_free(vm_building,  __FUNCTION__);
    }
  else if (missing_dir(vm_building->kvm.name, vm_building->vm_id))
    {
    sprintf(err,"Bad vm %s dir creation", vm_building->kvm.name);
    send_status_ko(vm_building->llid, vm_building->tid, err);
    clownix_free(vm_building,  __FUNCTION__);
    }
  else
    {
    event_print("Directories for %s created", vm_building->kvm.name);
    cfg_set_vm(&(vm_building->kvm),
                vm_building->vm_id, vm_building->llid);
    vm = cfg_get_vm(vm_building->kvm.name);
    if (!vm)
      KOUT(" ");

    if (!run_linux_virtual_machine(vm_building->llid, vm_building->tid,
                                   vm_building->kvm.name, vm, err))
      event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    else
      {
      send_status_ko(vm_building->llid, vm_building->tid, err);
      machine_death(vm_building->kvm.name, error_death_run);
      }
    }
  recv_coherency_unlock();
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int mkdir_clone(void *data)
{
  int result;
  t_vm_building *vm_building = (t_vm_building *) data;
  result = mk_machine_dirs(vm_building->kvm.name, vm_building->vm_id);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void machine_recv_add_vm(int llid, int tid, t_topo_kvm *kvm, int vm_id)
{
  t_vm_building *vm_building;
  vm_building = (t_vm_building *) clownix_malloc(sizeof(t_vm_building), 16);
  memset(vm_building, 0, sizeof(t_vm_building));
  vm_building->llid = llid;
  vm_building->tid  = tid;
  memcpy(&(vm_building->kvm), kvm, sizeof(t_topo_kvm));
  vm_building->vm_id  = vm_id;
  pid_clone_launch(mkdir_clone, death_of_mkdir_clone, NULL,
                   (void *) vm_building, (void *) vm_building, NULL, 
                   vm_building->kvm.name, -1, 1);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int machine_death( char *name, int error_death)
{
  int result = -1;
  t_vm *vm = cfg_get_vm(name);
  if (!vm)
    return result;
  if ((error_death) && 
      (error_death != error_death_qmp) &&
      (error_death != error_death_qmonitor))
    {
    if (error_death == error_death_timeout_hvc0_silent)
      KERR("%s KILLED BECAUSE OF NO hvc0 IN GUEST", name);
    else if (error_death == error_death_timeout_hvc0_conf)
      KERR("%s KILLED BECAUSE OF NO AUTOLOGING IN hvc0 CONF", name);
    else
      KERR("%s %s %d ", __FUNCTION__, name, error_death);
    }
  if (vm->vm_to_be_killed == 0)
    {
    vm->vm_to_be_killed = 1;
    doors_send_del_vm(get_doorways_llid(), 0, name);
    qhvc0_end_qemu_unix(name);
    qmonitor_end_qemu_unix(name);
    qmp_request_qemu_halt(name, 0, 0);
    arm_delayed_vm_cutoff(name);
    if (vm->pid_of_cp_clone)
      {
      KERR("CP ROOTFS SIGKILL %s, PID %d", name, vm->pid_of_cp_clone);
      kill(vm->pid_of_cp_clone, SIGKILL);
      vm->pid_of_cp_clone = 0;
      }
    if (!cfg_is_a_zombie(name))
      {
      result = 0;
      stats_counters_sysinfo_vm_death(name);
      cfg_add_zombie(vm->kvm.vm_id, name);
      if (!cfg_get_vm_locked(vm))
        {
        if (vm->wake_up_eths != NULL)
          KOUT(" ");
        timeout_erase_dir_zombie(vm->kvm.vm_id, name);
        }
      else
        {
        if (vm->wake_up_eths == NULL)
          KOUT(" ");
        vm->vm_to_be_killed = 0;
        vm->wake_up_eths->destroy_requested = 1;
        clownix_timeout_del(vm->wake_up_eths->abs_beat,vm->wake_up_eths->ref,
                            __FILE__, __LINE__);
        clownix_timeout_add(1, utils_vm_create_fct_abort,(void *)vm,
                      &(vm->wake_up_eths->abs_beat),&(vm->wake_up_eths->ref));
        }
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void machine_recv_kill_clownix(void)
{
  int i, nb;
  char name[MAX_NAME_LEN];
  t_vm *vm = cfg_get_first_vm(&nb);
  t_vm *next_vm;
  for (i=0; i<nb; i++)
    {
    if (!vm)
      KOUT(" ");
    next_vm = vm->next;
    strcpy(name, vm->kvm.name);
    machine_death(name, error_death_noerr);
    vm = next_vm;
    }
  if (vm) 
    KOUT(" ");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void dtach_duplicate_clone_msg(void *data, char *msg)
{
  char dtach_name[MAX_NAME_LEN+2];
  t_check_dtach_duplicate *dtach = (t_check_dtach_duplicate *) data;
  memset(dtach_name, 0, MAX_NAME_LEN+2);
  snprintf(dtach_name, MAX_NAME_LEN+1, "%s: ", dtach->name);
  if (!strncmp(msg, dtach_name, strlen(dtach_name)))
    strcpy(dtach->msg, "DUPLICATE");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void dtach_duplicate_clone_death(void *data, int status, char *name)
{
  t_check_dtach_duplicate *dtach = (t_check_dtach_duplicate *) data;
  if (!dtach->cb)
    KOUT(" ");
  if (!strcmp(dtach->msg, "DUPLICATE"))
    dtach->cb(-1, dtach->name);
  else
    dtach->cb(0, dtach->name);
  clownix_free(data, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int dtach_duplicate_clone(void *data)
{
  t_check_dtach_duplicate *dtach = (t_check_dtach_duplicate *) data;
  char *cmd = utils_get_dtach_bin_path();
  char *sock = utils_get_dtach_sock_path(dtach->name);

  char *argv[] = { cmd, "-n", sock, "ls", NULL, };
  my_popen(cmd, argv);
  return 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void dtach_duplicate_check(char *name, t_dtach_duplicate_callback cb)
{
  t_check_dtach_duplicate *dtach;
  int len = sizeof(t_check_dtach_duplicate);
  dtach = (t_check_dtach_duplicate *) clownix_malloc(len, 7);
  memset(dtach, 0, len);
  strncpy(dtach->name, name, MAX_NAME_LEN-1);
  dtach->cb = cb;
  pid_clone_launch(dtach_duplicate_clone, dtach_duplicate_clone_death,
                   dtach_duplicate_clone_msg, NULL, dtach, dtach, name, -1, 1);
}
/*---------------------------------------------------------------------------*/


