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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "commun_daemon.h"
#include "heartbeat.h"
#include "machine_create.h"
#include "event_subscriber.h"
#include "pid_clone.h"
#include "system_callers.h"
#include "automates.h"
#include "lan_to_name.h"
#include "utils_cmd_line_maker.h"
#include "file_read_write.h"
#include "qmonitor.h"
#include "qmp.h"
#include "doorways_mngt.h"
#include "doors_rpc.h"
#include "timeout_service.h"
#include "c2c.h"
#include "dropbear.h"
#include "sav_vm.h"
#include "mulan_mngt.h"
#include "mueth_events.h"
#include "musat_mngt.h"
#include "musat_events.h"
#include "hop_event.h"
#include "c2c_utils.h"


void activate_deactivate_all_snf_capture(t_tux *tux);


int produce_list_commands(t_list_commands *list);

static void recv_del_vm(int llid, int tid, char *name);
static void recv_halt_vm(int llid, int tid, char *name);
static void recv_reboot_vm(int llid,int tid,char *name,int is_cloonix_reboot);
static void recv_promiscious(int llid, int tid, char *name, int eth, int on);



int inside_cloonix(char **name);

extern int clownix_server_fork_llid;
void local_recv_add_lan_eth(int llid, int tid, char *name, 
                             int eth, char *lan);

static int g_in_cloonix;
static char *g_cloonix_vm_name;

int file_exists(char *path, int mode);


/*****************************************************************************/
typedef struct t_coherency_delay
{
  int llid;
  int tid;
  int eth;
  char name[MAX_NAME_LEN];
  char lan[MAX_NAME_LEN];
  struct t_coherency_delay *prev;
  struct t_coherency_delay *next;
} t_coherency_delay;
/*---------------------------------------------------------------------------*/
typedef struct t_add_vm_cow_look
{
  char msg[MAX_PRINT_LEN];
  int llid;
  int tid;
  int vm_id;
  t_vm_params vm_params;
} t_add_vm_cow_look;
/*---------------------------------------------------------------------------*/

static int glob_coherency;
static t_coherency_delay *g_head_coherency;
static long long g_coherency_abs_beat_timer;
static int g_coherency_ref_timer;
static int g_inhib_new_clients;


/*****************************************************************************/
static int get_inhib_new_clients(void)
{
  if (g_inhib_new_clients)
    {
    KERR("Server being killed, no new client");
    event_print("Server being killed, no new client");
    }
  return g_inhib_new_clients;
}
/*---------------------------------------------------------------------------*/
  


/*****************************************************************************/
void recv_coherency_unlock(void)
{
  glob_coherency -= 1;
  if (glob_coherency < 0)
    KOUT(" ");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_coherency_lock(void)
{
  glob_coherency += 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int recv_coherency_locked(void)
{
  return glob_coherency;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_coherency_delay *coherency_add_chain(int llid, int tid, 
                                              char *name, int eth, char *lan)
{
  t_coherency_delay *cur, *elem;
  elem = (t_coherency_delay *) clownix_malloc(sizeof(t_coherency_delay), 16);
  memset(elem, 0, sizeof(t_coherency_delay));
  elem->llid = llid;
  elem->tid = tid;
  elem->eth = eth;
  strcpy(elem->name, name);
  strcpy(elem->lan, lan);
  if (g_head_coherency)
    {
    cur = g_head_coherency;
    while (cur && cur->next)
      cur = cur->next;
    cur->next = elem;
    elem->prev = cur;
    }
  else
    g_head_coherency = elem;
  return g_head_coherency;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void coherency_del_chain(t_coherency_delay *cd)
{
  if (cd->prev)
    cd->prev->next = cd->next;
  if (cd->next)
    cd->next->prev = cd->prev;
  if (cd == g_head_coherency)
    g_head_coherency = cd->next;
  clownix_free(cd, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void delayed_coherency_cmd_timeout(void *data)
{
  t_coherency_delay *next, *cur = (t_coherency_delay *) data;
  g_coherency_abs_beat_timer = 0;
  g_coherency_ref_timer = 0;
  if (g_head_coherency != cur)
    KOUT(" ");
  if (recv_coherency_locked())
    clownix_timeout_add(20, delayed_coherency_cmd_timeout, data, 
                        &g_coherency_abs_beat_timer, &g_coherency_ref_timer);
  else
    {
    while (cur)
      {
      next = cur->next;
      local_recv_add_lan_eth(cur->llid, cur->tid, cur->name, 
                              cur->eth, cur->lan);
      coherency_del_chain(cur);
      cur = next;
      }
    }
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void recv_work_dir_req(int llid, int tid)
{
  t_cloonix_config *conf = cfg_get_cloonix_config();
  send_work_dir_resp(llid, tid, conf);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void recv_promiscious(int llid, int tid, char *name, int eth, int on)
{
  char info[MAX_PRINT_LEN];
  t_vm *vm;
  vm = cfg_get_vm(name);
  event_print("Rx Req promisc %d for  %s eth%d", on, name, eth);
  if (!vm)
    {
    sprintf( info, "Machine %s does not exist", name);
    send_status_ko(llid, tid, info);
    }
  else if ((eth < 0) || (eth >= vm->vm_params.nb_eth))
    {
    sprintf( info, "eth%d for machine %s does not exist", eth, name);
    send_status_ko(llid, tid, info);
    }
  else
    {
    vm->vm_params.eth_params[eth].is_promisc = on;
    sprintf( info, "Promisc %d for %s eth%d", on, name, eth);
    send_status_ok(llid, tid, info);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_vmcmd(int llid, int tid, char *name, int cmd, int param)
{
  switch(cmd)
    {
    case vmcmd_del:
      recv_del_vm(llid, tid, name);
      break;
    case vmcmd_halt:
      recv_halt_vm(llid, tid, name);
      break;
    case vmcmd_reboot_with_cloonix_agent:
      recv_reboot_vm(llid, tid, name, 1);
      break;
    case vmcmd_reboot_with_qemu:
      recv_reboot_vm(llid, tid, name, 0);
      break;
    case vmcmd_promiscious_flag_set:
      recv_promiscious(llid, tid, name, param, 1);
      break;
    case vmcmd_promiscious_flag_unset:
      recv_promiscious(llid, tid, name, param, 0);
      break;
    default:
      KERR("%d", cmd);
      break;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int machine_not_ready(char *name)
{
  int result = -1;
  t_vm *vm = cfg_get_vm(name);
  if (vm)
    {
    if (!cfg_is_a_zombie(name))
      result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void local_recv_add_lan_eth(int llid, int tid, char *name, 
                             int eth, char *lan)
{
  char info[MAX_PRINT_LEN];
  t_vm *vm;
  vm = cfg_get_vm(name); 
  event_print("Rx Req add lan %s in %s eth%d", lan, name, eth);

  if (!vm) 
    {
    sprintf( info, "Machine %s does not exist", name);
    send_status_ko(llid, tid, info);
    }
  else if (machine_not_ready(name))
    {
    sprintf( info, "Machine %s not ready", name);
    send_status_ko(llid, tid, info);
    }
  else if (cfg_get_eth(name, eth)) 
    {
    sprintf( info, "Interface %s  eth%d does not exist", name, eth);
    send_status_ko(llid, tid, info);
    }
  else if (mulan_is_zombie(lan))
    {
    sprintf( info, "lan %s is zombie",  lan);
    send_status_ko(llid, tid, info);
    }
  else
    {
    mueth_event_admin_add_lan(llid, tid, name, eth, lan);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void add_lan_eth(int llid, int tid, char *name, int eth, char *lan)
{
  char use[MAX_PATH_LEN];
  if (get_inhib_new_clients())
    send_status_ko(llid, tid, "AUTODESTRUCT_ON");
  else if (cfg_name_is_in_use(1, lan, use))
    send_status_ko(llid, tid, use);
  else
    {
    if (recv_coherency_locked())
      {
      g_head_coherency = coherency_add_chain(llid, tid, name, eth, lan);
      if (!g_coherency_abs_beat_timer)
        clownix_timeout_add(20, delayed_coherency_cmd_timeout, 
                            (void *) g_head_coherency, 
                            &g_coherency_abs_beat_timer, 
                            &g_coherency_ref_timer);
      }
    else
      local_recv_add_lan_eth(llid, tid, name, eth, lan);
    }
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void recv_evt_print_sub(int llid, int tid)
{
  event_print("Rx Req subscribing to print for client: %d", llid);
  if (msg_exist_channel(llid))
    {
    event_subscribe(sub_evt_print, llid, tid);
    send_status_ok(llid, tid, "printsub");
    }
  else
    send_status_ko(llid, tid, "Abnormal!");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_event_topo_sub(int llid, int tid)
{
  event_print("Rx Req subscribing to topology for client: %d", llid);
  if (msg_exist_channel(llid))
    {
    event_subscribe(sub_evt_topo, llid, tid);
    event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    }
  else
    send_status_ko(llid, tid, "Abnormal!");
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static void del_lan_eth(int llid, int tid, t_vm *vm, int eth, char *lan)
{
  char info[MAX_PRINT_LEN];
  int lan_num;
  char *name = vm->vm_params.name;
  event_print("Rx Req del lan %s in %s eth%d", lan, name, eth);
  if (!vm)
    {
    sprintf(info, "ethvdel %s %d %s", name, eth, lan);
    send_status_ok(llid, tid, info);
    }
  else
    {
    if (machine_not_ready(name))
      {
      sprintf(info, "ethvdel %s %d %s", name, eth, lan);
      send_status_ok(llid, tid, info);
      }
    else if (!cfg_get_eth(name, eth))
      {
      lan_num = lan_get_with_name(lan);
      if (!lan_num)
        {
        sprintf(info, "lan %s does not exist", lan);
        send_status_ko(llid, tid, info);
        }
      else if (mueth_event_admin_del_lan(name, eth, lan))
        {
        sprintf(info, "lan %s eth%d  lan %s not found", name, eth, lan);
        send_status_ko(llid, tid, info);
        }
      else
        {
        sprintf(info, "ethvdel %s %d %s", name, eth, lan);
        send_status_ok(llid, tid, info);
        event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
        }
      }
    else
      {
      sprintf(info, "Interface %s eth%d not found", name, eth);
      send_status_ko(llid, tid, info);
      }
    }
}
/*---------------------------------------------------------------------------*/




/*****************************************************************************/
void recv_add_lan_sat(int llid, int tid, char *sat, char *lan, int num)
{
  int type;
  char use[MAX_PATH_LEN];
  t_sc2c *c2c = c2c_find(sat);
  t_vm *vm = cfg_get_vm(sat); 
  event_print("Rx Req add lan %s %d in %s", lan, num, sat);
  if (get_inhib_new_clients())
    send_status_ko(llid, tid, "AUTODESTRUCT_ON");
  else if (cfg_name_is_in_use(1, lan, use))
    send_status_ko(llid, tid, use);
  else if (vm)
    add_lan_eth(llid, tid, sat, num, lan);
  else if (c2c)
    c2c_add_lan(llid, tid, sat, lan);
  else if (!musat_mngt_exists(sat, &type))
    send_status_ko(llid, tid, "sat not found");
  else
    {
    if (lan_musat_locked(sat, num))
      send_status_ko(llid, tid, "sat already in a ulan");
    else
      {
      musat_event_admin_add_lan(llid, tid, sat, num, lan);
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_del_lan_sat(int llid, int tid, char *sat, char *lan, int num)
{
  char info[MAX_PRINT_LEN];
  int lan_num, type;
  char *attached_lan;
  t_vm *vm = cfg_get_vm(sat); 
  t_sc2c *c2c = c2c_find(sat);
  event_print("Rx Req del lan %s of %s %d", lan, sat, num);
  lan_num = lan_get_with_name(lan);
  if (!lan_num)
    send_status_ko(llid, tid, "lan does not exist");
  else if (vm)
    del_lan_eth(llid, tid, vm, num, lan);
  else if (c2c)
    c2c_del_lan(llid, tid, sat, lan);
  else if (!musat_mngt_exists(sat, &type))
    send_status_ko(llid, tid, "sat not found");
  else if (!(lan_musat_locked(sat, num)))
    send_status_ko(llid, tid, "not attached sat");
  else
    {
    attached_lan = musat_get_attached_lan(sat, num);
    if (!attached_lan)
      send_status_ko(llid, tid, "sat has no lan");
    else if (strcmp(attached_lan, lan))
      send_status_ko(llid, tid, "sat not attached to this lan");
    else if (musat_event_admin_del_lan(sat, num, lan))
      {
      sprintf(info, "lan %s not found in %s", lan, sat);
      send_status_ko(llid, tid, info);
      }
    else
      {
      sprintf(info, "tuxvdel %s %s %d", sat, lan, num);
      send_status_ok(llid, tid, info);
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_kill_uml_clownix(int llid, int tid)
{
  g_inhib_new_clients = 1;
  event_print("Rx Req Self-Destruction");
  mulan_del_all();
  musat_mngt_stop_all();
  c2c_free_all();
  machine_recv_kill_clownix();
  auto_self_destruction(llid, tid);
  doors_send_command(get_doorways_llid(), 0, "noname", STOP_DOORS_LISTENING);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int test_machine_is_kvm_able(void)
{
  int found = 0;
  FILE *fhd;
  char *result = NULL;
  fhd = fopen("/proc/cpuinfo", "r");
  if (fhd)
    {
    result = (char *) malloc(500);
    while(!found)
      {
      if (fgets(result, 500, fhd) != NULL)
        {
        if (!strncmp(result, "flags", strlen("flags")))
          found = 1;
        }
      else
        KOUT(" ");
      }
    fclose(fhd);
    }
  if (!found)
    KOUT(" ");
  found = 0;
  if ((strstr(result, "vmx")) || (strstr(result, "svm")))
    found = 1;
  free(result);
  return found;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static int i_have_read_write_access(char *path)
{
  return ( ! access(path, R_OK|W_OK) );
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static char *read_sys_file(char *file_name, char *err)
{
  char *buf = NULL;
  int fd;
  fd = open(file_name, O_RDONLY);
  if (fd > 0)
    {
    buf = (char *) clownix_malloc(100,13);
    read(fd, buf, 99);
    buf[99] = 0;
    close (fd);
    }
  else
    sprintf(err, "Cannot open file %s\n", file_name);
  return buf;
}
/*--------------------------------------------------------------------------*/

#define SYS_KVM_DEV "/sys/devices/virtual/misc/kvm/dev"
/*****************************************************************************/
static int get_dev_kvm_major_minor(int *major, int *minor, char *info)
{
  int result = -1;
  char err[MAX_PATH_LEN];
  char *buf;
  if (file_exists(SYS_KVM_DEV, F_OK))
    {
    buf = read_sys_file(SYS_KVM_DEV, err);
    if (buf)
      {
      if (sscanf(buf, "%d:%d", major, minor) == 2)
        result = 0;
      else
        sprintf(info, "UNEXPECTED %s\n", SYS_KVM_DEV);
      }
    else
      sprintf(info, "ERR %s %s\n", SYS_KVM_DEV, err);
    clownix_free(buf, __FUNCTION__);
    }
  else
    sprintf(info,
            "/dev/kvm not found, \"modprobe kvm_intel/kvm_amd nested=1\""
            " and \"chmod 666 /dev/kvm\", (on the real host!)\n");
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int inside_cloonix_test_dev_kvm(char *err)
{
  int major, minor;
  int result = -1;
  char cmd[MAX_PATH_LEN];
  if (!get_dev_kvm_major_minor(&major, &minor, err))
    {
    if (major == 10)
      {
      sprintf(cmd, "/bin/mknod /dev/kvm c %d %d", major, minor);
      if (!clownix_system(cmd))
        {
        result = 0;
        sprintf(cmd, "/bin/chmod 666 /dev/kvm");
        clownix_system(cmd);
        }
      else
        sprintf(err, "/bin/mknod /dev/kvm c %d %d", major, minor);
      }
    else
      sprintf(err, "/dev/kvm: %d:%d major is not 10, something wrong\n",
              major, minor);
    }
  return result;
}
/*---------------------------------------------------------------------------*/



/*****************************************************************************/
static int test_dev_kvm(char *info, int *has_kvm_virt)
{
  int result = -1;
  int fd;
  *has_kvm_virt = 1;
  if (test_machine_is_kvm_able())
    {
    result = 0;
    if (access("/dev/kvm", F_OK))
      {
      if (g_in_cloonix)
        result = inside_cloonix_test_dev_kvm(info);
      else
        {
        sprintf(info, "/dev/kvm not found see \"KVM module\" "
                      "in \"Depends\" chapter of doc");
        result = -1;
        }
      }
    else if (!i_have_read_write_access("/dev/kvm"))
      {
      sprintf(info, "/dev/kvm not writable see \"KVM module\" "
                    "in \"Depends\" chapter of doc");
      result = -1;
      }
    else
      {
      fd = open("/dev/kvm", O_RDWR);
      if (fd < 0)
        {
        sprintf(info, "/dev/kvm not openable  \n");
        result = -1;
        }
      close(fd);
      }

    }
  else
    {
    result = 0;
//    sprintf(info, "Your machine has no hardware virtualisation!\n");
    *has_kvm_virt = 0;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int test_qemu_kvm_wanted_files(t_vm_params *vm_params, char *rootfs, 
                                      char *bzimage, char *info, 
                                      int *has_kvm_virt)
{
  int result = 0;
  char bz_image[MAX_PATH_LEN];
  char qemu_kvm_exe[MAX_PATH_LEN];
  sprintf(qemu_kvm_exe, "%s/server/qemu/%s/%s", 
          cfg_get_bin_dir(), QEMU_BIN_DIR, QEMU_EXE);
  sprintf(bz_image,  "%s/%s", cfg_get_bulk(), bzimage);
  if (test_dev_kvm(info, has_kvm_virt))
    result = -1;
  else if (!file_exists(qemu_kvm_exe, F_OK))
    {
    sprintf(info, "File: \"%s\" not found\n", qemu_kvm_exe);
    result = -1;
    }
  else if (!file_exists(rootfs, F_OK))
    {
    sprintf(info, "File: \"%s\" not found \n", rootfs);
    result = -1;
    }
  else if ((vm_params->vm_config_flags & VM_CONFIG_FLAG_PERSISTENT) &&
           (!file_exists(rootfs, W_OK)))
    {
    sprintf(info, "Persistent write rootfs file: \"%s\" not writable \n", rootfs);
    result = -1;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int test_vm_params(t_vm_params *vm_params, int vm_id, 
                          char *info, int *has_kvm_virt)
{
  int result = 0;
  char rootfs[MAX_PATH_LEN];
  if (vm_params->cpu == 0)
    vm_params->cpu =  1;
  if (vm_params->mem == 0)
    vm_params->mem =  128;
  if (vm_params->vm_config_flags & VM_CONFIG_FLAG_HAS_BDISK)
    {
    if (!file_exists(vm_params->bdisk, F_OK))
      {
      sprintf(info, "File: \"%s\" not found\n", vm_params->bdisk);
      result = -1;
      }
    }
  if (result == 0)
    {
    memset(rootfs, 0, MAX_PATH_LEN);
    if (vm_params->vm_config_flags & VM_CONFIG_FLAG_PERSISTENT)
      {
      strncpy(rootfs, vm_params->rootfs_input, MAX_PATH_LEN-1);
      strncpy(vm_params->rootfs_used, rootfs, MAX_PATH_LEN-1);
      }
    else if (vm_params->vm_config_flags & VM_CONFIG_FLAG_EVANESCENT)
      {
      vm_params->vm_config_flags |= VM_FLAG_DERIVED_BACKING;
      if (file_exists(vm_params->rootfs_input, F_OK))
        {
        snprintf(vm_params->rootfs_backing, MAX_PATH_LEN-1, 
                 "%s", vm_params->rootfs_input);
        }
      else
        {
        snprintf(vm_params->rootfs_backing, MAX_PATH_LEN-1, 
                 "%s", utils_get_root_fs(vm_params->rootfs_input));
        }
      snprintf(vm_params->rootfs_used,MAX_PATH_LEN-1,"%s/derived.qcow2",
               utils_get_disks_path_name(vm_id));
      strncpy(rootfs, vm_params->rootfs_backing, MAX_PATH_LEN-1); 
      }
    else
      KOUT(" ");
    if (!strlen(rootfs))
      {
      result = -1;
      sprintf(info, "BAD rootfs\n");
      }
    else
      {
      result = test_qemu_kvm_wanted_files(vm_params, rootfs,
                                          vm_params->linux_kernel, 
                                          info, has_kvm_virt);
      }
      }
    if (result == 0)
      sprintf(info, "Rx Req add kvm machine %s with %d eth , FLAGS:%s",
              vm_params->name, vm_params->nb_eth, 
              prop_flags_ascii_get(vm_params->vm_config_flags));
  if (!result)
    {
    if (vm_params->nb_eth > MAX_ETH_VM)
      {
      sprintf(info, "Maximum ethernet %d per machine", MAX_ETH_VM);
      result = -1;
      }
    }
  event_print(info);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void cow_look_clone_msg(void *data, char *msg)
{
  char *ptr;
  t_add_vm_cow_look *add_vm = (t_add_vm_cow_look *) data;
  if (!strncmp(msg, "backing file", strlen("backing file")))
    {
    ptr = strchr(msg, '/');
    if (ptr)
      {
      strncpy(add_vm->msg, ptr, MAX_PRINT_LEN-1);
      KERR("%s", add_vm->msg);
      }
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void cow_look_clone_death(void *data, int status, char *name)
{
  t_add_vm_cow_look *add_vm = (t_add_vm_cow_look *) data;
  if (add_vm->msg[0] == '/')
    {
    if (add_vm->vm_params.rootfs_backing[0])
      KERR("%s %s", add_vm->msg,  add_vm->vm_params.rootfs_backing);
    else
      {
      snprintf(add_vm->vm_params.rootfs_backing, MAX_PATH_LEN-1, 
               "%s", add_vm->msg);
      add_vm->vm_params.vm_config_flags |= VM_FLAG_DERIVED_BACKING;
      }
    }
  machine_recv_add_vm(add_vm->llid, add_vm->tid, 
                      &(add_vm->vm_params), add_vm->vm_id);
  clownix_free(data, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int cow_look_clone(void *data)
{
  t_add_vm_cow_look *add_vm = (t_add_vm_cow_look *) data;
  char *cmd = utils_get_qemu_img();
  char rootfs[MAX_PATH_LEN];
  char *argv[] = { cmd, "info", rootfs, NULL, };
  memset(rootfs, 0, MAX_PATH_LEN);
  if (add_vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_PERSISTENT)
    snprintf(rootfs, MAX_PATH_LEN-1, "%s", add_vm->vm_params.rootfs_used);
  else if (add_vm->vm_params.vm_config_flags & VM_FLAG_DERIVED_BACKING)
    snprintf(rootfs, MAX_PATH_LEN-1, "%s", add_vm->vm_params.rootfs_backing); 
  else
    KOUT("%X", add_vm->vm_params.vm_config_flags);
  my_popen(cmd, argv);
  return 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_add_vm(int llid, int tid, t_vm_params *vm_params)
{
  int i, vm_id, has_kvm_virt, result = 0;
  char mac[6];
  char info[MAX_PRINT_LEN];
  t_add_vm_cow_look *cow_look;
  char use[MAX_PATH_LEN];
  t_vm   *vm = cfg_get_vm(vm_params->name);
  info[0] = 0;
  memset(mac, 0, 6);
  if (get_inhib_new_clients())
    send_status_ko(llid, tid, "AUTODESTRUCT_ON");
  else if (cfg_name_is_in_use(0, vm_params->name, use))
    send_status_ko(llid, tid, use);
  else if (vm)
    {
    sprintf(info, "Machine: \"%s\" already exists", vm_params->name);
    event_print("%s", info);
    send_status_ko(llid, tid, info);
    }
  else if (cfg_is_a_zombie(vm_params->name))
    {
    sprintf( info, "Machine: \"%s\" is a zombie", vm_params->name);
    event_print("%s", info);
    send_status_ko(llid, tid, info);
    }
  else if (cfg_is_a_newborn(vm_params->name))
    {
    sprintf( info, "Machine: \"%s\" is a newborn", vm_params->name);
    event_print("%s", info);
    send_status_ko(llid, tid, info);
    }
  else
    {
    cfg_add_newborn(vm_params->name);
    vm_id = cfg_alloc_vm_id();
    event_print("%s was allocated number %d", vm_params->name, vm_id);
    for (i=0; i<vm_params->nb_eth; i++)
      {
      if (!memcmp(vm_params->eth_params[i].mac_addr, mac, 6))
        { 
        if (g_in_cloonix)
          {
          vm_params->vm_config_flags |= VM_FLAG_IS_INSIDE_CLOONIX;
          vm_params->eth_params[i].mac_addr[0] = 0x72;
          }
        else
          {
          vm_params->eth_params[i].mac_addr[0] = 0x2;
          }
        vm_params->eth_params[i].mac_addr[1] = 0xFF & rand();
        vm_params->eth_params[i].mac_addr[2] = 0xFF & rand();
        vm_params->eth_params[i].mac_addr[3] = 0xFF & rand();
        vm_params->eth_params[i].mac_addr[4] = vm_id%100;
        vm_params->eth_params[i].mac_addr[5] = i;
        }
      }
    result = test_vm_params(vm_params, vm_id, info, &has_kvm_virt);
    if (result)
      {
      send_status_ko(llid, tid, info);
      cfg_del_newborn(vm_params->name);
      }
    else 
      {
      vm_params->has_kvm_virt = has_kvm_virt;
      recv_coherency_lock();
      cow_look = (t_add_vm_cow_look *) 
                 clownix_malloc(sizeof(t_add_vm_cow_look), 7);
      memset(cow_look, 0, sizeof(t_add_vm_cow_look));
      cow_look->llid = llid;
      cow_look->tid = tid;
      cow_look->vm_id = vm_id;
      memcpy(&(cow_look->vm_params), vm_params, sizeof(t_vm_params));
      pid_clone_launch(cow_look_clone, cow_look_clone_death,
                       cow_look_clone_msg, cow_look, cow_look, cow_look, 
                       vm_params->name, -1, 1);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void recv_del_vm(int llid, int tid, char *name)
{
  t_vm   *vm = cfg_get_vm(name);
  if (vm)
    {
    event_print("Rx Req del machine %s", name);
    if (machine_death(name, error_death_noerr))
      send_status_ko(llid, tid, "ZOMBI MACHINE");
    else
      send_status_ok(llid, tid, "delvm");
    }
  else
    send_status_ko(llid, tid, "MACHINE NOT FOUND");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_list_commands_req(int llid, int tid)
{
  t_list_commands *list;
  int qty, alloc_len = MAX_LIST_COMMANDS_QTY * sizeof(t_list_commands);
  list = (t_list_commands *) clownix_malloc(alloc_len, 7);
  memset(list, 0, alloc_len);
  qty = produce_list_commands(list);
  send_list_commands_resp(llid, tid, qty, list);
  clownix_free(list, __FILE__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_list_pid_req(int llid, int tid)
{
  int i,j, nb_vm, nb_sat, nb_sum, nb_mulan;
  t_lst_pid *sat_pid = NULL;
  t_lst_pid *mulan_pid = NULL;
  t_vm *vm = cfg_get_first_vm(&nb_vm);
  t_pid_lst *lst;
  event_print("Rx Req list pid");
  nb_sat = musat_mngt_get_all_pid(&sat_pid);
  nb_mulan = mulan_get_all_pid(&mulan_pid);
  nb_sum = nb_vm + nb_sat + nb_mulan + 10;
  lst = (t_pid_lst *)clownix_malloc(nb_sum*sizeof(t_pid_lst),18);
  memset(lst, 0, nb_sum*sizeof(t_pid_lst));
  for (i=0, j=0; i<nb_vm; i++)
    {
    if (!vm)
      KOUT(" ");
    strncpy(lst[j].name, vm->vm_params.name, MAX_NAME_LEN-1); 
    lst[j].pid = machine_read_umid_pid(vm->vm_id);
    j++;
    vm = vm->next;
    }
  if (vm)
    KOUT(" ");
  for (i=0 ; i<nb_sat; i++)
    {
    strncpy(lst[j].name, sat_pid[i].name, MAX_NAME_LEN-1);
    lst[j].pid = sat_pid[i].pid;
    j++;
    }
  clownix_free(sat_pid, __FUNCTION__);
  for (i=0 ; i<nb_mulan; i++)
    {
    strncpy(lst[j].name, mulan_pid[i].name, MAX_NAME_LEN-1);
    lst[j].pid = mulan_pid[i].pid;
    j++;
    }
  clownix_free(mulan_pid, __FUNCTION__);
  strcpy(lst[j].name, "doors");
  lst[j].pid = doorways_get_distant_pid();
  j++;
  strcpy(lst[j].name, "bear");
  lst[j].pid = dropbear_pid();
  j++;
  strcpy(lst[j].name, "switch");
  lst[j].pid = getpid();
  j++;
  send_list_pid_resp(llid, tid, j, lst);
  clownix_free(lst, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_event_sys_sub(int llid, int tid)
{
  event_print("Rx Req subscribing to system counters for client: %d", llid);
  if (msg_exist_channel(llid))
    {
    event_subscribe(sub_evt_sys, llid, tid);
    send_status_ok(llid, tid, "syssub");
    }
  else
    send_status_ko(llid, tid, "Abnormal!");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_event_sys_unsub(int llid, int tid)
{
  event_print("Rx Req unsubscribing from system for client: %d", llid);
  if (msg_exist_channel(llid))
    {
    event_unsubscribe(sub_evt_sys, llid);
    send_status_ok(llid, tid, "sysunsub");
    }
  else
    send_status_ko(llid, tid, "Abnormal!");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_event_topo_unsub(int llid, int tid)
{
  event_print("Rx Req unsubscribing from topo modif for client: %d", llid);
  if (msg_exist_channel(llid))
    {
    event_unsubscribe(sub_evt_topo, llid);
    send_status_ok(llid, tid, "topounsub");
    }
  else
    send_status_ko(llid, tid, "Abnormal!");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_evt_print_unsub(int llid, int tid)
{
  event_print("Rx Req unsubscribing from print for client: %d", llid);
  if (msg_exist_channel(llid))
    {
    event_unsubscribe(sub_evt_print, llid);
    send_status_ok(llid, tid, "printunsub");
    }
  else
    send_status_ko(llid, tid, "Abnormal!");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_del_all(int llid, int tid)
{
  event_print("Rx Req Delete ALL");
  mulan_del_all();
  musat_mngt_stop_all();
  c2c_free_all();
  machine_recv_kill_clownix();
  event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
  send_status_ok(llid, tid, "delall");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_topo_small_event_sub(int llid, int tid)
{
  int i, nb;
  t_vm *cur;
  event_print("Req subscribing to Machine poll event for client: %d", llid);
  if (msg_exist_channel(llid))
    {
    event_subscribe(topo_small_event, llid, tid);
    send_status_ok(llid, tid, "vmpollsub");
    cur = cfg_get_first_vm(&nb);
    for (i=0; i<nb; i++)
      {
      if (!cur)
        KOUT(" ");

      if (cur->tmux_launch == 1)
        send_topo_small_event(llid, tid, cur->vm_params.name, 
                              NULL, NULL, vm_evt_tmux_launch_ok);
      else
        send_topo_small_event(llid, tid, cur->vm_params.name,
                              NULL, NULL, vm_evt_tmux_launch_ko);

      if (cur->vm_params.vm_config_flags & VM_FLAG_CLOONIX_AGENT_PING_OK)
        send_topo_small_event(llid, tid, cur->vm_params.name,
                              NULL, NULL, vm_evt_cloonix_ga_ping_ok);
      else
        send_topo_small_event(llid, tid, cur->vm_params.name,
                              NULL, NULL, vm_evt_cloonix_ga_ping_ko);

      cur = cur->next;
      }
    if (cur)
      KOUT(" ");
    }
  else
    send_status_ko(llid, tid, "Abnormal!");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_topo_small_event_unsub(int llid, int tid)
{
  event_print("Req unsubscribing from Machine poll event for client: %d", llid);
  if (msg_exist_channel(llid))
    {
    event_unsubscribe(topo_small_event, llid);
    send_status_ok(llid, tid, "vmpollunsub");
    }
  else
    send_status_ko(llid, tid, "tid, Abnormal!");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_add_sat(int llid, int tid, char *name, int mutype, 
                  t_c2c_req_info *c2c_info)
{
  t_tux *tmptux = cfg_get_tux(name);
  char info[MAX_PRINT_LEN];
  int no_use;
  char use[MAX_PATH_LEN];
  char snf_recpath[MAX_PATH_LEN];
  int snf_capture_on;
  memset(snf_recpath, 0, MAX_PATH_LEN);
  snf_capture_on = 0;
  event_print("Rx Req add %s %d", name, mutype);
  if (get_inhib_new_clients())
    send_status_ko(llid, tid, "AUTODESTRUCT_ON");
  else if (cfg_name_is_in_use(0, name, use))
    send_status_ko(llid, tid, use);
  else if (tmptux)
    {
    sprintf( info, "Unix sock %s already exists", name);
    send_status_ko(llid, tid, info);
    }
  else if ((mutype != musat_type_tap) &&
           (mutype != musat_type_snf) &&
           (mutype != musat_type_c2c) &&
           (mutype != musat_type_nat) &&
           (mutype != musat_type_a2b) &&
           (mutype != musat_type_wif))
    {
    sprintf(info, "%s Bad type: %d", name, mutype);
    send_status_ko(llid, tid, info);
    }
  else if (musat_mngt_exists(name, &no_use))
    {
    sprintf(info, "%s Already exists", name);
    send_status_ko(llid, tid, info);
    }
  else
    {
    if (musat_mngt_is_snf(mutype))
      {
      snf_capture_on = 0;
      snprintf(snf_recpath, MAX_PATH_LEN-1, "/tmp/cloonix_%s.pcap", name);
      }
    if (musat_mngt_start(llid, tid, name, mutype, 
                         snf_capture_on, snf_recpath,
                         c2c_info->cloonix_slave,
                         c2c_info->ip_slave, 
                         c2c_info->port_slave))
      {
      sprintf( info, "Bad start of %s", name);
      send_status_ko(llid, tid, info);
      }
    else 
      {
      if (musat_mngt_is_c2c(mutype))
        {
        if (!c2c_info)
          {
          KERR("%s", name);
          sprintf( info, "Bad c2c param info %s", name);
          send_status_ko(llid, tid, info);
          musat_mngt_stop(name);
          }
        else
          {
          if (c2c_create_master_begin(name, 
                                      c2c_info->ip_slave, 
                                      c2c_info->port_slave,
                                      c2c_info->passwd_slave))
            {
            KERR("%s", name);
            sprintf( info, "Bad c2c begin %s", name);
            send_status_ko(llid, tid, info);
            musat_mngt_stop(name);
            }
          }
        }
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_del_sat(int llid, int tid, char *name)
{
  event_print("Rx Req del %s", name);
  if (!musat_mngt_stop(name))
    {
    send_status_ok(llid, tid, "del usat");
    event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    }
  else
    send_status_ko(llid, tid, "del usat");
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_hop_get_name_list_doors(int llid, int tid)
{
  int nb;
  t_hop_list *list = hop_get_name_list(&nb);
  send_hop_name_list_doors(llid, tid, nb, list);
  hop_free_name_list(list);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_sav_vm(int llid, int tid, char *name, int stype, char *path)
{
  t_vm   *vm = cfg_get_vm(name);
  char *dir_path = mydirname(path);
  if (!vm)
    {
    send_status_ko(llid, tid, "MACHINE NOT FOUND");
    }
  else if (sav_vm_count())
    {
    send_status_ko(llid, tid, "LAST SAVING NOT FINISHED");
    }
  else if (file_exists(path, F_OK))
    {
    send_status_ko(llid, tid, "FILE ALREADY EXISTS");
    }
  else if (!file_exists(dir_path, W_OK))
    {
    send_status_ko(llid, tid, "DIRECTORY NOT WRITABLE OR NOT FOUND");
    }
  else if (!sav_vm_agent_ok_name(name))
    {
    send_status_ko(llid, tid, "AGENT NOT REACHEABLE FOR THIS VM");
    }
  else
    {
    sav_vm_rootfs(name, path, llid, tid, stype);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_sav_vm_all(int llid, int tid, int stype, char *path)
{
  char info[MAX_PRINT_LEN];
  char *dir_path = mydirname(path);
  int nb;
  t_vm *vm = cfg_get_first_vm(&nb);
  if (!vm)
    {
    send_status_ko(llid, tid, "NO MACHINE NOT FOUND");
    }
  else if (sav_vm_count())
    {
    sprintf(info, "LAST SAVING NOT FINISHED");
    send_status_ko(llid, tid, info);
    }
  else if (file_exists(path, F_OK))
    {
    send_status_ko(llid, tid, "DIRECTORY ALREADY EXISTS");
    }
  else if (!file_exists(dir_path, W_OK))
    {
    sprintf(info, "DIRECTORY %s NOT WRITABLE", dir_path);
    send_status_ko(llid, tid, info);
    }
  else if (!sav_vm_agent_ok_all())
    {
    send_status_ko(llid, tid, "AGENT NOT REACHEABLE FOR AT LEAST ONE VM");
    }
  else
    {
    if (mkdir(path, 0700))
      {
      if (errno == EEXIST)
        {
        sprintf(info, "%s ALREADY EXISTS", path);
        send_status_ko(llid, tid, info);
        }
      else
        {
        sprintf(info, "DIR %s CREATE ERROR %d", path, errno);
        send_status_ko(llid, tid, info);
        }
      }
    else
      {
      sav_all_vm_rootfs(nb, vm, path, llid, tid, stype);
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void recv_reboot_vm(int llid,int tid,char *name,int is_cloonix_reboot)
{
  int job_idx;
  char buf[MAX_NAME_LEN];
  t_opaque_agent_req *opaque;
  t_vm   *vm = cfg_get_vm(name);
  if (vm)
    {
    if (is_cloonix_reboot)
      {
      opaque = (void *) clownix_malloc(sizeof(t_opaque_agent_req), 9);
      memset(opaque, 0, sizeof(t_opaque_agent_req));
      opaque->llid = llid;
      opaque->tid = tid;
      strncpy(opaque->name, name, MAX_NAME_LEN-1);
      strncpy(opaque->action, "reboot", MAX_NAME_LEN-1);
      job_idx = timeout_service_alloc(doors_timeout_service_cb, 
                                      (void *)opaque, 300);
      memset(buf, 0, MAX_NAME_LEN);
      snprintf(buf, MAX_NAME_LEN-1, REBOOT_REQUEST, job_idx);
      doors_send_command(get_doorways_llid(), 0, name, buf);
      }
    else
      {
      qmp_request_qemu_reboot(name);
      send_status_ok(llid, tid, name);
      }
    }
  else
    send_status_ko(llid, tid, "MACHINE NOT FOUND");
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void recv_halt_vm(int llid, int tid, char *name)
{
  int job_idx;
  char buf[MAX_NAME_LEN];
  t_vm   *vm = cfg_get_vm(name);
  t_opaque_agent_req *opaque;
  if (vm)
    {
    opaque = (void *) clownix_malloc(sizeof(t_opaque_agent_req), 9);
    memset(opaque, 0, sizeof(t_opaque_agent_req));
    opaque->llid = llid;
    opaque->tid = tid;
    strncpy(opaque->name, name, MAX_NAME_LEN-1);
    strncpy(opaque->action, "poweroff", MAX_NAME_LEN-1);
    job_idx = timeout_service_alloc(doors_timeout_service_cb, 
                                   (void *)opaque, 300);
    memset(buf, 0, MAX_NAME_LEN);
    snprintf(buf, MAX_NAME_LEN-1, HALT_REQUEST, job_idx);
    doors_send_command(get_doorways_llid(), 0, name, buf);
    }
  else
    send_status_ko(llid, tid, "MACHINE NOT FOUND");
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void recv_init(void)
{
  glob_coherency = 0;
  g_head_coherency = NULL;
  g_coherency_abs_beat_timer = 0;
  g_coherency_ref_timer = 0;
  g_in_cloonix = inside_cloonix(&g_cloonix_vm_name);
  g_inhib_new_clients = 0;
}
/*---------------------------------------------------------------------------*/


