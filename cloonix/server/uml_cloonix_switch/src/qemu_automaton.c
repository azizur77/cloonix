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
#include <errno.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>


#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "pid_clone.h"
#include "machine_create.h"
#include "heartbeat.h"
#include "system_callers.h"
#include "automates.h"
#include "util_sock.h"
#include "utils_cmd_line_maker.h"
#include "qmonitor.h"
#include "qmp.h"
#include "qhvc0.h"
#include "doorways_mngt.h"
#include "doors_rpc.h"
#include "file_read_write.h"

#define DRIVE_PARAMS " -drive file=%s,index=%d,media=disk,if=virtio"

#define VIRTIO_9P " -fsdev local,id=fsdev0,security_model=passthrough,path=%s"\
                  " -device virtio-9p-pci,id=fs0,fsdev=fsdev0,mount_tag=%s"

#define CDROM " -drive file=%s,index=%d,media=cdrom,if=virtio"

#define DRIVE_FULL_VIRT " -drive file=%s,index=%d,media=disk,if=ide"

#define INSTALL_DISK " -boot d -drive file=%s,index=%d,media=disk,if=virtio"

#define ADDED_CDROM " -drive file=%s,media=cdrom"


typedef struct t_cprootfs_config
{
  char name[MAX_NAME_LEN];
  char msg[MAX_PRINT_LEN];
  char backing[MAX_PATH_LEN];
  char used[MAX_PATH_LEN];
} t_cprootfs_config;


enum
  {
  auto_idle = 0,
  auto_create_disk,
  auto_create_vm_launch,
  auto_create_vm_connect,
  auto_max,
  };

/*--------------------------------------------------------------------------*/

int inside_cloonix(char **name);

void qemu_vm_automaton(void *unused_data, int status, char *name);

char **get_saved_environ(void);

/****************************************************************************/
static int get_wake_up_eths(char *name, t_vm **vm,
                            t_wake_up_eths **wake_up_eths)
{
  *vm = cfg_get_vm(name);
  if (!(*vm))
    return -1;
  *wake_up_eths = (*vm)->wake_up_eths;
  if (!(*wake_up_eths))
    return -1;
  return 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void static_vm_timeout(void *data)
{
  t_wake_up_eths *wake_up_eths = (t_wake_up_eths *) data;
  if (!wake_up_eths)
    KOUT(" ");
  qemu_vm_automaton(NULL, 0, wake_up_eths->name);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void cprootfs_clone_death(void *data, int status, char *name)
{
  t_cprootfs_config *cprootfs = (t_cprootfs_config *) data;
  t_vm   *vm;
  t_wake_up_eths *wake_up_eths;

  event_print("%s %s", __FUNCTION__, name);
  if (!get_wake_up_eths(name, &vm, &wake_up_eths))
    {
    if (strcmp(name, cprootfs->name))
      KOUT("%s %s", name, cprootfs->name);
    if (strstr(cprootfs->msg, "OK"))
      {
      if (status)
        KOUT("%d", status);
      }
    else if (strstr(cprootfs->msg, "KO"))
      {
      if (!status)
        KOUT("%d", status);
      snprintf(wake_up_eths->error_report, MAX_PRINT_LEN-1, 
               "%s", cprootfs->msg);
      KERR("%s", name);
      }
    else
      KERR("%s %d", cprootfs->msg, status);
    qemu_vm_automaton(NULL, status, name);
    }
  clownix_free(cprootfs, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void cprootfs_clone_msg(void *data, char *msg)
{
  int pid;
  t_cprootfs_config *cprootfs = (t_cprootfs_config *) data;
  t_vm   *vm;
  t_wake_up_eths *wake_up_eths;
  if (!get_wake_up_eths(cprootfs->name, &vm, &wake_up_eths))
    {
    if (!strncmp(msg, "pid=", strlen("pid=")))
      {
      if (!strncmp(msg, "pid=start", strlen("pid=start")))
        {
        if (sscanf(msg, "pid=start:%d", &(vm->pid_of_cp_clone)) != 1)
          KOUT("%s", msg);
        }
      else if (!strncmp(msg, "pid=end", strlen("pid=end")))
        {
        if (sscanf(msg, "pid=end:%d", &pid) != 1)
          KOUT("%s", msg);
        if (pid != vm->pid_of_cp_clone)
          KERR(" %s %d", msg, vm->pid_of_cp_clone);
        vm->pid_of_cp_clone = 0;
        }
      else
        KERR(" %s", msg);
      }
    else
      strncpy(cprootfs->msg, msg, MAX_NAME_LEN-1);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int local_clownix_system (char *commande)
{
  pid_t pid;
  int   status;
  char **environ = NULL;
  char * argv [4];
  char msg_dad[MAX_NAME_LEN];
  if (commande == NULL)
    return (1);
  if ((pid = fork ()) < 0)
    return (-1);
  if (pid == 0)
    {
    argv[0] = "/bin/bash";
    argv[1] = "-c";
    argv[2] = commande;
    argv[3] = NULL;
    execve("/bin/bash", argv, environ);
    exit (127);
    }
  memset(msg_dad, 0, MAX_NAME_LEN);
  snprintf(msg_dad, MAX_NAME_LEN - 1, "pid=start:%d", pid);
  send_to_daddy(msg_dad);
  while (1)
    {
    if (waitpid (pid, &status, 0) == -1)
      return (-1);
    else
      {
      memset(msg_dad, 0, MAX_NAME_LEN);
      snprintf(msg_dad, MAX_NAME_LEN - 1, "pid=end:%d", pid);
      send_to_daddy(msg_dad);
      return (status);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int cprootfs_clone(void *data)
{
  int result;
  char err[MAX_PRINT_LEN];
  char *cmd;
  t_cprootfs_config *cprootfs = (t_cprootfs_config *) data;
  memset(err, 0, MAX_PRINT_LEN);
  strcpy(err, "KO ");
  cmd = utils_qemu_img_derived(cprootfs->backing, cprootfs->used);
  result = local_clownix_system(cmd);
  if (result)
    KERR("%s", cmd);
  snprintf(cmd, 2*MAX_PATH_LEN, "/bin/chmod +w %s", cprootfs->used);
  result = clownix_system(cmd);
  if (result)
    KERR("%s", cmd);
  if (result)
    {
    send_to_daddy(err);
    KERR("%s", cmd);
    }
  else
    {
    send_to_daddy("OK");
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void derived_file_creation_request(t_vm *vm)
{
  char *name;
  t_cprootfs_config *cprootfs;
  if (!vm)
    KOUT(" ");
  name = vm->vm_params.name;
  cprootfs=(t_cprootfs_config *)clownix_malloc(sizeof(t_cprootfs_config),13);
  memset(cprootfs, 0, sizeof(t_cprootfs_config));
  strncpy(cprootfs->name, name, MAX_NAME_LEN-1);
  strcpy(cprootfs->msg, "NO_MSG");

  strncpy(cprootfs->used, vm->vm_params.rootfs_used, MAX_PATH_LEN-1);
  strncpy(cprootfs->backing, vm->vm_params.rootfs_backing, MAX_PATH_LEN-1);

  event_print("%s %s", __FUNCTION__, name);
  pid_clone_launch(cprootfs_clone, cprootfs_clone_death,
                   cprootfs_clone_msg, cprootfs, 
                   cprootfs, cprootfs, name, -1, 1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static char *format_virtkvm_net_mueth_cmd(t_vm *vm, int eth)
{
  static char net_cmd[MAX_PATH_LEN*3];
  char *name;
  int len = 0;
  char *mac_addr;
  len+=sprintf(net_cmd+len,
               " -device virtio-muethnet,tx=bh,netdev=eth%d,mac=",
               eth);
  mac_addr = vm->vm_params.eth_params[eth].mac_addr;
  len += sprintf(net_cmd+len,"%02X:%02X:%02X:%02X:%02X:%02X",
                 mac_addr[0] & 0xFF, mac_addr[1] & 0xFF, mac_addr[2] & 0xFF,
                 mac_addr[3] & 0xFF, mac_addr[4] & 0xFF, mac_addr[5] & 0xFF);
  name = utils_get_mueth_name(vm->vm_params.name, eth);
  len += sprintf(net_cmd+len, 
      " -netdev mueth,id=eth%d,munetname=%s,muname=%s,sock=%s,mutype=1", eth,
      cfg_get_cloonix_name(), name, utils_get_mueth_path(vm->vm_id, eth)); 
  return net_cmd;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
#define QEMU_OPTS \
   " -m %d"\
   " -serial mon:stdio"\
   " -nographic"\
   " -nodefaults"\
   " -name %s"\
   " -device virtio-serial-pci"\
   " -chardev socket,id=mon1,path=%s,server,nowait"\
   " -mon chardev=mon1,mode=readline"\
   " -chardev socket,id=qmp1,path=%s,server,nowait"\
   " -mon chardev=qmp1,mode=control"\
   " -chardev socket,path=%s,server,nowait,id=cloon"\
   " -device virtserialport,chardev=cloon,name=net.cloonix.0"\
   " -chardev socket,path=%s,server,nowait,id=hvc0"\
   " -device virtconsole,chardev=hvc0"

#define QEMU_SPICE \
   " -balloon virtio"\
   " -device virtio-rng-pci"\
   " -soundhw hda"\
   " -usb"\
   " -chardev spicevmc,id=charredir0,name=usbredir"\
   " -device usb-redir,chardev=charredir0,id=redir0"\
   " -spice unix,addr=%s,disable-ticketing"\
   " -device virtserialport,chardev=spicechannel0,name=com.redhat.spice.0"\
   " -chardev spicevmc,id=spicechannel0,name=vdagent"
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static int create_linux_cmd_kvm(t_vm *vm, char *linux_cmd)
{
  int i, nb_cpu,  len=0;
  char option_kvm_txt[MAX_NAME_LEN];
  char cmd_start[3*MAX_PATH_LEN];
  char cpu_type[MAX_NAME_LEN];
  char *rootfs, *added_disk, *gname;
  char *spice_path, *cdrom;
  if (!vm)
    KOUT(" ");
  spice_path = utils_get_spice_path(vm->vm_id);
  nb_cpu = vm->vm_params.cpu;
  if (vm->vm_params.has_kvm_virt) 
    {
    strcpy(option_kvm_txt, "-enable-kvm");
    if (inside_cloonix(&gname))
      {
      strcpy(cpu_type, "kvm64");
      }
    else
      {
      strcpy(cpu_type, "host,+vmx");
      }
    }
  else
    {
    strcpy(cpu_type, "qemu64");
    strcpy(option_kvm_txt, "-no-kvm");
    }

  sprintf(cmd_start, QEMU_OPTS, 
          vm->vm_params.mem,
          vm->vm_params.name,
          utils_get_qmonitor_path(vm->vm_id),
          utils_get_qmp_path(vm->vm_id),
          utils_get_qbackdoor_path(vm->vm_id),
          utils_get_qhvc0_path(vm->vm_id));
  len += sprintf(linux_cmd+len, " %s"
                                " -pidfile %s/%s/pid"
                                " -cpu %s"
                                " -smp %d,maxcpus=%d,cores=1"
                                " %s"
                                " -vga qxl",
                                //" -vga virtio -display gtk,gl=on",
          cmd_start, cfg_get_work_vm(vm->vm_id), DIR_UMID,
          cpu_type, nb_cpu, nb_cpu, option_kvm_txt);
  if (spice_libs_exists())
    len += sprintf(linux_cmd+len, QEMU_SPICE, spice_path);
  if (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_9P_SHARED)
    {
    if (vm->vm_params.p9_host_share[0] == 0) 
      KERR(" ");
    else
      {
      if (!is_directory_readable(vm->vm_params.p9_host_share))
        KERR("%s", vm->vm_params.p9_host_share);
      else
        len += sprintf(linux_cmd+len, VIRTIO_9P, vm->vm_params.p9_host_share,
                                                 vm->vm_params.name);
      }
    }

  rootfs = vm->vm_params.rootfs_used;
  added_disk = vm->vm_params.added_disk;

  if  (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_NO_REBOOT)
    {
    len += sprintf(linux_cmd+len, " -no-reboot");
    }
  if  (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_INSTALL_CDROM)
    {
    len += sprintf(linux_cmd+len, INSTALL_DISK, rootfs, 0);
    len += sprintf(linux_cmd+len, ADDED_CDROM, vm->vm_params.install_cdrom);
    }
  else
    {
    if (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_FULL_VIRT)
      len += sprintf(linux_cmd+len, DRIVE_FULL_VIRT, rootfs, 0);
    else
      len += sprintf(linux_cmd+len, DRIVE_PARAMS, rootfs, 0);
  
    cdrom = utils_get_cdrom_path_name(vm->vm_id);
    len += sprintf(linux_cmd+len, ADDED_CDROM, cdrom);
  
    if  (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_ADDED_DISK)
      len += sprintf(linux_cmd+len, DRIVE_PARAMS, added_disk, 1);
    }

  if  (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_ADDED_CDROM)
    {
    len += sprintf(linux_cmd+len, ADDED_CDROM, vm->vm_params.added_cdrom);
    }


  for (i=0; i<vm->vm_params.nb_eth; i++)
    {
    len+=sprintf(linux_cmd+len,"%s",format_virtkvm_net_mueth_cmd(vm,i));
    }
  return len;
}
/*--------------------------------------------------------------------------*/
              
/****************************************************************************/
static char *qemu_cmd_format(t_vm *vm)
{
  int len = 0;
  char *cmd = (char *) clownix_malloc(MAX_BIG_BUF, 7);
  memset(cmd, 0,  MAX_BIG_BUF);
  len += snprintf(cmd, MAX_BIG_BUF-1,
                  "%s/server/qemu/%s/%s -L %s/server/qemu/%s ",
                  cfg_get_bin_dir(), QEMU_BIN_DIR, QEMU_EXE,
                  cfg_get_bin_dir(), QEMU_BIN_DIR);
  len += create_linux_cmd_kvm(vm, cmd+len);
  strcat(cmd, ";sleep 10");
  return cmd;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static char *alloc_argv(char *str)
{
  int len = strlen(str);
  char *argv = (char *)clownix_malloc(len + 1, 15);
  memset(argv, 0, len + 1);
  strncpy(argv, str, len);
  return argv;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static char **create_qemu_argv(t_vm *vm)
{
  int i = 0;
  static char **argv;
  char *kvm_exe = qemu_cmd_format(vm);
  argv = (char **)clownix_malloc(10 * sizeof(char *), 13);
  memset(argv, 0, 10 * sizeof(char *));
  argv[i++] = alloc_argv(utils_get_tmux_bin_path());
  argv[i++] = alloc_argv("-S");
  argv[i++] = alloc_argv(utils_get_tmux_sock_path());
  argv[i++] = alloc_argv("new-session");
  argv[i++] = alloc_argv("-s");
  argv[i++] = alloc_argv(vm->vm_params.name);
  argv[i++] = alloc_argv("-d");
  argv[i++] = kvm_exe;
  argv[i++] = NULL;
  return argv;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int start_launch_args(void *ptr)
{  

  return (utils_execve(ptr));
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void launcher_death(void *data, int status, char *name)
{
  int i;
  char **argv = (char **) data;
  for (i=0; argv[i] != NULL; i++)
    clownix_free(argv[i], __FUNCTION__);
  clownix_free(argv, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int launch_qemu_vm(t_vm *vm)
{
  char **argv;
  int result = -1;
  argv = create_qemu_argv(vm);
  utils_send_creation_info(vm->vm_params.name, argv);

//VIP
// gdb ...
// set follow-fork-mode child

  pid_clone_launch(start_launch_args, launcher_death, NULL, 
                   (void *)argv, (void *)argv, NULL, 
                   vm->vm_params.name, -1, 1);
  result = 0;

  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void tmux_duplicate_callback(int status, char *name)
{
  t_vm   *vm = cfg_get_vm(name);
  t_wake_up_eths *wake_up_eths;
  char err[MAX_PRINT_LEN];
  if (!vm)
    return;
  wake_up_eths = vm->wake_up_eths;
  if (!wake_up_eths)
    return;
  if (strcmp(wake_up_eths->name, name))
    KOUT(" ");
  if (status)
    {
    sprintf(err, "ERROR TMUX WITH SAME NAME EXISTS: %s\n", name);
    event_print(err);
    send_status_ko(wake_up_eths->llid, wake_up_eths->tid, err);
    utils_launched_vm_death(name, error_death_tmuxerr);
    }
  else
    qemu_vm_automaton(NULL, 0, name); 
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void arm_utils_finish_vm_init(char *name)
{
  char *nm;
  nm = (char *) clownix_malloc(MAX_NAME_LEN, 9);
  memset(nm, 0, MAX_NAME_LEN);
  strncpy(nm, name, MAX_NAME_LEN-1);
  clownix_timeout_add(4000, utils_finish_vm_init, (void *) nm, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void qemu_vm_automaton(void *unused_data, int status, char *name) 
{
  char err[MAX_PRINT_LEN];
  int state;
  t_vm   *vm = cfg_get_vm(name);
  t_wake_up_eths *wake_up_eths;
  t_small_evt vm_evt;
  if (!vm)
    return;
  wake_up_eths = vm->wake_up_eths;
  if (!wake_up_eths)
    return;
  if (strcmp(wake_up_eths->name, name))
    KOUT(" ");
  state = wake_up_eths->state;
  if (status)
    {
    sprintf(err, "ERROR when creating %s\n", name);
    event_print(err);
    send_status_ko(wake_up_eths->llid, wake_up_eths->tid, err);
    utils_launched_vm_death(name, error_death_qemuerr);
    return;
    }
  switch (state)
    {
    case auto_idle:
      wake_up_eths->state = auto_create_disk;
      tmux_duplicate_check(name, tmux_duplicate_callback);
      break;
    case auto_create_disk:
      wake_up_eths->state = auto_create_vm_launch;
      if (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_PERSISTENT)
        clownix_timeout_add(1, static_vm_timeout, (void *) wake_up_eths,
                            NULL, NULL);
      else if (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_EVANESCENT)
        derived_file_creation_request(vm);
      else
        KOUT("%X", vm->vm_params.vm_config_flags);
      break;
    case auto_create_vm_launch:
      wake_up_eths->state = auto_create_vm_connect;
      if (launch_qemu_vm(vm))
        clownix_timeout_add(4000, static_vm_timeout, (void *) wake_up_eths,
                            NULL, NULL);
      else
        clownix_timeout_add(500, static_vm_timeout, (void *) wake_up_eths,
                            NULL, NULL);
      break;
    case auto_create_vm_connect:
      vm->tmux_launch = 1;
      arm_utils_finish_vm_init(name);
      qmonitor_begin_qemu_unix(name);
      qmp_begin_qemu_unix(name);
      qhvc0_begin_qemu_unix(name);
      doors_send_add_vm(get_doorways_llid(), 0, vm->vm_params.name,
                        utils_get_qbackdoor_path(vm->vm_id));
      memset(&vm_evt, 0, sizeof(t_small_evt));
      strncpy(vm_evt.name, name, MAX_NAME_LEN-1);
      vm_evt.evt = vm_evt_tmux_launch_ok;
      event_subscriber_send(topo_small_event, (void *) &vm_evt);
      start_mueth_qemu(vm);
      break;
    default:
      KOUT(" ");
    }
}
/*--------------------------------------------------------------------------*/



