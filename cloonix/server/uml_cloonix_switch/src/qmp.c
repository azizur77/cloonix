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
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "io_clownix.h"
//#include "rpc_qmonitor.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
//#include "util_sock.h"
//#include "llid_trace.h"
//#include "machine_create.h"
#include "utils_cmd_line_maker.h"
//#include "pid_clone.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "qmp.h"
//#include "qmonitor.h"
//#include "qhvc0.h"
#include "qmp_dialog.h"


/****************************************************************************/
void qmp_request_qemu_reboot(char *name)
{
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int qmp_end_qemu_unix(char *name)
{
  qmp_dialog_free(name);
  return 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_conn_end(char *name)
{
KERR("%s", name);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_begin_qemu_unix(char *name)
{
  qmp_dialog_alloc(name, qmp_conn_end);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_agent_sysinfo(char *name, int used_mem_agent)
{
  t_vm   *vm;
  vm = cfg_get_vm(name);
  if ((vm) && 
      (vm->kvm.vm_config_flags & VM_CONFIG_FLAG_BALLOONING))
    {
//TODO
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_vm_save_rootfs(char *name, char *path, int llid, int tid, int stype)
{
  send_status_ko(llid, tid, "NOT IMPLEM");
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_vm_save_rootfs_all(int nb, t_vm *vm, char *path,
                           int llid, int tid, int stype)
{
  send_status_ko(llid, tid, "NOT IMPLEM");
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_init(void)
{
}
/*--------------------------------------------------------------------------*/

