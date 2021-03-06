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
typedef struct t_llid_tid
{
  int llid;
  int tid;
} t_llid_tid;

typedef struct t_lst_pid
{
  char name[MAX_NAME_LEN];
  int pid;
} t_lst_pid;
/*--------------------------------------------------------------------------*/

#define STAT_FORMAT "%*d (%s %*s %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "\
                    "%lu %lu %lu %lu %*d %*d %*u %*u %*d %*u %lu"

/****************************************************************************/
typedef struct t_pid_info
{
        unsigned long      utime    ;
        unsigned long      cutime   ;
        unsigned long      stime    ;
        unsigned long      cstime   ;
        unsigned long      rss      ;
        char               comm[MAX_PATH_LEN];
} t_pid_info;
/*--------------------------------------------------------------------------*/


#define CDROM_CONFIG_ISO "cdrom_config.iso"
#define DIR_CONF "config"
#define FILE_COW "cow"
#define DIR_UMID "umid"
#define CLOONIX_FILE_NAME "name"
#define FILE_IMAGE "image.bin"
#define CLOONIX_INTERNAL_COM "cloonix_internal_com"
#define QEMU_BIN_DIR "qemu_bin"
#define QEMU_EXE "qemu-system-x86_64"
#define QEMU_ARM_EXE "qemu-system-arm"
#define QEMU_AARCH64_EXE "qemu-system-aarch64"
#define QEMU_IMG "qemu-img"
#define DIR_CLOONIX_DISKS "disks"
#define CLOONIX_VM_WORKDIR "vm"
#define QMONITOR_UNIX "mon"
#define QMP_UNIX "qmp"
#define QHVCO_UNIX "qhvc0"
#define QBACKDOOR_UNIX "qdoor"
#define QBACKDOOR_HVCO_UNIX "qdoorhvc"





