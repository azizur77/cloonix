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
/*---------------------------------------------------------------------------*/
#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "doorways_sock.h"
#include "client_clownix.h"
#include "file_read_write.h"
#include "cmd_help_fn.h"
/*---------------------------------------------------------------------------*/

int param_tester(char *param, int min, int max);
void callback_end(int tid, int status, char *err);


/***************************************************************************/
void help_add_vm_kvm(char *line)
{
  printf("\n\n\n %s <name> <mem> <cpu> <eth> <rootfs> [options]\n", line);
  printf("\n\tmem is in mega");
  printf("\n\tcpu is the processor qty\n");
  printf("\n\teth is the ethernet qty\n");
  printf("\n\t[options]");
  printf("\n\t       --persistent ");
  printf("\n\t       --9p_share=<host_shared_dir_file_path>");
  printf("\n\t       --fullvirt");
  printf("\n\t       --balloon");
  printf("\n\tnote: for the --persistent option, the rootfs must be a full");
  printf("\n\t      path to a file system. If not set, the rootfs writes are");
  printf("\n\t      evenescent, lost at shutdown.");
  printf("\n\t      If set, those writes are persistent after shutwown.\n");
  printf("\n\tnote: for the 9p_share, the shared dir mount point is");
  printf("\n\t      /mnt/p9_host_share in the guest kvm.\n\n");
  printf("\n\nexample:\n\n");
  printf("%s jessie 1000 1 3 jessie.qcow2\n", line);
  printf("%s cloon 1000 1 1 /tmp/jessie.qcow2 --persistent\n", line);
  printf("%s clown 1000 1 2 stretch.qcow2 --9p_share=/tmp\n", line);
  printf("\n\n\n");
}
/*-------------------------------------------------------------------------*/

/***************************************************************************/
static int local_add_kvm(char *name, int mem, int cpu, int eth, 
                         char *rootfs, int argc, char **argv)
{
  int i, result = 0, prop_flags = 0; 
  char *img_linux = NULL;
  char *p9_host_shared=NULL;
  char *bdisk=NULL;
  prop_flags |= VM_CONFIG_FLAG_EVANESCENT;
  for (i=0; i<argc; i++)
    {
    if (!strcmp(argv[i], "--persistent"))
      {
      prop_flags |= VM_CONFIG_FLAG_PERSISTENT;
      prop_flags &= ~VM_CONFIG_FLAG_EVANESCENT;
      }
    else if (!strcmp(argv[i], "--fullvirt"))
      prop_flags |= VM_CONFIG_FLAG_FULL_VIRT;
    else if (!strcmp(argv[i], "--balloon"))
      prop_flags |= VM_CONFIG_FLAG_BALLOONING;
    else if (!strncmp(argv[i], "--9p_share=", strlen("--9p_share=")))
      {
      prop_flags |= VM_CONFIG_FLAG_9P_SHARED;
      p9_host_shared = argv[i] + strlen("--9p_share=");
      }
    else
      {
      printf("\nERROR: %s not an option\n\n", argv[i]);
      result = -1;
      break;
      }
    }
  if (result == 0)
    {
    init_connection_to_uml_cloonix_switch();
    client_add_vm(0, callback_end, name, eth, prop_flags, cpu, mem,
                  img_linux, rootfs, bdisk, p9_host_shared);
    }
  return result;
}
/*---------------------------------------------------------------------------*/


/***************************************************************************/
int cmd_add_vm_kvm(int argc, char **argv)
{
  int cpu, mem, eth, result = -1;
  char *name, *rootfs;
  if (argc >= 5) 
    {
    name = argv[0];
    mem = param_tester(argv[1], 1, 50000);
    if (mem != -1)
      {
      cpu = param_tester(argv[2], 1, 32);
      if (cpu != -1)
        {
        eth = param_tester(argv[3], 1, MAX_ETH_VM);
          {
          if (eth != -1)
            {
            rootfs = argv[4];
            result = local_add_kvm(name, mem, cpu, eth, 
                                   rootfs, argc-5, &(argv[5])); 
            }
          }
        }
      }
    }
  return result;
}
/*-------------------------------------------------------------------------*/











