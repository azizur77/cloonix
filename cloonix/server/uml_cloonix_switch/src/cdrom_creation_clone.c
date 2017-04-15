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
#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "pid_clone.h"
#include "cfg_store.h"
#include "event_subscriber.h"
#include "utils_cmd_line_maker.h"
#include "machine_create.h"
#include "commun_daemon.h"
#include "file_read_write.h"
#include "system_callers.h"






/*****************************************************************************/
typedef struct t_cdrom_config
{
  char name[MAX_NAME_LEN];
  int vm_id;
  int nb_eth;
  int has_p9_host_share;
  char tmp_conf[MAX_PATH_LEN];
  char cdrom_path[MAX_PATH_LEN];
  char msg_from_clone[MAX_PATH_LEN];
} t_cdrom_config;
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int create_tmp_config(int vm_id, char *name, int nb_eth, 
                             int has_p9_host_share,
                             char *err)
{
  int result = 0;
  char agent_dir[MAX_PATH_LEN];
  char *tmp_conf_dir;
  memset(agent_dir, 0, MAX_PATH_LEN);
  snprintf(agent_dir, MAX_PATH_LEN-1, 
           "%s/common/agent_dropbear/agent_bin_alien/", cfg_get_bin_dir());
  tmp_conf_dir = utils_dir_conf_tmp(vm_id);
  my_cp_file(agent_dir, tmp_conf_dir, "cloonix_agent");
  my_cp_file(agent_dir, tmp_conf_dir, "dropbear_cloonix_sshd");
  my_cp_dir(agent_dir, tmp_conf_dir, "lib_alien", "lib_alien");
  make_config_cloonix_vm_name(tmp_conf_dir, name);
  make_config_cloonix_vm_p9_host_share(tmp_conf_dir, has_p9_host_share);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int fct_in_clone_context(void *data)
{
  char *genisobin = util_get_genisoimage();
  int result;
  char err[MAX_PRINT_LEN];
  t_cdrom_config *cdrom_conf = (t_cdrom_config *) data;
  char *argv[] = { genisobin, "-U", "-o", cdrom_conf->cdrom_path, 
                   cdrom_conf->tmp_conf, NULL, 
                 };
  if (create_tmp_config(cdrom_conf->vm_id, cdrom_conf->name, 
                        cdrom_conf->nb_eth, 
                        cdrom_conf->has_p9_host_share,
                        err))
    {
    send_to_daddy(err);
    return -1;
    }
  result = my_popen(genisobin, argv);
  if (result == 0)
    send_to_daddy("CDROM_DONE_OK");
  else
    {
    KERR("%s -J -o %s %s", genisobin, cdrom_conf->cdrom_path, cdrom_conf->tmp_conf);
    send_to_daddy("Error genisoimage");
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void msg_from_clone_in_main_context(void *data, char *msg)
{
  t_cdrom_config *cdrom_conf = (t_cdrom_config *) data;
  strncpy(cdrom_conf->msg_from_clone, msg, MAX_PATH_LEN-1);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void death_of_clone_in_main_context(void *data, int status, char *name)
{
  char err[MAX_PATH_LEN];
  char *vm_name;
  t_cdrom_config *cdrom_conf = (t_cdrom_config *) data;
  t_vm   *vm = cfg_get_vm(name);
  t_wake_up_eths *wake_up_eths;
  if (!vm)
    return;
  wake_up_eths = vm->wake_up_eths;
  if (!wake_up_eths)
    return;
  if (strcmp(wake_up_eths->name, name))
    KOUT(" ");
  if (strcmp(cdrom_conf->name, name))
    KOUT(" ");
  if (strstr(cdrom_conf->msg_from_clone, "CDROM_DONE_OK"))
    {
    vm_name = (char *) clownix_malloc(MAX_NAME_LEN, 7);
    memset(vm_name, 0, MAX_NAME_LEN);
    strncpy(vm_name, name, MAX_NAME_LEN-1);
    clownix_timeout_add(100, timeout_start_vm_create_automaton,
                        (void *) vm_name, NULL, NULL);
    clownix_free(data, __FUNCTION__);
    }
  else
    {
    sprintf(err, "ERROR CDROM when creating %s detail: %s", 
            name, cdrom_conf->msg_from_clone);
    event_print(err);
    send_status_ko(wake_up_eths->llid, wake_up_eths->tid, err);
    utils_launched_vm_death(name, error_death_cdrom);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void cdrom_config_creation(t_vm *vm, int nb_eth) 
{
  char *genisobin = util_get_genisoimage();
  t_cdrom_config *cdrom_conf;
  char *tmp_conf  = utils_dir_conf_tmp(vm->vm_id);
  char *cdrom_path = utils_get_cdrom_path_name(vm->vm_id);
  if (access(genisobin, X_OK))
    KOUT("%s not found", genisobin);
  if (access(tmp_conf, F_OK))
    KOUT("%s not found", tmp_conf);
  cdrom_conf = (t_cdrom_config *) clownix_malloc(sizeof(t_cdrom_config), 13); 
  memset(cdrom_conf, 0, sizeof(t_cdrom_config));
  strncpy(cdrom_conf->name, vm->vm_params.name, MAX_NAME_LEN-1);
  cdrom_conf->vm_id = vm->vm_id;
  cdrom_conf->nb_eth = nb_eth;
  cdrom_conf->has_p9_host_share = vm->vm_params.vm_config_flags & 
                                 VM_CONFIG_FLAG_9P_SHARED;
  strncpy(cdrom_conf->tmp_conf, tmp_conf, MAX_PATH_LEN-1);
  strncpy(cdrom_conf->cdrom_path, cdrom_path, MAX_PATH_LEN-1);
  pid_clone_launch(fct_in_clone_context, death_of_clone_in_main_context,
                   msg_from_clone_in_main_context, 
                   cdrom_conf, cdrom_conf, cdrom_conf,
                   vm->vm_params.name, -1, 1);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void cdrom_config_creation_request(t_vm *vm, int nb_eth, 
                                  int vm_config_flags) 
{
  cdrom_config_creation(vm, nb_eth);
}
/*---------------------------------------------------------------------------*/

