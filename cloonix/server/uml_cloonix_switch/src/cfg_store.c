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
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "event_subscriber.h"
#include "lan_to_name.h"
#include "llid_trace.h"
#include "system_callers.h"
#include "commun_daemon.h"
#include "utils_cmd_line_maker.h"
#include "c2c.h"
#include "mueth_events.h"
#include "musat_events.h"
#include "stats_counters.h"
#include "musat_mngt.h"
#include "c2c_utils.h"
#include "layout_rpc.h"
#include "layout_topo.h"






/*---------------------------------------------------------------------------*/
static t_cfg cfg;
static int vm_id_tab[MAX_VM];
static t_zombie *head_zombie;
static int nb_zombie;
static int glob_vm_id;
static t_newborn *head_newborn;
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static t_tux *find_tux(char *name)
{
  int i;
  t_tux *cur = cfg.tux_head;
  t_tux *result = NULL;
  for (i=0; i<cfg.nb_tux; i++)
    {
    if (!cur)
      KOUT(" ");
    if (!strcmp(cur->name, name))
      {
      result = cur;
      break;
      }
    cur = cur->next;
    }
  if (i == cfg.nb_tux)
    if (cur)
      KOUT(" ");
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_vm *find_vm(char *name)
{
  int i;
  t_vm *cur = cfg.vm_head;
  t_vm *result = NULL;
  for (i=0; i<cfg.nb_vm; i++)
    {
    if (!cur)
      KOUT(" ");
    if (!strcmp(cur->vm_params.name, name))
      {
      result = cur;
      break;
      }
    cur = cur->next;
    }
  if (i == cfg.nb_vm)
    if (cur)
      KOUT(" ");
  return result;    
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_name_is_in_use(int is_lan, char *name, char *use)
{
  int result = 0;
  t_sc2c *c2c = c2c_find(name);
  t_tux *tux;
  memset(use, 0, MAX_PATH_LEN);
  tux = find_tux(name);

  if (c2c)
    {
    snprintf(use, MAX_NAME_LEN, "%s is used by a sat c2c", name);
    result = 1;
    }
  else if ((!strcmp(name, "doors")) ||
           (!strcmp(name, "uml_cloonix_switch")))
    {
    snprintf(use, MAX_NAME_LEN, "%s is for system use", name);
    result = 1;
    }
  else if (cfg_is_a_zombie(name))
    {
    snprintf(use, MAX_NAME_LEN, "%s is vm zombie", name);
    result = 1;
    }
  else if (cfg_is_a_newborn(name))
    {
    snprintf(use, MAX_NAME_LEN, "%s is vm newborn", name);
    result = 1;
    }
  else if (find_vm(name))
    {
    snprintf(use, MAX_NAME_LEN, "%s is running vm", name);
    result = 1;
    }
  else if (tux)
    {
    if (tux->is_musat)
      {
      if (musat_mngt_is_tap(tux->musat_type))
        snprintf(use, MAX_NAME_LEN, "%s is a tap", name);
      else if (musat_mngt_is_snf(tux->musat_type))
        snprintf(use, MAX_NAME_LEN, "%s is a snf", name);
      else if (musat_mngt_is_a2b(tux->musat_type))
        snprintf(use, MAX_NAME_LEN, "%s is a a2b", name);
      else if (musat_mngt_is_nat(tux->musat_type))
        snprintf(use, MAX_NAME_LEN, "%s is a nat", name);
      else if (musat_mngt_is_c2c(tux->musat_type))
        snprintf(use, MAX_NAME_LEN, "%s is a c2c", name);
      else
        KERR(" ");
      }
    else
      snprintf(use, MAX_NAME_LEN, "%s is a tux", name);
    result = 1;
    }
  else if ((!is_lan) && (lan_get_with_name(name)))
    {
    snprintf(use, MAX_NAME_LEN, "%s is a lan", name);
    result = 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_vm *find_vm_with_id(int vm_id)
{
  int i;
  t_vm *cur = cfg.vm_head;
  t_vm *result = NULL;
  for (i=0; i<cfg.nb_vm; i++)
    {
    if (!cur)
      KOUT(" ");
    if (cur->vm_id == vm_id)
      { 
      result = cur;
      break;
      }
    cur = cur->next;
    }
  if (i == cfg.nb_vm)
    if (cur)
      KOUT(" ");
  return result;   
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_free_vm_id(int vm_id)
{
  if (!vm_id_tab[vm_id])
    KOUT(" ");
  vm_id_tab[vm_id] = 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_alloc_vm_id(void)
{
  int found = glob_vm_id;
  if (vm_id_tab[found])
    KOUT(" ");
  vm_id_tab[found] = 1;
  do
    {
    glob_vm_id += 1;
    if (glob_vm_id == MAX_VM)
      glob_vm_id = 1;
    } while((vm_id_tab[glob_vm_id]) || 
             cfg_is_a_zombie_with_vm_id(glob_vm_id));
  if (find_vm_with_id(found))
    KOUT("%d ", found);
  if (find_vm_with_id(glob_vm_id))
    KOUT("%d ", glob_vm_id);
  if (cfg_is_a_zombie_with_vm_id(found))
    KOUT("%d ", found);
  if (cfg_is_a_zombie_with_vm_id(glob_vm_id))
    KOUT("%d ", glob_vm_id);
  return found;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
t_eth *cfg_find_eth(t_vm *vm, int eth)
{
  int i;
  t_eth *cur;
  t_eth *result = NULL;
  if (vm)
    {
    cur = vm->eth_head;
    for (i=0; i<vm->nb_eth; i++)
      {
      if (!cur)
        KOUT(" ");
      if (cur->eth == eth)
        {
        result = cur;
        break; 
        }
      cur = cur->next;
      }
    if (i == vm->nb_eth)
      if (cur)
        KOUT(" ");
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_tux *alloc_tux(int is_musat, int musat_type, char *name)
{
  t_tux *tmptux = (t_tux *) clownix_malloc(sizeof(t_tux),23);
  memset(tmptux, 0, sizeof(t_tux));
  tmptux->is_musat = is_musat;
  tmptux->musat_type = musat_type;
  strncpy(tmptux->name, name, MAX_NAME_LEN-1);
  return tmptux;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_vm *alloc_vm(t_vm_params *vm_params, int vm_id)
{
  t_vm *vm = (t_vm *) clownix_malloc(sizeof(t_vm),24);
  memset(vm, 0, sizeof(t_vm));
  memcpy(&(vm->vm_params), vm_params, sizeof(t_vm_params));
  vm->vm_id = vm_id;
  return vm;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static t_eth *alloc_eth(int eth, t_vm *vm, char *data)
{ 
  t_eth *tmpeth = (t_eth *) clownix_malloc(sizeof(t_eth),25);
  memset(tmpeth, 0, sizeof(t_eth));
  if (!data)
    KOUT(" ");
  strncpy(tmpeth->data_path, data, MAX_PATH_LEN-1);
  tmpeth->eth = eth;
  tmpeth->vm = vm;
  return tmpeth;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void extract_tux(t_cfg *cf, t_tux *tux)
{
  t_tux *cur;
  if (!tux)
    KOUT(" ");
  if (cf->nb_tux <= 0)
    KOUT(" ");
  cur = cf->tux_head;
  if (cur == tux)
    {
    cf->tux_head = cur->next;
    if (cur->next)
      cur->next->prev = NULL;
    }
  else
    {
    if (tux->next)
      tux->next->prev = tux->prev;
    if (tux->prev)
      tux->prev->next = tux->next;
    }
  cf->nb_tux -= 1;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static void extract_vm(t_cfg *cf, t_vm *vm)
{
  t_vm *cur;
  if (!vm)
    KOUT(" ");
  if (cf->nb_vm <= 0)
    KOUT(" ");
  cur = cf->vm_head;
  if (cur == vm)
    {
    cf->vm_head = cur->next;
    if (cur->next)
      cur->next->prev = NULL;
    }
  else
    {
    if (vm->next)
      vm->next->prev = vm->prev;
    if (vm->prev)
      vm->prev->next = vm->next;
    }
  cf->nb_vm -= 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void extract_eth_vm(t_vm *vm, t_eth *eth)
{
  t_eth *cur;
  if ((!vm)||(!eth))
    KOUT(" ");
  if (vm->nb_eth <= 0)
    KOUT(" ");
  cur = vm->eth_head;
  if (cur == eth)
    {
    vm->eth_head = cur->next;
    if (cur->next)
      cur->next->prev = NULL;
    }
  else 
    {
    if (eth->next)
      eth->next->prev = eth->prev;
    if (eth->prev)
      eth->prev->next = eth->next;
    }
  vm->nb_eth -= 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void insert_eth_vm(t_vm *vm, t_eth *eth)
{
  int i;
  t_eth *cur;
  if ((!eth)||(!vm))
    KOUT(" ");
  cur = vm->eth_head;
  if (vm->nb_eth > 0)
    {
    for(i=0; i < vm->nb_eth - 1; i++)
      {
      if (!cur)
        KOUT(" ");
      cur = cur->next;
      }
    if (cur->next)
      KOUT(" ");
    cur->next = eth;
    eth->prev = cur;
    }
  else
    {
    if (vm->nb_eth != 0)
      KOUT(" ");
    if (cur)
      KOUT(" ");
    vm->eth_head = eth;
    }
  vm->nb_eth += 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void insert_vm(t_vm *vm)
{
  int i;
  t_vm *cur;
  if (!vm)
    KOUT(" ");
  cur = cfg.vm_head;
  if (cfg.nb_vm > 0)
    {
    for(i=0; i < cfg.nb_vm - 1; i++)
      {
      if (!cur)
        KOUT(" ");
      cur = cur->next;
      }
    if (cur->next)
      KOUT(" ");
    cur->next = vm;
    vm->prev = cur;
    }
  else
    {
    if (cfg.nb_vm != 0)
      KOUT(" ");
    if (cur)
      KOUT(" ");
    cfg.vm_head = vm;
    }
  cfg.nb_vm += 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void insert_tux(t_tux *tux)
{
  int i;
  t_tux *cur;
  if (!tux)
    KOUT(" ");
  cur = cfg.tux_head;
  if (cfg.nb_tux > 0)
    {
    for(i=0; i < cfg.nb_tux - 1; i++)
      {
      if (!cur)
        KOUT(" ");
      cur = cur->next;
      }
    if (cur->next)
      KOUT(" ");
    cur->next = tux;
    tux->prev = cur;
    }
  else
    {
    if (cfg.nb_tux != 0)
      KOUT(" ");
    if (cur)
      KOUT(" ");
    cfg.tux_head = tux;
    }
  cfg.nb_tux += 1;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
int cfg_set_tux(int is_musat, int musat_type, char *name, int llid)
{
  int result = -1;
  t_tux *tmptux = find_tux(name);
  if (!tmptux)
    {
    tmptux = alloc_tux(is_musat, musat_type, name);
    insert_tux(tmptux);
    result = 0;
    event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    if (is_musat)
      layout_add_sat(name, llid);
    }
  return result;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
int cfg_unset_tux(char *name)
{
  int result = -1;
  t_tux *tmptux = find_tux(name);
  if (tmptux)
    {
    if (tmptux->is_musat)
      {
      musat_mngt_update_unset_tux_action(name, tmptux);
      layout_del_sat(name);
      }
    unlink(utils_get_tux_path(name));
    extract_tux(&cfg, tmptux);
    stats_counters_sat_death(name);
    clownix_free(tmptux, __FUNCTION__);
    event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
    result = 0;
    }
  return result;
} 
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_set_vm(t_vm_params *vm_params, int vm_id, int llid)
{
  int result = -1;
  t_vm *vm = find_vm(vm_params->name);
  if (!vm)
    {
    vm = alloc_vm(vm_params, vm_id);
    insert_vm(vm);
    layout_add_vm(vm_params->name, llid);
    musat_mngt_add_vm(vm_params->name, vm_id, 
                      vm_params->nb_eth, 
                      vm_params->eth_params);
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_unset_eth(t_vm *vm, t_eth *eth)
{
  char *name = vm->vm_params.name;
  int lan = eth->lan_attached.lan;
  extract_eth_vm(vm, eth);
  if (lan)
    {
    KERR("ERROR %s %d", name, lan);
    }
  if (strncmp(eth->data_path, cfg_get_work(), strlen(cfg_get_work())))
    KOUT("%s %s\n", eth->data_path, cfg_get_work());
  unlink(eth->data_path);
  clownix_free(eth, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_unset_vm(t_vm *vm)
{
  int vm_id = vm->vm_id;

  if (vm->wake_up_eths != NULL)
    {
    KERR("BUG %s", vm->vm_params.name);
    free_wake_up_eths(vm);
    }
  musat_mngt_del_vm(vm->vm_params.name, vm_id, 
                    vm->vm_params.nb_eth, 
                    vm->vm_params.eth_params);
  layout_del_vm(vm->vm_params.name);
  extract_vm(&cfg, vm);
  clownix_free(vm, __FUNCTION__);
  llid_trace_vm_delete(vm_id);
  return vm_id;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_set_eth(t_vm_params *vm_params, int eth, char *data)
{
  int result = -1;
  t_vm *vm = find_vm(vm_params->name);
  t_eth *tmpeth;
  if (vm)
    {
    tmpeth = cfg_find_eth(vm, eth);
    if (!tmpeth)
      {
      tmpeth = alloc_eth(eth, vm, data);
      insert_eth_vm(vm, tmpeth);
      result = 0;
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_set_eth_lan(char *name, int num, char *lan, int llid_req)
{
  int result = -1;
  t_vm *vm = find_vm(name);
  t_eth *tmpeth;
  int lan_num;
  if (vm)
    {
    tmpeth = cfg_find_eth(vm, num);
    if (tmpeth)
      {
      if (tmpeth->lan_attached.lan == 0)
        {
        lan_num = lan_add_name(lan, llid_req);
        if ((lan_num <= 0) || (lan_num >= MAX_LAN))
          KOUT("%s", lan);
        tmpeth->lan_attached.lan = lan_num;
        result = 0;
        }
      else
        KERR(" %s %d %s", name, num, lan);
      }
    else
      KERR(" %s %d ", name, num);
    }
  else
    KERR(" %s %d ", name, num);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_unset_eth_lan(char *name, int num, char *lan)
{
  int lan_num, result = -1;
  t_vm *vm = find_vm(name);
  t_eth *tmpeth;
  lan_num = lan_get_with_name(lan);
  if (vm)
    {
    if ((lan_num <= 0) || (lan_num >= MAX_LAN))
      KERR("%s %d %s", name, num, lan);
    else
      {
      tmpeth = cfg_find_eth(vm, num);
      if (tmpeth) 
        {
        if (tmpeth->lan_attached.lan == lan_num)
          {
          if (lan_del_name(lan) != lan_num)
            KOUT("%s", lan);
          memset(&(tmpeth->lan_attached), 0, sizeof(t_lan_attached));
          result = 0;
          }
        else
          KERR("%s %d %s", name, num, lan);
        }
      else
        KERR("%s %d %s", name, num, lan);
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_set_tux_lan(char *tux, int num, char *lan, int llid_req)
{
  int lan_num, result = -1;
  t_tux *tmptux = find_tux(tux);
  if ((num != 0) && (num != 1))
    KOUT("%d", num);
  if (tmptux)
    {
    if (tmptux->lan_attached[num].lan == 0)
      {
      lan_num = lan_add_name(lan, llid_req);
      if ((lan_num <= 0) || (lan_num >= MAX_LAN))
        KOUT("%d", lan_num);
      tmptux->lan_attached[num].lan = lan_num;
      event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
      result = 0;
      }
    else
      KERR("%s %d", tux, num); 
    }
  else
    KERR("%s %d", tux, num); 
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_unset_tux_lan(char *name, int num, char *lan)
{
  int lan_num, result = -1;
  t_tux *tmptux = find_tux(name);
  lan_num = lan_get_with_name(lan);
  if ((lan_num <= 0) || (lan_num >= MAX_LAN))
    KOUT("%d", lan_num);
  if ((num != 0) && (num != 1))
    KOUT("%d", num);
  if (tmptux)
    {
    if (tmptux->lan_attached[num].lan == lan_num)
      {
      if (lan_del_name(lan) != lan_num)
        KOUT(" ");
      memset(&(tmptux->lan_attached[num]), 0, sizeof(t_lan_attached));
      result = 0;
      event_subscriber_send(sub_evt_topo, cfg_produce_topo_info());
      }
    else
      KERR("%s %s", lan, name);
    }
  return result;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
t_tux *cfg_get_tux(char *tux)
{
  t_tux *tmptux = find_tux(tux);
  return tmptux;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
t_vm *cfg_get_vm(char *name) 
{
  t_vm *tmpvm = find_vm(name);
  return tmpvm;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_get_eth(char *name, int eth)
{
  int mutype, result = -1;
  t_vm *vm = find_vm(name);
  t_eth *tmpeth;
  if (vm)
    {
    tmpeth = cfg_find_eth(vm, eth);
    if (tmpeth)
      result = 0;
    }
  else
    {
    if ((musat_mngt_exists(name, &mutype)) &&
        (musat_mngt_is_a2b(mutype)))
      {
      if ((eth == 0) || (eth == 1))
        {
        result = 0;
        }
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_check_eth(int vm_id, int eth, char *path)
{
  int result = -1;
  t_vm *vm = find_vm_with_id(vm_id);
  t_eth *tmpeth = cfg_find_eth(vm, eth);
  if (tmpeth)
    {
    result = 0;
    if (path)
      {
      memset(path, 0, MAX_PATH_LEN);
      strncpy(path, tmpeth->data_path, MAX_PATH_LEN-1);
      }
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_vm   *cfg_get_first_vm(int *nb)
{
  *nb = cfg.nb_vm; return cfg.vm_head;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_tux  *cfg_get_first_tux(int *nb)
{
  *nb = cfg.nb_tux; return cfg.tux_head;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_eth  *cfg_get_first_eth(char *name, int *nb)
{
  t_vm *vm = find_vm(name);
  *nb = 0;
  if (vm)
    {
    *nb = vm->nb_eth;
    return (vm->eth_head);
    }
  return NULL;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void cfg_set_lock_fd(int fd)
{
  cfg.lock_fd = fd;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
int  cfg_get_lock_fd(void)
{
  return (cfg.lock_fd);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_zombie *cfg_is_a_zombie_with_vm_id(int vm_id)
{
  int i;
  t_zombie *result = NULL;
  t_zombie *cur = head_zombie;
  for (i=0; i<nb_zombie; i++)
    {
    if (!cur)
      KOUT(" ");
    if (cur->vm_id == vm_id)
      {
      result = cur;
      break;
      }
    cur = cur->next;
    }
  if (!result && cur)
    KOUT(" ");
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_zombie *cfg_is_a_zombie(char *name)
{
  int i;
  t_zombie *result = NULL;
  t_zombie *cur = head_zombie;
  for (i=0; i<nb_zombie; i++)
    {
    if (!cur)
      KOUT(" ");
    if (!strcmp(cur->name, name))
      {
      result = cur;
      break;
      }
    cur = cur->next;
    }
  if (!result && cur)
    KOUT(" ");
  return result; 
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_del_zombie(char *name)
{
  t_zombie *target = cfg_is_a_zombie(name);
  if (target)
    {
    if (target->next)
      target->next->prev = target->prev;
    if (target->prev)
      target->prev->next = target->next;
    if (target == head_zombie)
      head_zombie = target->next;
    clownix_free(target, __FUNCTION__);
    nb_zombie--;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_add_zombie(int vm_id, char *name)
{
  t_zombie *target = (t_zombie *) clownix_malloc(sizeof(t_zombie),26);
  if (cfg_is_a_zombie_with_vm_id(vm_id))
    KOUT("%s %d", name, vm_id);
  memset(target, 0, sizeof(t_zombie));
  strncpy(target->name, name, MAX_NAME_LEN-1);
  target->vm_id = vm_id;
  if (head_zombie)
    head_zombie->prev = target;
  target->next = head_zombie;
  head_zombie = target;
  nb_zombie++;
  if (nb_zombie > MAX_VM-5)
    KOUT("%d %d", nb_zombie, MAX_VM-5);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_add_newborn(char *name)
{
  t_newborn *target = (t_newborn *) clownix_malloc(sizeof(t_newborn),26);
  if (cfg_is_a_newborn(name))
    KOUT("%s", name);
  memset(target, 0, sizeof(t_newborn));
  strncpy(target->name, name, MAX_NAME_LEN-1);
  if (head_newborn)
    head_newborn->prev = target;
  target->next = head_newborn;
  head_newborn = target;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_del_newborn(char *name)
{
  t_newborn *target = cfg_is_a_newborn(name);
  if (target)
    {
    if (target->next)
      target->next->prev = target->prev;
    if (target->prev)
      target->prev->next = target->next;
    if (target == head_newborn)
      head_newborn = target->next;
    clownix_free(target, __FUNCTION__);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_newborn *cfg_is_a_newborn(char *name)
{
  t_newborn *result = NULL;
  t_newborn *cur = head_newborn;
  while (cur)
    {
    if (!strcmp(cur->name, name))
      {
      result = cur;
      break;
      }
    cur = cur->next;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_set_host_conf(t_cloonix_config *conf)
{
  if (cfg.cloonix_config.network_name[0])
    KOUT(" ");
  memcpy(&(cfg.cloonix_config), conf, sizeof(t_cloonix_config));
  snprintf(conf->tmux_bin, MAX_PATH_LEN-1, "%s", utils_get_tmux_bin_path());
  snprintf(cfg.cloonix_config.tmux_bin, MAX_PATH_LEN-1, "%s", 
           utils_get_tmux_bin_path());
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_cloonix_config *cfg_get_cloonix_config(void)
{
  return (&(cfg.cloonix_config));
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_get_server_port(void)
{
  int result = cfg.cloonix_config.server_port;
  if (!result)
    KOUT(" ");
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *cfg_get_ctrl_doors_sock(void)
{
  static char path[MAX_PATH_LEN];
  memset(path, 0, MAX_PATH_LEN);
  sprintf(path, "%s/%s", cfg_get_root_work(), DOORS_CTRL_SOCK);
  return path;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *cfg_get_root_work(void)
{
  if (cfg.cloonix_config.work_dir[0] == 0)
    KOUT(" ");
  return(cfg.cloonix_config.work_dir);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *cfg_get_work(void)
{
  static char path[MAX_PATH_LEN];
  memset(path, 0, MAX_PATH_LEN);
  strncpy(path,cfg_get_root_work(),MAX_PATH_LEN-1-strlen(CLOONIX_VM_WORKDIR));
  strcat(path, "/");
  strcat(path, CLOONIX_VM_WORKDIR);
  return(path);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *cfg_get_work_vm(int vm_id)
{
  static char path[MAX_PATH_LEN];
  memset(path, 0, MAX_PATH_LEN);
  snprintf(path,MAX_PATH_LEN-1, "%s/vm%d", cfg_get_work(), vm_id);
  return(path);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *cfg_get_bin_dir(void)
{
  if (cfg.cloonix_config.bin_dir[0] == 0)
    KOUT(" ");
  return(cfg.cloonix_config.bin_dir);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
char *cfg_get_bulk(void)
{
  static char path[MAX_PATH_LEN];
  if (cfg.cloonix_config.bulk_dir[0] == 0)
    KOUT(" ");
  memset(path, 0, MAX_PATH_LEN);
  sprintf(path,"%s", cfg.cloonix_config.bulk_dir);
  return path;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *cfg_get_cloonix_name(void)
{
  return (cfg.cloonix_config.network_name);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *cfg_get_version(void)
{
  return (cfg.cloonix_config.version);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
int cfg_compute_qty_elements(void)
{
  int i,j, qty, nb_vm, nb_eth, nb_tux;
  t_vm *vm = cfg_get_first_vm(&nb_vm);
  t_eth *eth;
  cfg_get_first_tux(&nb_tux);
  qty = nb_tux;
  for (i=0; i<nb_vm; i++)
    {
    eth = cfg_get_first_eth(vm->vm_params.name, &nb_eth);
    for (j=0; j<nb_eth; j++)
      {
      qty += 1;
      eth = eth->next;
      }
    vm = vm->next;
    }
  return qty;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void topo_vlg(t_lan_group *vlg, int lan)
{
  int i, len;
  if (lan) 
    vlg->nb_lan = 1;
  else
    vlg->nb_lan = 0;
  len = vlg->nb_lan * sizeof(t_lan_group_item);
  vlg->lan = (t_lan_group_item *) clownix_malloc(len, 29);
  memset(vlg->lan, 0, len);
  for (i=0; i<vlg->nb_lan; i++)
    {
    if (!lan_get_with_num(lan))
      KOUT(" ");
    strncpy(vlg->lan[i].name, lan_get_with_num(lan), MAX_NAME_LEN-1); 
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void produce_topovm_item(t_vm *vm, t_vm_item *vi)
{
  int i;
  t_eth *eth = vm->eth_head;
  memcpy(&(vi->vm_params), &(vm->vm_params), sizeof(t_vm_params)); 
  vi->vm_id     = vm->vm_id;
  for (i=0; i<vm->nb_eth; i++)
    {
    topo_vlg(&(vi->lan_eth[i]), eth->lan_attached.lan); 
    eth = eth->next;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_topo_info *cfg_produce_topo_info(void)
{
  int i, j, nb_vm, nb_tux, nb_sat;
  t_vm  *vm  = cfg_get_first_vm(&nb_vm);
  t_tux *tux = cfg_get_first_tux(&nb_tux);
  t_topo_info  *topo = (t_topo_info *) clownix_malloc(sizeof(t_topo_info),17);
  t_sat_item *si = NULL;
  t_vm_item  *vi = NULL;

  memset(topo, 0, sizeof(t_topo_info));
  if (nb_vm)
    {
    vi = (t_vm_item *) clownix_malloc(nb_vm * sizeof(t_vm_item),17); 
    memset(vi, 0, nb_vm * sizeof(t_vm_item));
    }
  if (nb_tux)
    {
    si = (t_sat_item *) clownix_malloc(nb_tux * sizeof(t_sat_item),17);
    memset(si, 0, nb_tux * sizeof(t_sat_item));
    }
  for (i=0; i<nb_vm; i++)
    {
    produce_topovm_item(vm, &(vi[i]));
    vm = vm->next;
    }
  for (i=0, j=0; i<nb_tux; i++)
    { 
    if (tux->is_musat)
      { 
      if ((musat_mngt_is_c2c(tux->musat_type)) ||
          (musat_event_exists(tux->name)))
        {
        si[j].musat_type = tux->musat_type;
        strncpy(si[j].name, tux->name, MAX_NAME_LEN-1);
        memcpy(&(si[j].snf_info), &(tux->snf_info), sizeof(t_snf_info));
        memcpy(&(si[j].c2c_info), &(tux->c2c_info), sizeof(t_c2c_info));
        topo_vlg(&(si[j].lan0_sat), tux->lan_attached[0].lan);
        topo_vlg(&(si[j].lan1_sat), tux->lan_attached[1].lan);
        j++;
        }
      }
    tux = tux->next;
    }
  nb_sat = j;

  memcpy(&(topo->cloonix_config), &(cfg.cloonix_config), 
         sizeof(t_cloonix_config));
  topo->nb_vm    = nb_vm;
  topo->vmit       = vi;
  topo->nb_sat   = nb_sat;
  topo->sati       = si;
  return topo;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_get_vm_locked(t_vm *vm)
{
return (vm->locked_vm);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_set_vm_locked(t_vm *vm)
{
  vm->locked_vm = 1;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_reset_vm_locked(t_vm *vm)
{
  vm->locked_vm = 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_insert_c2c_to_topo(int local_is_master, char *name, 
                           char *master_cloonix, char *slave_cloonix)
{
  int result = -1;
  t_tux *tux = cfg_get_tux(name);
  if (tux)
    {
    if ((tux->is_musat) && (musat_mngt_is_c2c(tux->musat_type)))
      {
      tux->c2c_info.local_is_master = local_is_master;
      strncpy(tux->c2c_info.master_cloonix, master_cloonix, MAX_NAME_LEN-1);
      strncpy(tux->c2c_info.slave_cloonix, slave_cloonix, MAX_NAME_LEN-1);
      result = 0;
      }
    else
      KERR("%s", name);
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_remove_c2c_from_topo(char *name)
{
  int result = -1;
  t_tux *tux;
  tux = cfg_get_tux(name);
  if (tux)
    {
    if ((tux->is_musat) && (musat_mngt_is_c2c(tux->musat_type)))
      {
      cfg_unset_tux(name);
      result = 0;
      }
    else
      KERR("%s", name);
    }
  else
    KERR("%s", name);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_exists_c2c_from_topo(char *name)
{
  int result = 0;
  t_tux *tux;
  tux = cfg_get_tux(name);
  if (tux)
    {
    if ((tux->is_musat) && (musat_mngt_is_c2c(tux->musat_type)))
      result = 1;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_tux *cfg_get_c2c_tux(char *name)
{
  t_tux *result = NULL;
  t_tux *tux;
  tux = cfg_get_tux(name);
  if (tux)
    {
    if ((tux->is_musat) && (musat_mngt_is_c2c(tux->musat_type)))
      result = tux;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_c2c_is_peered(char *name, int is_peered)
{
  t_tux *tux;
  tux = cfg_get_tux(name);
  if (tux)
    {
    if ((tux->is_musat) && (musat_mngt_is_c2c(tux->musat_type)))
      tux->c2c_info.is_peered = is_peered;
    else
      KERR("%s", name);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cfg_get_musat_type(char *name)
{
  t_tux *tux = cfg_get_tux(name);
  int type = -1; 
  if (tux->is_musat)
    {
    type = tux->musat_type;
    }
  return type;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cfg_init(void)
{
  memset(&cfg, 0, sizeof(t_cfg));
  memset(vm_id_tab, 0, MAX_VM * sizeof(int));
  head_zombie = NULL;
  nb_zombie = 0;
  glob_vm_id = 1;;
}
/*---------------------------------------------------------------------------*/
