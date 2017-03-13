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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include "io_clownix.h"
#include "lib_commons.h"



/*****************************************************************************/
static int my_rand(int max)
{
  unsigned int result = rand();
  result %= max;
  return (int) result;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static void random_choice_str(char *name, int max_len)
{
  int i, len = my_rand(max_len-1);
  len += 1;
  memset (name, 0 , max_len);
  for (i=0; i<len; i++)
    name[i] = 'A'+ my_rand(26);
  name[len] = 0;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static void topo_vlg_gen(t_lan_group *vlg)
{
  int i, len;
  vlg->nb_lan = my_rand(5);
  len = vlg->nb_lan * sizeof(t_lan_group_item);
  vlg->lan = (t_lan_group_item *) clownix_malloc(len, 3);
  memset(vlg->lan, 0, len);
  for (i=0; i<vlg->nb_lan; i++)
    {
    random_choice_str(vlg->lan[i].name, MAX_NAME_LEN);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
t_topo_info *random_topo_gen(void)
{
  int i,j,k,l, nb_vm, nb_sat;
  t_topo_info  *topo;
  t_sat_item *sati = NULL;
  t_vm_item  *vmit = NULL;
  topo = (t_topo_info *) clownix_malloc(sizeof(t_topo_info), 3);
  memset(topo, 0, sizeof(t_topo_info));
  nb_vm  = my_rand(30);
  nb_sat = my_rand(10);
  if (nb_vm)
    {
    vmit = (t_vm_item *) clownix_malloc(nb_vm * sizeof(t_vm_item), 3);
    memset(vmit, 0, nb_vm * sizeof(t_vm_item));
    }
  if (nb_sat)
    {
    sati = (t_sat_item *) clownix_malloc(nb_sat * sizeof(t_sat_item), 3);
    memset(sati, 0, nb_sat * sizeof(t_sat_item));
    }
  for (i=0; i<nb_vm; i++)
    {
    random_choice_str(vmit[i].vm_params.name, MAX_NAME_LEN);
    random_choice_str(vmit[i].vm_params.install_cdrom, MAX_PATH_LEN);
    random_choice_str(vmit[i].vm_params.added_cdrom, MAX_PATH_LEN);
    random_choice_str(vmit[i].vm_params.added_disk, MAX_PATH_LEN);
    random_choice_str(vmit[i].vm_params.p9_host_share, MAX_PATH_LEN);
    random_choice_str(vmit[i].vm_params.linux_kernel, MAX_NAME_LEN);

    random_choice_str(vmit[i].vm_params.rootfs_used, MAX_PATH_LEN);
    random_choice_str(vmit[i].vm_params.rootfs_backing, MAX_PATH_LEN);

    vmit[i].vm_params.cpu = rand();
    vmit[i].vm_params.mem = (rand()%500)+10;
    vmit[i].vm_params.nb_eth    = my_rand(MAX_ETH_VM);
    if (vmit[i].vm_params.nb_eth == 0)
      vmit[i].vm_params.nb_eth = 1;
    for (k=0; k < vmit[i].vm_params.nb_eth; k++)
      {
      for (l=0; l < MAC_ADDR_LEN; l++)
        {
        vmit[i].vm_params.eth_params[k].mac_addr[l] = rand() & 0xFF;
        }
      vmit[i].vm_params.eth_params[k].is_promisc = rand();
      }
    vmit[i].vm_id     = rand();
    vmit[i].vm_params.vm_config_flags = rand();
    if (rand() % 2)
      {
      vmit[i].vm_params.vm_config_flags |= VM_CONFIG_FLAG_PERSISTENT;
      vmit[i].vm_params.vm_config_flags &= ~VM_CONFIG_FLAG_EVANESCENT;
      }
    else
      {
      vmit[i].vm_params.vm_config_flags &= ~VM_CONFIG_FLAG_PERSISTENT;
      vmit[i].vm_params.vm_config_flags |= VM_CONFIG_FLAG_EVANESCENT;
      }
    for (j=0; j<vmit[i].vm_params.nb_eth; j++)
      {
      if (j == 0)
        {
        vmit[i].lan_eth[j].nb_lan = 0;
        vmit[i].lan_eth[j].lan = (t_lan_group_item *) clownix_malloc(0, 3);
        }
      else
        topo_vlg_gen(&(vmit[i].lan_eth[j]));
      }
    }
  for (i=0; i<nb_sat; i++)
    {

    random_choice_str(sati[i].name, MAX_NAME_LEN);
    sati[i].musat_type = rand();

    random_choice_str(sati[i].snf_info.recpath, MAX_PATH_LEN);
    sati[i].snf_info.capture_on = rand();

    sati[i].c2c_info.is_peered = rand();
    sati[i].c2c_info.local_is_master = rand();
    random_choice_str(sati[i].c2c_info.master_cloonix, MAX_NAME_LEN);
    random_choice_str(sati[i].c2c_info.slave_cloonix, MAX_NAME_LEN);
    sati[i].c2c_info.ip_slave = rand();
    sati[i].c2c_info.port_slave = rand();

    topo_vlg_gen(&(sati[i].lan0_sat));
    topo_vlg_gen(&(sati[i].lan1_sat));

    }
  topo->nb_vm    = nb_vm;
  topo->vmit     = vmit;
  random_choice_str(topo->cloonix_config.network_name,MAX_NAME_LEN);
  random_choice_str(topo->cloonix_config.username,MAX_NAME_LEN);
  topo->cloonix_config.server_port = rand();
  random_choice_str(topo->cloonix_config.bin_dir,MAX_PATH_LEN);
  random_choice_str(topo->cloonix_config.tmux_bin,MAX_PATH_LEN);
  random_choice_str(topo->cloonix_config.work_dir,MAX_PATH_LEN);
  random_choice_str(topo->cloonix_config.bulk_dir,MAX_PATH_LEN);
  topo->nb_sat  = nb_sat;
  topo->sati      = sati;
  return topo;
}
/*---------------------------------------------------------------------------*/




/*****************************************************************************/
static int topo_vlg_diff(t_lan_group *vlg, t_lan_group *ref)
{
  int i;
  if (vlg->nb_lan != ref->nb_lan)
    return 1;
  for (i=0; i<vlg->nb_lan; i++)
    {
    if (strcmp(vlg->lan[i].name, ref->lan[i].name))
      return 1;
    }
  return 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int topo_info_diff(t_topo_info *topo, t_topo_info *ref)
{
  int i,j;
  char *ptr1, *ptr2;
  if (topo->nb_vm  != ref->nb_vm)
    return 1;
  if (topo->nb_sat != ref->nb_sat)
    return 2;

  for (i=0; i<ref->nb_vm; i++)
    {
    for (j=0; j<topo->vmit[i].vm_params.nb_eth; j++)
      {
      if (topo->vmit[i].vm_params.eth_params[j].is_promisc !=
          ref->vmit[i].vm_params.eth_params[j].is_promisc)
        return 6;
      if (memcmp(topo->vmit[i].vm_params.eth_params[j].mac_addr,
          ref->vmit[i].vm_params.eth_params[j].mac_addr, MAC_ADDR_LEN))
        return 7;
      }

    ptr1 = strrchr(topo->vmit[i].vm_params.install_cdrom, '/');
    ptr2 = strrchr(ref->vmit[i].vm_params.install_cdrom, '/');
    if ((ptr1 && !ptr2) || (ptr2 && !ptr1))
      return 12;
    if (ptr1 && (strcmp(ptr1, ptr2)))
      return 13;

    ptr1 = strrchr(topo->vmit[i].vm_params.added_cdrom, '/');
    ptr2 = strrchr(ref->vmit[i].vm_params.added_cdrom, '/');
    if ((ptr1 && !ptr2) || (ptr2 && !ptr1))
      return 12;
    if (ptr1 && (strcmp(ptr1, ptr2)))
      return 13;



    ptr1 = strrchr(topo->vmit[i].vm_params.added_disk, '/');
    ptr2 = strrchr(ref->vmit[i].vm_params.added_disk, '/');
    if ((ptr1 && !ptr2) || (ptr2 && !ptr1))
      return 12;
    if (ptr1 && (strcmp(ptr1, ptr2)))
      return 13;

    ptr1 = strrchr(topo->vmit[i].vm_params.p9_host_share, '/');
    ptr2 = strrchr(ref->vmit[i].vm_params.p9_host_share, '/');
    if ((ptr1 && !ptr2) || (ptr2 && !ptr1))
      return 1114;
    if (ptr1 && (strcmp(ptr1, ptr2)))
      return 1115;



    if (topo->vmit[i].vm_params.mem != ref->vmit[i].vm_params.mem)
      return 16;
    if (topo->vmit[i].vm_params.cpu != ref->vmit[i].vm_params.cpu)
      return 17;

    if (strcmp(topo->vmit[i].vm_params.name, ref->vmit[i].vm_params.name))
      return 18;
    if (strcmp(topo->vmit[i].vm_params.linux_kernel,
               ref->vmit[i].vm_params.linux_kernel))
      return 19;
    if (strcmp(topo->vmit[i].vm_params.rootfs_input,
               ref->vmit[i].vm_params.rootfs_input))
      return 20;
    if (strcmp(topo->vmit[i].vm_params.rootfs_used,
               ref->vmit[i].vm_params.rootfs_used))
      return 20;
    if (strcmp(topo->vmit[i].vm_params.rootfs_backing,
               ref->vmit[i].vm_params.rootfs_backing))
      return 21;
    if (topo->vmit[i].vm_id   != ref->vmit[i].vm_id)
      return 22;
    if (topo->vmit[i].vm_params.vm_config_flags != ref->vmit[i].vm_params.vm_config_flags)
      return 24;
    if (topo->vmit[i].vm_params.nb_eth  != ref->vmit[i].vm_params.nb_eth)
      return 26;
    for (j=0; j<topo->vmit[i].vm_params.nb_eth; j++)
      if (topo_vlg_diff(&(topo->vmit[i].lan_eth[j]),&(ref->vmit[i].lan_eth[j])))
        return 28;
    }
  for (i=0; i<ref->nb_sat; i++)
    {
    if (strcmp(topo->sati[i].name, ref->sati[i].name))
      return 120;
    if (topo->sati[i].musat_type != ref->sati[i].musat_type)
      return 120;

    if (strcmp(topo->sati[i].snf_info.recpath, ref->sati[i].snf_info.recpath))
      return 121;
    if (topo->sati[i].snf_info.capture_on != ref->sati[i].snf_info.capture_on)
      return 122;
    if (topo->sati[i].c2c_info.is_peered != ref->sati[i].c2c_info.is_peered)
      return 381;
    if (topo->sati[i].c2c_info.local_is_master != ref->sati[i].c2c_info.local_is_master)
      return 383;
    if (strcmp(topo->sati[i].c2c_info.master_cloonix, ref->sati[i].c2c_info.master_cloonix))
      return 37;
    if (strcmp(topo->sati[i].c2c_info.slave_cloonix, ref->sati[i].c2c_info.slave_cloonix))
      return 38;
    if (topo->sati[i].c2c_info.ip_slave != ref->sati[i].c2c_info.ip_slave)
      return 363;
    if (topo->sati[i].c2c_info.port_slave != ref->sati[i].c2c_info.port_slave)
      return 364;

    if (topo_vlg_diff(&(topo->sati[i].lan0_sat), &(ref->sati[i].lan0_sat)))
      return 130;
    if (topo_vlg_diff(&(topo->sati[i].lan1_sat), &(ref->sati[i].lan1_sat)))
      return 130;
    }

  if (strcmp(topo->cloonix_config.network_name,
             ref->cloonix_config.network_name))
    return 150;
  if (strcmp(topo->cloonix_config.username,
             ref->cloonix_config.username))
    return 151;
  if (topo->cloonix_config.server_port !=  ref->cloonix_config.server_port)
    return 125;
  if (strcmp(topo->cloonix_config.work_dir,       
             ref->cloonix_config.work_dir))
    return 170;
  if (strcmp(topo->cloonix_config.bulk_dir,  ref->cloonix_config.bulk_dir))
    return 181;
  if (strcmp(topo->cloonix_config.bin_dir,    ref->cloonix_config.bin_dir))
    return 191;
  if (strcmp(topo->cloonix_config.tmux_bin,    ref->cloonix_config.tmux_bin))
    return 192;
  return 0;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void topo_vlg_dup(t_lan_group *vlg, t_lan_group *ref)
{
  int i, len;
  vlg->nb_lan = ref->nb_lan;
  len = vlg->nb_lan * sizeof(t_lan_group_item);
  vlg->lan = (t_lan_group_item *) clownix_malloc(len, 3);
  memset(vlg->lan, 0, len);
  for (i=0; i<vlg->nb_lan; i++)
    {
    strncpy(vlg->lan[i].name, ref->lan[i].name, MAX_NAME_LEN-1);
    }
}
/*---------------------------------------------------------------------------*/




/*****************************************************************************/
t_topo_info *topo_info_dup(t_topo_info *ref)
{
  int i,j, nb_vm, nb_sat;
  t_topo_info  *topo;
  t_sat_item   *sati = NULL;
  t_vm_item    *vmit = NULL;
  topo = (t_topo_info *) clownix_malloc(sizeof(t_topo_info), 3);
  memset(topo, 0, sizeof(t_topo_info));
  nb_vm  = ref->nb_vm;
  nb_sat = ref->nb_sat;
  if (nb_vm)
    {
    vmit = (t_vm_item *) clownix_malloc(nb_vm * sizeof(t_vm_item), 3);
    memset(vmit, 0, nb_vm * sizeof(t_vm_item));
    }
  if (nb_sat)
    {
    sati = (t_sat_item *)clownix_malloc(nb_sat*sizeof(t_sat_item),3);
    memset(sati, 0, nb_sat*sizeof(t_sat_item));
    }
  for (i=0; i<nb_vm; i++)
    {
    memcpy(&(vmit[i].vm_params), &(ref->vmit[i].vm_params), sizeof(t_vm_params));
    vmit[i].vm_id     = ref->vmit[i].vm_id;
    for (j=0; j<vmit[i].vm_params.nb_eth; j++)
      topo_vlg_dup(&(vmit[i].lan_eth[j]), &(ref->vmit[i].lan_eth[j]));
    }
  for (i=0; i<nb_sat; i++)
    {
    strncpy(sati[i].name, ref->sati[i].name, MAX_NAME_LEN-1);
    sati[i].musat_type = ref->sati[i].musat_type;
    memcpy(&(sati[i].snf_info), &(ref->sati[i].snf_info), sizeof(t_snf_info));
    memcpy(&(sati[i].c2c_info), &(ref->sati[i].c2c_info), sizeof(t_c2c_info));
    topo_vlg_dup(&(sati[i].lan0_sat), &(ref->sati[i].lan0_sat));
    topo_vlg_dup(&(sati[i].lan1_sat), &(ref->sati[i].lan1_sat));
    }
  memcpy(&(topo->cloonix_config), &(ref->cloonix_config),
        sizeof(t_cloonix_config));
  topo->nb_vm     = nb_vm;
  topo->vmit      = vmit;
  topo->nb_sat    = nb_sat;
  topo->sati      = sati;
  return topo;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
void topo_info_free(t_topo_info *topo)
{
  int i, j;
  if (topo)
    {
    for (i=0; i<topo->nb_vm; i++)
      {
      for (j=0; j < topo->vmit[i].vm_params.nb_eth; j++)
        clownix_free(topo->vmit[i].lan_eth[j].lan, __FUNCTION__);
      }
    for (i=0; i<topo->nb_sat; i++)
      {
      clownix_free(topo->sati[i].lan0_sat.lan, __FUNCTION__);
      clownix_free(topo->sati[i].lan1_sat.lan, __FUNCTION__);
      }

    clownix_free(topo->vmit, __FUNCTION__);
    clownix_free(topo->sati, __FUNCTION__);
    clownix_free(topo, __FUNCTION__);
    }
}
/*---------------------------------------------------------------------------*/

