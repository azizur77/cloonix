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

/****************************************************************************/
int topo_find_vm_in_topo(char *name, t_topo_info *topo)
{
  int i, found = 0;
  for (i=0; i< topo->nb_vm; i++)
    if (!strcmp(name, topo->vmit[i].vm_params.name))
      {
      found = 1;
      break;
      }
  return found;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int topo_find_sat_in_topo(char *sat, t_topo_info *topo)
{
  int i, found = 0;
  for (i=0; i< topo->nb_sat; i++)
    if (!strcmp(topo->sati[i].name, sat))
      {
      found = 1;
      break;
      }
  return found;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int topo_find_lan_in_topo(char *lan, t_topo_info *topo)
{
  int i, j, k, found = 0;
  for (i=0; (found==0) && (i<topo->nb_vm); i++)
    for (j=0; (found==0) && (j<topo->vmit[i].vm_params.nb_eth); j++)
      for (k=0; (found==0) && (k<topo->vmit[i].lan_eth[j].nb_lan); k++)
        {
        if (!strcmp(lan, topo->vmit[i].lan_eth[j].lan[k].name))
          found = 1;
        }
  for (i=0; (found==0) && (i< topo->nb_sat); i++)
    {
    for (j=0; (found==0) && (j<topo->sati[i].lan0_sat.nb_lan); j++)
      {
      if (!strcmp(lan, topo->sati[i].lan0_sat.lan[j].name))
        found = 1;
      }
    for (j=0; (found==0) && (j<topo->sati[i].lan1_sat.nb_lan); j++)
      {
      if (!strcmp(lan, topo->sati[i].lan1_sat.lan[j].name))
        found = 1;
      }
    }
  return found;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int topo_find_edge_eth_in_topo(char *name, int num, char *lan,
                                      t_topo_info *topo)
{
  int i, j, found = 0;
  for (i=0; i<topo->nb_vm; i++)
    {
    if (!strcmp(name, topo->vmit[i].vm_params.name))
      {
      if (num > topo->vmit[i].vm_params.nb_eth)
        KOUT("%d %d", num, topo->vmit[i].vm_params.nb_eth);
      if (num < 0)
        KOUT(" ");
      for (j=0; j<topo->vmit[i].lan_eth[num].nb_lan; j++)
        {
        if (!strcmp(topo->vmit[i].lan_eth[num].lan[j].name, lan))
          found = 1;
        }
      break;
      }
    }
  if (found == 0)
    {
    for (i=0; i< topo->nb_sat; i++)
      {
      if (!strcmp(topo->sati[i].name, name))
        {
        if (num == 0)
          {
          for (j=0; j<topo->sati[i].lan0_sat.nb_lan; j++)
            {
            if (!strcmp(topo->sati[i].lan0_sat.lan[j].name, lan))
              found = 1;
            }
          }
        else if (num == 1)
          {
          for (j=0; j<topo->sati[i].lan1_sat.nb_lan; j++)
            {
            if (!strcmp(topo->sati[i].lan1_sat.lan[j].name, lan))
              found = 1;
            }
          }
        else
          KOUT("%d", num);
        break;
        }
      }
    }
  return found;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
t_topo_node_chain *topo_get_node_chain(t_topo_info *topo)
{
  int i;
  t_topo_node_chain *cur, *res = NULL;
  for (i=0; i< topo->nb_vm; i++)
    {
    cur = (t_topo_node_chain *) clownix_malloc(sizeof(t_topo_node_chain), 3); 
    memset(cur, 0, sizeof(t_topo_node_chain));
    strncpy(cur->name, topo->vmit[i].vm_params.name, MAX_NAME_LEN-1);
    strncpy(cur->kernel, topo->vmit[i].vm_params.linux_kernel, MAX_NAME_LEN-1);
    cur->vm_config_flags = topo->vmit[i].vm_params.vm_config_flags;

    strncpy(cur->rootfs_used, 
            topo->vmit[i].vm_params.rootfs_used, MAX_PATH_LEN-1);
    strncpy(cur->rootfs_backing, 
            topo->vmit[i].vm_params.rootfs_backing, MAX_PATH_LEN-1);

    strncpy(cur->node_bdisk, topo->vmit[i].vm_params.bdisk, MAX_PATH_LEN-1);
    cur->vm_id = topo->vmit[i].vm_id;
    cur->num_eth = topo->vmit[i].vm_params.nb_eth;
    cur->next = res;
    if (res)
      res->prev = cur;
    res = cur;
    }
  return res;
}
/*--------------------------------------------------------------------------*/
/*****************************************************************************/
t_topo_sat_chain *topo_get_sat_chain(t_topo_info *topo)
{
  int i;
  t_topo_sat_chain *cur, *res = NULL;
  for (i=0; i< topo->nb_sat; i++)
    {
    cur = (t_topo_sat_chain *) clownix_malloc(sizeof(t_topo_sat_chain),3);
    memset(cur, 0, sizeof(t_topo_sat_chain));
    strncpy(cur->name, topo->sati[i].name, MAX_NAME_LEN-1);
    cur->musat_type = topo->sati[i].musat_type;
    memcpy(&(cur->snf_info), &(topo->sati[i].snf_info), sizeof(t_snf_info));
    memcpy(&(cur->c2c_info), &(topo->sati[i].c2c_info), sizeof(t_c2c_info));
    cur->next = res;
    if (res)
      res->prev = cur;
    res = cur;
    }
  return res;
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
static int lan_does_not_exist(t_topo_lan_chain *ch, char *lan)
{
  t_topo_lan_chain *cur = ch;
  int result = 1;
  while(cur)
    {
    if (!strcmp(cur->lan, lan))
      {
      result = 0;
      break;
      }
    cur = cur->next;
    }
  return result;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
t_topo_lan_chain *topo_get_lan_chain(t_topo_info *topo)
{
  int i, j, k;
  char *lan;
  t_topo_lan_chain *cur, *res = NULL;
  for (i=0; i<topo->nb_vm; i++)
    for (j=0; j<topo->vmit[i].vm_params.nb_eth; j++)
      for (k=0; k<topo->vmit[i].lan_eth[j].nb_lan; k++)
        {
        lan = topo->vmit[i].lan_eth[j].lan[k].name;
        if (lan_does_not_exist(res, lan))
          {
          cur=(t_topo_lan_chain *)clownix_malloc(sizeof(t_topo_lan_chain),3);
          memset(cur, 0, sizeof(t_topo_lan_chain));
          strncpy(cur->lan, lan, MAX_NAME_LEN-1);
          cur->next = res;
          if (res)
            res->prev = cur;
          res = cur;
          }
        }
  for (i=0; i< topo->nb_sat; i++)
    {
    for (j=0; j<topo->sati[i].lan0_sat.nb_lan; j++)
      {
      lan = topo->sati[i].lan0_sat.lan[j].name;
      if (lan_does_not_exist(res, lan))
        {
        cur=(t_topo_lan_chain *)clownix_malloc(sizeof(t_topo_lan_chain),3);
        memset(cur, 0, sizeof(t_topo_lan_chain));
        strncpy(cur->lan, lan, MAX_NAME_LEN-1);
        cur->next = res;
        if (res)
          res->prev = cur;
        res = cur;
        }
      }
    for (j=0; j<topo->sati[i].lan1_sat.nb_lan; j++)
      {
      lan = topo->sati[i].lan1_sat.lan[j].name;
      if (lan_does_not_exist(res, lan))
        {
        cur=(t_topo_lan_chain *)clownix_malloc(sizeof(t_topo_lan_chain),3);
        memset(cur, 0, sizeof(t_topo_lan_chain));
        strncpy(cur->lan, lan, MAX_NAME_LEN-1);
        cur->next = res;
        if (res)
          res->prev = cur;
        res = cur;
        }
      }
    }
  return res;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
t_topo_edge_eth_chain *topo_get_edge_eth_node_chain(t_topo_info *topo)
{
  int i, j, k, len = sizeof(t_topo_edge_eth_chain);
  t_topo_edge_eth_chain *cur, *res = NULL;
  for (i=0; i<topo->nb_vm; i++)
    for (j=0; j<topo->vmit[i].vm_params.nb_eth; j++)
      for (k=0; k<topo->vmit[i].lan_eth[j].nb_lan; k++)
        {
        cur = (t_topo_edge_eth_chain *) clownix_malloc(len, 3);
        memset(cur, 0, len);
        strncpy(cur->name, topo->vmit[i].vm_params.name, MAX_NAME_LEN-1);
        cur->num = j;
        strncpy(cur->lan,topo->vmit[i].lan_eth[j].lan[k].name,MAX_NAME_LEN-1);
        cur->next = res;
        if (res)
          res->prev = cur;
        res = cur;
        }
  return res;
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
t_topo_edge_eth_chain *topo_get_edge_eth_sat_chain(t_topo_info *topo)
{
  int i, j, len = sizeof(t_topo_edge_eth_chain);
  t_topo_edge_eth_chain *cur, *res = NULL;
  for (i=0; i< topo->nb_sat; i++)
    {
    for (j=0; j<topo->sati[i].lan0_sat.nb_lan; j++)
      {
      cur = (t_topo_edge_eth_chain *) clownix_malloc(len, 3);
      memset(cur, 0, len);
      strncpy(cur->name, topo->sati[i].name, MAX_NAME_LEN-1);
      strncpy(cur->lan, topo->sati[i].lan0_sat.lan[j].name, MAX_NAME_LEN-1);
      cur->num = 0;
      cur->next = res;
      if (res)
        res->prev = cur;
      res = cur;
      }
    for (j=0; j<topo->sati[i].lan1_sat.nb_lan; j++)
      {
      cur = (t_topo_edge_eth_chain *) clownix_malloc(len, 3);
      memset(cur, 0, len);
      strncpy(cur->name, topo->sati[i].name, MAX_NAME_LEN-1);
      strncpy(cur->lan, topo->sati[i].lan1_sat.lan[j].name, MAX_NAME_LEN-1);
      cur->num = 1;
      cur->next = res;
      if (res)
        res->prev = cur;
      res = cur;
      }
    }
  return res;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void topo_free_node_chain(t_topo_node_chain *ch)
{
  t_topo_node_chain *next, *cur = ch;
  while(cur)
    {
    next = cur->next;
    clownix_free(cur, __FUNCTION__);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
void topo_free_sat_chain(t_topo_sat_chain *ch)
{
  t_topo_sat_chain *next, *cur = ch;
  while(cur)
    {
    next = cur->next;
    clownix_free(cur, __FUNCTION__);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void topo_free_lan_chain(t_topo_lan_chain *ch)
{
  t_topo_lan_chain *next, *cur = ch;
  while(cur)
    {
    next = cur->next;
    clownix_free(cur, __FUNCTION__);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void topo_free_edge_eth_chain(t_topo_edge_eth_chain *ch)
{
  t_topo_edge_eth_chain *next, *cur = ch;
  while(cur)
    {
    next = cur->next;
    clownix_free(cur, __FUNCTION__);
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void topo_free_edge_sat_chain(t_topo_edge_eth_chain *ch)
{
  t_topo_edge_eth_chain *next, *cur = ch;
  while(cur)
    {
    next = cur->next;
    clownix_free(cur, __FUNCTION__);
    cur = next;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int get_port_from_str(char *str_int)
{
  unsigned long num;
  int result;
  char *endptr;
  num = strtoul(str_int, &endptr, 10);
  if ((endptr == NULL)||(endptr[0] != 0))
    {
    printf("Bad input port %s\n", str_int);
    exit(-1);
    }
  else if ((num == 0) || (num > 0xFFFF))
    {
    printf("Bad input port %s\n", str_int);
    exit(-1);
    }
  else
    result = (int) num;
  return result;
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
int found_in_lan_chain(t_topo_lan_chain *head, char *lan)
{
  t_topo_lan_chain *cur = head;
  while(cur)
    {
    if (!strcmp(lan, cur->lan))
      return 1;
    cur = cur->next;
    }
  return 0;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
void take_out_from_node_chain(t_topo_node_chain **nodes, t_topo_info *topo)
{
  t_topo_node_chain *next, *cur = *nodes;
  while (cur)
    {
    next = cur->next;
    if (topo_find_vm_in_topo(cur->name, topo))
      {
      if (cur->next)
        cur->next->prev = cur->prev;
      if (cur->prev)
        cur->prev->next = cur->next;
      if (cur == *nodes)
        *nodes = cur->next;
      clownix_free(cur, __FUNCTION__);
      }
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void take_out_from_sat_chain(t_topo_sat_chain **sats, t_topo_info *topo)
{
  t_topo_sat_chain *next, *cur = *sats;
  while (cur)
    {
    next = cur->next;
    if (topo_find_sat_in_topo(cur->name, topo))
      {
      if (cur->next)
        cur->next->prev = cur->prev;
      if (cur->prev)
        cur->prev->next = cur->next;
      if (cur == *sats)
        *sats = cur->next;
      clownix_free(cur, __FUNCTION__);
      }
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void take_out_from_lan_chain(t_topo_lan_chain **lans, t_topo_info *topo)
{
  t_topo_lan_chain *next, *cur = *lans;
  while (cur)
    {
    next = cur->next;
    if (topo_find_lan_in_topo(cur->lan, topo))
      {
      if (cur->next)
        cur->next->prev = cur->prev;
      if (cur->prev)
        cur->prev->next = cur->next;
      if (cur == *lans)
        *lans = cur->next;
      clownix_free(cur, __FUNCTION__);
      }
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void take_out_from_edge_eth_chain(t_topo_edge_eth_chain **edge,
                                         t_topo_info *topo)
{
  t_topo_edge_eth_chain *next, *cur = *edge;
  while (cur)
    {
    next = cur->next;
    if (topo_find_edge_eth_in_topo(cur->name, cur->num, cur->lan, topo))
      {
      if (cur->next)
        cur->next->prev = cur->prev;
      if (cur->prev)
        cur->prev->next = cur->next;
      if (cur == *edge)
        *edge = cur->next;
      clownix_free(cur, __FUNCTION__);
      }
    cur = next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
t_topo_differences *get_topo_diffs(t_topo_info *newt, t_topo_info *oldt)
{
  static t_topo_differences diffs;
  memset(&diffs, 0, sizeof(t_topo_differences));
  diffs.add_nodes     = topo_get_node_chain(newt);
  if (oldt)
    diffs.del_nodes     = topo_get_node_chain(oldt);

  diffs.add_sats      = topo_get_sat_chain(newt);
  if (oldt)
    diffs.del_sats      = topo_get_sat_chain(oldt);

  diffs.add_lans      = topo_get_lan_chain(newt);
  if (oldt)
    diffs.del_lans      = topo_get_lan_chain(oldt);

  diffs.add_edge_eth = topo_get_edge_eth_node_chain(newt);
  if (oldt)
    diffs.del_edge_eth = topo_get_edge_eth_node_chain(oldt);

  diffs.add_edge_sat  = topo_get_edge_eth_sat_chain(newt);
  if (oldt)
    diffs.del_edge_sat  = topo_get_edge_eth_sat_chain(oldt);

  if (diffs.add_nodes && oldt)
    take_out_from_node_chain(&(diffs.add_nodes), oldt);
  if (diffs.del_nodes && newt)
    take_out_from_node_chain(&(diffs.del_nodes), newt);

  if (diffs.add_sats && oldt)
    take_out_from_sat_chain(&(diffs.add_sats), oldt);
  if (diffs.del_sats && newt)
    take_out_from_sat_chain(&(diffs.del_sats), newt);

  if (diffs.add_lans && oldt)
    take_out_from_lan_chain(&(diffs.add_lans), oldt);
  if (diffs.del_lans && newt)
    take_out_from_lan_chain(&(diffs.del_lans), newt);

  if (diffs.add_edge_eth && oldt)
    take_out_from_edge_eth_chain(&(diffs.add_edge_eth), oldt);
  if (diffs.del_edge_eth && newt)
    take_out_from_edge_eth_chain(&(diffs.del_edge_eth), newt);

  if (diffs.add_edge_sat && oldt)
    take_out_from_edge_eth_chain(&(diffs.add_edge_sat), oldt);
  if (diffs.del_edge_sat && newt)
    take_out_from_edge_eth_chain(&(diffs.del_edge_sat), newt);

  return &diffs;
}
/*---------------------------------------------------------------------------*/


/****************************************************************************/
void free_diffs(t_topo_differences *diffs)
{
  topo_free_node_chain(diffs->add_nodes);
  topo_free_sat_chain(diffs->add_sats);
  topo_free_lan_chain(diffs->add_lans);
  topo_free_edge_eth_chain(diffs->add_edge_eth);
  topo_free_edge_sat_chain(diffs->add_edge_sat);
  topo_free_node_chain(diffs->del_nodes);
  topo_free_sat_chain(diffs->del_sats);
  topo_free_lan_chain(diffs->del_lans);
  topo_free_edge_eth_chain(diffs->del_edge_eth);
  topo_free_edge_sat_chain(diffs->del_edge_sat);
}
/*--------------------------------------------------------------------------*/

