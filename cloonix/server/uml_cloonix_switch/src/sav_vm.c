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
#include <sys/stat.h>



#include "io_clownix.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "doors_rpc.h"
#include "doorways_mngt.h"
#include "event_subscriber.h"
#include "pid_clone.h"
#include "utils_cmd_line_maker.h"
#include "qmp.h"


int produce_list_commands(t_list_commands *list);

enum{
  state_none = 0,
  state_fifreeze_sent,
  state_saving,
  state_fithaw_sent,
  state_freeing,
  state_max,
};

typedef struct t_sav_vm
{
  char name[MAX_NAME_LEN];
  int llid;
  int tid;
  int type;
  int state;
  char clone_msg[MAX_NAME_LEN];
  char dir_path[MAX_PATH_LEN];
  char src_rootfs[MAX_PATH_LEN];
  char dst_rootfs[MAX_PATH_LEN];
  long long abeat_timer;
  int ref_timer;
  int count_fail_cont;
  struct t_sav_vm *prev;
  struct t_sav_vm *next;
} t_sav_vm;
/*---------------------------------------------------------------------------*/
typedef struct t_replay_script
{
  char replay_script_dir[MAX_PATH_LEN];
  char replay_script_path[MAX_PATH_LEN];
} t_replay_script;
/*---------------------------------------------------------------------------*/

static t_sav_vm *g_head_svm;
static int g_sav_vm_count_all;
static int g_sav_vm_count_OK;
static int g_sav_vm_count_KO;



/****************************************************************************/
static void replay_script_clone_death(void *data, int status, char *name)
{
  t_replay_script *rs = (t_replay_script *) data;
  if (!rs)
    KOUT(" ");
  clownix_free(data, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void fprintf_add_kvm(FILE *fhd, char *line, char *dir_path)
{
  int i, len = strlen(line) + 1;
  char *ptr;
  char *spare1 = (char *) clownix_malloc(len, 7);
  char *spare2 = (char *) clownix_malloc(len, 7);
  char rootfs[MAX_PATH_LEN];
  memcpy(spare1, line, len); 
  memcpy(spare2, line, len); 
  ptr = spare1;
  for (i=0; i<8; i++)
    {
    ptr = strchr(ptr, ' '); 
    if (!ptr)
      {
      KERR("%s", line);
      fprintf(fhd, "ERROR %s\n", line);
      }
    else
      {
      if (i == 7)
        *ptr = 0;
      else
        ptr++;
      }
    }
  if (ptr)
    {
    ptr = spare2;
    for (i=0; i<5; i++)
      {
      ptr = strchr(ptr, ' ');
      if (!ptr)
        KOUT("%s", line);
      if (i == 4)
        *ptr = 0;
      else
        ptr++;
      }
    ptr = spare2;
    for (i=0; i<4; i++)
      {
      ptr = strchr(ptr, ' ');
      if (!ptr)
        KOUT("%s", line);
      ptr++;
      }
    memset(rootfs, 0, MAX_PATH_LEN);
    snprintf(rootfs, MAX_PATH_LEN-1, "%s/%s.qcow2", dir_path, ptr);
    fprintf(fhd, "%s %s --persistent &\n", spare1, rootfs);
    }
  clownix_free(spare1, __FUNCTION__);
  clownix_free(spare2, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int replay_script_clone(void *data)
{
  FILE *fhd;
  int i, qty, result = -1;
  int alloc_len = MAX_LIST_COMMANDS_QTY * sizeof(t_list_commands);
  mode_t mode;
  t_list_commands *list;
  t_replay_script *rs = (t_replay_script *) data;
  if (!rs)
    KOUT(" ");

  list = (t_list_commands *) clownix_malloc(alloc_len, 7);
  memset(list, 0, alloc_len);
  qty = produce_list_commands(list);
  fhd = fopen(rs->replay_script_path, "w");
  if (fhd)
    {
    for (i=0; i<qty; i++)
      {
      if (strlen(list[i].cmd) == 0)
        {
        KERR(" ");
        }
      else if (strlen(list[i].cmd) >= MAX_LIST_COMMANDS_LEN)
        {
        KERR("%d", (int) strlen(list[i].cmd));
        }
      else if (strstr(list[i].cmd, "add kvm"))
        {
        fprintf_add_kvm(fhd, list[i].cmd, rs->replay_script_dir);
        }
      else 
        {
        fprintf(fhd, "%s\n", list[i].cmd);
        }
      }
    if (fclose(fhd))
      KOUT("%d", errno);
    result = 0;
    mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
    if (chmod(rs->replay_script_path, mode))
      KERR("%d", errno);
    }
  clownix_free(list, __FUNCTION__);
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void replay_script_creation(char *dir_path, char *path)
{
  t_replay_script *rs;
  rs = (t_replay_script *) clownix_malloc(sizeof(t_replay_script), 7);
  memset(rs, 0, sizeof(t_replay_script));
  snprintf(rs->replay_script_dir, MAX_PATH_LEN-1, "%s", dir_path);
  snprintf(rs->replay_script_path, MAX_PATH_LEN-1, "%s", path);
  pid_clone_launch(replay_script_clone, replay_script_clone_death, NULL, 
                  (void *)rs, (void *)rs, NULL, (char *)__FUNCTION__, -1, 0);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int sav_vm_count(void)
{
  int result = 0;
  t_sav_vm *cur = g_head_svm;
  while (cur)
    {
    result += 1;
    cur = cur->next;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int sav_vm_agent_ok_name(char *name)
{
  int result = 0;
  t_vm *vm = cfg_get_vm(name);
  if (vm->kvm.vm_config_flags & VM_FLAG_CLOONIX_AGENT_PING_OK)
    result = 1;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int sav_vm_agent_ok_all(void)
{
  int nb, result = 1;
  t_vm *cur = cfg_get_first_vm(&nb);
  while (cur)
    {  
    if (!(cur->kvm.vm_config_flags & VM_FLAG_CLOONIX_AGENT_PING_OK))
      result = 0;
    cur = cur->next;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void set_svm_state(t_sav_vm *svm, int new_state)
{
  svm->state = new_state;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void send_fifreeze_to_cloonix_agent(char *name)
{
  doors_send_command(get_doorways_llid(), 0, name, FIFREEZE_FITHAW_FREEZE);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void send_fithaw_to_cloonix_agent(char *name)
{
  doors_send_command(get_doorways_llid(), 0, name, FIFREEZE_FITHAW_THAW);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static t_sav_vm *get_svm(char *name)
{
  t_sav_vm *cur = g_head_svm;
  while (cur)
    {
    if (!strcmp(cur->name,name))
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_sav_vm *alloc_svm(char *name) 
{
  t_sav_vm *res = (t_sav_vm *) clownix_malloc(sizeof(t_sav_vm), 11);
  memset(res, 0, sizeof(t_sav_vm)); 
  strncpy(res->name, name, MAX_NAME_LEN-1);
  if (g_head_svm)
    g_head_svm->prev = res;
  res->next = g_head_svm; 
  g_head_svm = res;
  return res;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_svm(t_sav_vm *svm)
{
  if (svm->prev)
    svm->prev->next = svm->next;
  if (svm->next)
    svm->next->prev = svm->prev;
  if (svm==g_head_svm)
    g_head_svm = svm->next;
  clownix_free(svm, __FUNCTION__); 
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_svm(void *data)
{
  t_sav_vm *svm = (t_sav_vm *) data;
  char err[MAX_PATH_LEN];
  if (!svm)
    KOUT(" ");
  if (svm->llid)
    {
    snprintf(err, MAX_PATH_LEN-1, "VM TIMER SAVING ERROR %d", svm->state);
    send_status_ko(svm->llid, svm->tid, err);
    }
  svm->abeat_timer = 0;
  svm->ref_timer = 0;
  svm->llid = 0;
  set_svm_state(svm, state_freeing);
  free_svm(svm);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_qemu_cont(void *data)
{
  t_sav_vm *svm = (t_sav_vm *) data;
  if (!svm)
    KOUT(" ");
  if (!get_probably_stopped_cpu(svm->name))
    {
    set_svm_state(svm, state_fithaw_sent);
    send_fithaw_to_cloonix_agent(svm->name);
    }
  else
    {
    clownix_timeout_add(10, timer_qemu_cont, (void *) svm, NULL, NULL);
    svm->count_fail_cont++;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void cp_rootfs_clone_death(void *data, int status, char *name)
{
  t_sav_vm *svm = (t_sav_vm *) data;
  if (!svm)
    KOUT(" ");
  qmp_request_qemu_stop_cont(svm->name, 1);
  clownix_timeout_add(10, timer_qemu_cont, (void *) svm, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void cp_rootfs_clone_msg(void *data, char *msg)
{
  t_sav_vm *svm = (t_sav_vm *) data;
  if (!svm)
    KOUT(" ");
  strncpy(svm->clone_msg, msg, MAX_NAME_LEN-1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int cp_rootfs_clone(void *data)
{
  int result = -1;
  char err[MAX_PATH_LEN];
  char cmd[2*MAX_PATH_LEN];
  t_sav_vm *svm = (t_sav_vm *) data;
  if (!svm)
    KOUT(" ");
  memset(cmd, 0, 2*MAX_PATH_LEN);
  if (svm)
    {
    if (svm->type)
      utils_qemu_img_copy_backing(svm->src_rootfs, svm->dst_rootfs, cmd);
    else
      snprintf(cmd, 2*MAX_PATH_LEN, "/bin/cp -f %s %s",
               svm->src_rootfs, svm->dst_rootfs);
    result = clownix_system(cmd);
    if (result)
      KERR("%s %s", svm->name, cmd);
    }
  if (result)
    {
    memset(err, 0, MAX_PATH_LEN);
    snprintf(err, MAX_PATH_LEN-1, "KO save %s", svm->name);
    send_to_daddy(err);
    KERR("%s %s", svm->name, cmd);
    }
  else
    {
    memset(err, 0, MAX_PATH_LEN);
    snprintf(err, MAX_PATH_LEN-1, "OK save %s", svm->name);
    send_to_daddy(err);
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void start_saving_vm(t_sav_vm *svm)
{
  set_svm_state(svm, state_saving);
  qmp_request_qemu_stop_cont(svm->name, 0);
  clownix_timeout_add(150000, timer_svm, (void *) svm,
                      &(svm->abeat_timer), &(svm->ref_timer));
  pid_clone_launch(cp_rootfs_clone, cp_rootfs_clone_death,
                   cp_rootfs_clone_msg, (void *)svm,
                   (void *) svm, (void *) svm, svm->name, -1, 1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void end_saving_vm(t_sav_vm *svm)
{
  char replay_script[MAX_PATH_LEN];
  if (svm->llid)
    {
    if (!strncmp(svm->clone_msg, "OK", 2))
      g_sav_vm_count_OK += 1;
    else
      g_sav_vm_count_KO += 1;
    if (sav_vm_count() == 1)
      {
      if (g_sav_vm_count_OK == g_sav_vm_count_all)
        {
        send_status_ok(svm->llid, svm->tid, "end_save");
        if (g_sav_vm_count_KO != 0)
          KERR("%d %d %d", g_sav_vm_count_all, 
                           g_sav_vm_count_OK, 
                           g_sav_vm_count_KO);
        }
      else
        {
        send_status_ko(svm->llid, svm->tid, "end_save");
        KERR("%d %d %d", g_sav_vm_count_all, 
                         g_sav_vm_count_OK, 
                         g_sav_vm_count_KO);
        }
      svm->llid = 0;
      g_sav_vm_count_all = 0;
      g_sav_vm_count_OK = 0;
      g_sav_vm_count_KO = 0;
      if (!svm->dir_path)
        KERR("%s", svm->dir_path);
      else
        {
        memset(replay_script, 0, MAX_PATH_LEN);
        snprintf(replay_script, MAX_PATH_LEN-1, "%s/%s.sh", 
                 svm->dir_path, cfg_get_cloonix_name()); 
        replay_script_creation(svm->dir_path, replay_script);
        }
      }
    }
  set_svm_state(svm, state_freeing);
  free_svm(svm);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void sav_vm_fifreeze_fithaw(char *name, int is_freeze)
{
  t_sav_vm *svm = get_svm(name);
  if (!svm)
    KERR("%s %d", name, is_freeze);
  else
    {
    if (svm->abeat_timer)
      {
      clownix_timeout_del(svm->abeat_timer, svm->ref_timer,
                          __FILE__, __LINE__);
      svm->abeat_timer = 0;
      svm->ref_timer = 0;
      }
    if (svm->state == state_fifreeze_sent)
      {
      if (!is_freeze)
        KERR("%s %d", name, is_freeze);
      else
        start_saving_vm(svm);
      }
    else if (svm->state == state_fithaw_sent)
      {
      if (is_freeze)
        KERR("%s %d", name, is_freeze);
      else
        end_saving_vm(svm);
      }
    else
      KERR("%s %d %d", name, is_freeze, svm->state);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_and_init_svm(t_vm *vm, char *dir_path, char *path, 
                               int llid, int tid, int type)
{
  t_sav_vm *svm = alloc_svm(vm->kvm.name);
  svm->llid = llid;
  svm->tid = tid;
  svm->type = type;
  set_svm_state(svm, state_fifreeze_sent);
  strncpy(svm->src_rootfs, vm->kvm.rootfs_used, MAX_PATH_LEN-1);
  if (dir_path)
    strncpy(svm->dir_path, dir_path, MAX_PATH_LEN-1);
  strncpy(svm->dst_rootfs, path, MAX_PATH_LEN-1);
  strcpy(svm->clone_msg, "NO_MSG");
  clownix_timeout_add(500, timer_svm, (void *) svm, &(svm->abeat_timer),
                                                    &(svm->ref_timer));
  send_fifreeze_to_cloonix_agent(vm->kvm.name);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void sav_vm_rootfs(char *name, char *path, int llid, int tid, int type)
{
  t_vm   *vm = cfg_get_vm(name);
  t_sav_vm *svm = get_svm(name);
  if (sav_vm_count())
    KERR(" ");
  else
    {  
    if (!vm)
      KERR("%s", name);
    else if (svm)
      KERR("%s", name);
    else
      {
      alloc_and_init_svm(vm, NULL, path, llid, tid, type);
      g_sav_vm_count_all = sav_vm_count();
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void sav_all_vm_rootfs(int nb, t_vm *vm, char *dir_path, 
                       int llid, int tid, int type)
{
  t_vm *cur = vm;
  char path[MAX_PATH_LEN];
  if (sav_vm_count())
    KERR(" ");
  else
    {  
    while (cur)
      {
      memset(path, 0, MAX_PATH_LEN);
      snprintf(path,MAX_PATH_LEN-1,"%s/%s.qcow2",dir_path,cur->kvm.name);
      alloc_and_init_svm(cur, dir_path, path, llid, tid, type);
      cur = cur->next;
      }
    g_sav_vm_count_all = sav_vm_count();
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void sav_vm_init(void)
{
  g_head_svm = NULL;
}
/*--------------------------------------------------------------------------*/
