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
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "utils_cmd_line_maker.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "qmp.h"
#include "qmp_dialog.h"
#include "llid_trace.h"



/*--------------------------------------------------------------------------*/
typedef struct t_qmp_sub
{
  int llid;
  int tid;
  struct t_qmp_sub *prev;
  struct t_qmp_sub *next;
} t_qmp_sub;
/*--------------------------------------------------------------------------*/

/*--------------------------------------------------------------------------*/
typedef struct t_qmp
{
  char name[MAX_NAME_LEN];
  t_qmp_sub *head_qmp_sub;
  struct t_qmp *prev;
  struct t_qmp *next;
} t_qmp;
/*--------------------------------------------------------------------------*/

static t_qmp *g_head_qmp;
static t_qmp_sub *g_head_all_qmp_sub;

/****************************************************************************/
static t_qmp *find_qmp(char *name)
{
  t_qmp *cur = g_head_qmp;
  while (cur)
    {
    if (!strcmp(name, cur->name))
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_qmp(char *name)
{
  t_qmp *cur = (t_qmp *) clownix_malloc(sizeof(t_qmp), 7);
  memset(cur, 0, sizeof(t_qmp));
  strncpy(cur->name, name, MAX_NAME_LEN);
  if (g_head_qmp)
    g_head_qmp->prev = cur;
  cur->next = g_head_qmp;
KERR("ALLOC: %s", name);
  g_head_qmp = cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_qmp(t_qmp *cur)
{
KERR("FREE: %s", cur->name);
  if (cur->next)
    cur->next->prev = cur->prev;
  if (cur->prev)
    cur->prev->next = cur->next;
  if (cur == g_head_qmp)
    g_head_qmp = cur->next;
  clownix_free(cur, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_qmp_sub *find_qmp_sub(t_qmp *qmp, int llid)
{
  t_qmp_sub *cur;
  if (qmp)
    cur = qmp->head_qmp_sub;
  else
    cur = g_head_all_qmp_sub;
  while (cur)
    {
    if (cur->llid == llid)
      break;
    cur = cur->next;
    }
  return cur;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void alloc_qmp_sub(t_qmp *qmp, int llid, int tid)
{
  t_qmp_sub *cur = find_qmp_sub(qmp, llid);
  if (cur)
    KERR(" ");
  else
    {
    cur = (t_qmp_sub *) clownix_malloc(sizeof(t_qmp_sub), 7);
    memset(cur, 0, sizeof(t_qmp_sub));
    cur->llid = llid;
    cur->tid = tid;
    if (qmp)
      {
KERR("ALLOC: %s %d", qmp->name, llid);
      if (qmp->head_qmp_sub)
        qmp->head_qmp_sub->prev = cur;
      cur->next = qmp->head_qmp_sub;
      qmp->head_qmp_sub = cur;
      }
    else
      {
KERR("ALLOC: ALL %d", llid);
      if (g_head_all_qmp_sub)
        g_head_all_qmp_sub->prev = cur;
      cur->next = g_head_all_qmp_sub;
      g_head_all_qmp_sub = cur;
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void free_qmp_sub(t_qmp *qmp, t_qmp_sub *cur)
{
if (qmp)
KERR("FREE: %s %d", qmp->name, cur->llid);
else
KERR("FREE: ALL %d", cur->llid);
  if (cur->next)
    cur->next->prev = cur->prev;
  if (cur->prev)
    cur->prev->next = cur->next;
  if (qmp)
    {
    if (cur == qmp->head_qmp_sub)
      qmp->head_qmp_sub = cur->next;
    }
  else
    {
    if (cur == g_head_all_qmp_sub)
      g_head_all_qmp_sub = cur->next;
    }
  clownix_free(cur, __FUNCTION__);
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
void qmp_msg_recv(char *name, char *msg)
{
  t_qmp *qmp = g_head_qmp;
  t_qmp_sub *cur;
  KERR("%s %s", name, msg);
  while (qmp)
    {
    cur = qmp->head_qmp_sub;
    while(cur)
      {
      send_qmp_resp(cur->llid, cur->tid, name, msg, 0);
      cur = cur->next;
      }
    qmp = qmp->next;
    }
  cur = g_head_all_qmp_sub;
  while(cur)
    {
    send_qmp_resp(cur->llid, cur->tid, name, msg, 0);
    cur = cur->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_conn_end(char *name)
{
  t_qmp *qmp = find_qmp(name);
  t_qmp_sub *cur, *next;
  if (!qmp)
    KERR("%s", name);
  else
    {
    cur = qmp->head_qmp_sub;
    while(cur)
      {
      next = cur->next;
      free_qmp_sub(qmp, cur);
      cur = next;
      }
    free_qmp(qmp);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_event_free(int llid)
{
  t_qmp *cur = g_head_qmp;
  t_qmp_sub *sub;
  while(cur)
    {
    sub = find_qmp_sub(cur, llid);
    if (sub)
      free_qmp_sub(cur, sub);
    cur = cur->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_begin_qemu_unix(char *name)
{
  alloc_qmp(name);
  qmp_dialog_alloc(name, qmp_conn_end);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_init(void)
{
  g_head_qmp = NULL;
  g_head_all_qmp_sub = NULL;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_request_save_rootfs(char *name, char *path, int llid,
                             int tid, int stype)
{
  send_status_ko(llid, tid, "NOT IMPLEM");
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_request_save_rootfs_all(int nb, t_vm *vm, char *path, int llid,
                                 int tid, int stype)
{
  send_status_ko(llid, tid, "NOT IMPLEM");
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_request_qemu_reboot(char *name, int llid, int tid)
{
  send_status_ko(llid, tid, "NOT IMPLEM");
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_request_qemu_halt(char *name, int llid, int tid)
{
  if (llid)
    send_status_ko(llid, tid, "NOT IMPLEM");
  else
    KERR("%s", name);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_request_sub(char *name, int llid, int tid)
{
  t_qmp *qmp = NULL;
  if (name)
    qmp = find_qmp(name);
  if (!llid_trace_exists(llid))
    KERR("%s %d", name, llid);
  else if ((name) && (!qmp))
    send_qmp_resp(llid, tid, name, "qmp rec not found", -1);
  else
    alloc_qmp_sub(qmp, llid, tid);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_request_snd(char *name, int llid, int tid, char *msg)
{ 
  send_qmp_resp(llid, tid, "noname", "no implem", -1);
}
/*--------------------------------------------------------------------------*/

