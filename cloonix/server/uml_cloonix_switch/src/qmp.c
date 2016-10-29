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
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "io_clownix.h"
#include "lib_commons.h"
#include "rpc_qmonitor.h"
#include "rpc_clownix.h"
#include "cfg_store.h"
#include "util_sock.h"
#include "llid_trace.h"
#include "machine_create.h"
#include "utils_cmd_line_maker.h"
#include "pid_clone.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "qmp.h"
#include "qmonitor.h"
#include "qhvc0.h"


#define MAX_QMP_LEN 5000
#define MAX_WHOLE_RX_LEN 10000

#define QMP_RESET  "{ \"execute\": \"system_reset\" }"
#define QMP_STOP  "{ \"execute\": \"stop\" }"
#define QMP_CONT  "{ \"execute\": \"cont\" }"
#define QMP_SHUTDOWN  "{ \"execute\": \"system_powerdown\" }"
#define QMP_CAPA  "{ \"execute\": \"qmp_capabilities\" }"
#define QMP_QUERY "{\"execute\":\"query-status\"}"
#define QMP_BALLOON "{\"execute\":\"balloon\",\"arguments\":{\"value\":%llu}}"

enum {
  msg_type_none = 0,
  msg_type_tx_stop,
  msg_type_tx_cont,
  msg_type_tx_reset,
  msg_type_tx_shutdown,
  msg_type_tx_capa,
  msg_type_tx_query,
  msg_type_tx_balloon,
  msg_type_rx_capa,
  msg_type_rx_running_true,
  msg_type_rx_running_false,
  msg_type_rx_return,
  msg_type_rx_reset_event,
  msg_type_rx_powerdown_event,
  msg_type_rx_shutdown_event,
  msg_type_rx_spice_event,
  msg_type_rx_rtc_change_event,
  msg_type_rx_balloon_change_event,
  msg_type_rx_unknown,
};

enum {
  state_idle = 0,
  state_idle_pid_known,
  state_capa_return_wait,
  state_shutdown_return_wait,
  state_reset_return_wait,
  state_stop_return_wait,
  state_cont_return_wait,
  state_query_return_wait,
  state_max,
};

typedef struct t_qmp_vm
{
  char name[MAX_NAME_LEN];
  int vm_qmv_llid;
  int vm_qmv_fd;
  int connect_count;
  long long connect_abeat_timer;
  int connect_ref_timer;
  long long delete_abeat_timer;
  int delete_ref_timer;
  long long stop_abeat_timer;
  int stop_ref_timer;
  long long balloon_abeat_timer;
  int balloon_ref_timer;
  int pid;
  char stop_sav_clone_msg[MAX_NAME_LEN];
  char stop_sav_src_rootfs[MAX_PATH_LEN];
  char stop_sav_dst_rootfs[MAX_PATH_LEN];
  int qmp_auto_state;
  int request_shutdown;
  int request_stop;
  int request_cont;
  int request_reset;
  int request_capa;
  int request_query_counter;
  int probably_stopped_cpu;
  int capa_exchange_done;
  int stop_sav_llid;
  int stop_sav_tid;
  int stop_sav_stype;
  unsigned long stop_sav_ident;
  char whole_rx[MAX_WHOLE_RX_LEN];
  struct t_qmp_vm *prev;
  struct t_qmp_vm *next;
} t_qmp_vm;
/*--------------------------------------------------------------------------*/

/****************************************************************************/
typedef struct t_mdeath
{
  int err_type;
  char name[MAX_NAME_LEN];
} t_mdeath;
/*--------------------------------------------------------------------------*/

static void wrapper_call_machine_death(t_qmp_vm *qvm, int dly);
static void timer_qvm_connect_qmp(void *data);
static t_qmp_vm *vm_get_with_name(char *name);
static void vm_release(t_qmp_vm *qvm);
static t_qmp_vm *head_qvm;
static int nb_qmp;


/****************************************************************************/
static char *state2ascii(int state, char *ascii_state)
{
  memset(ascii_state, 0, MAX_NAME_LEN);
  switch (state)
    {
    case state_idle:
      strcpy(ascii_state, "state_idle");
      break;
    case state_idle_pid_known:
      strcpy(ascii_state, "state_idle_pid_known");
      break;
    case state_capa_return_wait:
      strcpy(ascii_state, "state_capa_return_wait");
      break;
    case state_query_return_wait:
      strcpy(ascii_state, "state_query_return_wait");
      break;
    case state_shutdown_return_wait:
      strcpy(ascii_state, "state_shutdown_return_wait");
      break;
    case state_reset_return_wait:
      strcpy(ascii_state, "state_reset_return_wait");
      break;
    case state_stop_return_wait:
      strcpy(ascii_state, "state_stop_return_wait");
      break;
    case state_cont_return_wait:
      strcpy(ascii_state, "state_cont_return_wait");
      break;
    }
  return ascii_state;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void change_state(int line, t_qmp_vm *qvm, int new_state)
{
  char ascii_old_state[MAX_NAME_LEN];
  char ascii_new_state[MAX_NAME_LEN];
  state2ascii(qvm->qmp_auto_state, ascii_old_state);
  state2ascii(new_state, ascii_new_state);
//  KERR("%d   %s ---> %s", line, ascii_old_state, ascii_new_state);
  qvm->qmp_auto_state = new_state;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int working_vm_qmv_llid(t_qmp_vm *qvm)
{
  int result = 0;
  if (qvm->vm_qmv_llid)
    {
    if (msg_exist_channel(qvm->vm_qmv_llid))
      result = 1;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void send_msg_to_qmp(t_qmp_vm *qvm, int msg_type, 
                            unsigned long long param)
{
  char buf[2*MAX_NAME_LEN];
  if (working_vm_qmv_llid(qvm))
    {
    switch(msg_type)
      {
      case msg_type_tx_stop:
        watch_tx(qvm->vm_qmv_llid, strlen(QMP_STOP), QMP_STOP);
        break;
      case msg_type_tx_cont:
        watch_tx(qvm->vm_qmv_llid, strlen(QMP_CONT), QMP_CONT);
        break;
      case msg_type_tx_reset:
        watch_tx(qvm->vm_qmv_llid, strlen(QMP_RESET), QMP_RESET);
        break;
      case msg_type_tx_shutdown:
        watch_tx(qvm->vm_qmv_llid, strlen(QMP_SHUTDOWN), QMP_SHUTDOWN);
        break;
      case msg_type_tx_capa:
        watch_tx(qvm->vm_qmv_llid, strlen(QMP_CAPA), QMP_CAPA);
        break;
      case msg_type_tx_query:
        watch_tx(qvm->vm_qmv_llid, strlen(QMP_QUERY), QMP_QUERY);
        break;
      case msg_type_tx_balloon:
        memset(buf, 0, 2*MAX_NAME_LEN);
        snprintf(buf, 2*MAX_NAME_LEN-1, QMP_BALLOON, param); 
        watch_tx(qvm->vm_qmv_llid, strlen(buf), buf);
        break;

      default:
        KOUT(" ");
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void auto_state_time_scheduler(void)
{
  static int count=0;
  char ascii_state[MAX_NAME_LEN];
  t_qmp_vm *qvm = head_qvm;

  while (qvm)
    { 
    if (qvm->qmp_auto_state == state_idle_pid_known)
      {
      if (strlen(qvm->whole_rx))
        KERR("%s %d %s", qvm->name,
             (int)strlen(qvm->whole_rx), qvm->whole_rx);
      count = 0;
      if (qvm->request_capa)
        {
        send_msg_to_qmp(qvm, msg_type_tx_capa, 0);
        change_state(__LINE__, qvm, state_capa_return_wait);
        qvm->request_capa = 0;
        }
      else if (qvm->capa_exchange_done)
        {
        if (qvm->request_stop)
          {
          send_msg_to_qmp(qvm, msg_type_tx_stop, 0);
          change_state(__LINE__, qvm, state_stop_return_wait);
          qvm->request_stop = 0;
          }
        else if (qvm->request_cont)
          {
          send_msg_to_qmp(qvm, msg_type_tx_cont, 0);
          change_state(__LINE__, qvm, state_cont_return_wait);
          qvm->request_cont = 0;
          }
        else if (qvm->request_shutdown)
          {
          send_msg_to_qmp(qvm, msg_type_tx_shutdown, 0);
          change_state(__LINE__, qvm, state_shutdown_return_wait);
          qvm->request_shutdown = 0;
          }
        else if (qvm->request_reset)
          {
          send_msg_to_qmp(qvm, msg_type_tx_reset, 0);
          change_state(__LINE__, qvm, state_reset_return_wait);
          qvm->request_reset = 0;
          }
        else 
          {
          qvm->request_query_counter += 1;
          if (qvm->request_query_counter > 5)
            {
            qvm->request_query_counter = 0;
            }
          }
        }
      }
    else
      {
      count += 1;
      if ((count > 10) && 
          (qvm->qmp_auto_state != state_shutdown_return_wait))
        {
        state2ascii(qvm->qmp_auto_state, ascii_state);
//        KERR("%s STUCK IN %s", qvm->name, ascii_state);
        }
      }
    qvm = qvm->next;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void auto_state_msg_rx(t_qmp_vm *qvm, int msg_type)
{
  switch (qvm->qmp_auto_state)
    {

    case state_idle:
    case state_idle_pid_known:
      if (msg_type == msg_type_rx_capa)
        {
        qvm->capa_exchange_done = 0;
        qvm->request_capa = 1;
        }
      else
        KERR("%s %d", qvm->name, msg_type);
      break;

    case state_capa_return_wait:
      if (msg_type == msg_type_rx_return)
        {
        qvm->capa_exchange_done = 1;
        change_state(__LINE__, qvm, state_idle_pid_known);
        }
      else
        KERR("%s %d", qvm->name, msg_type);
      break;

    case state_shutdown_return_wait:
      if (msg_type == msg_type_rx_return)
        {
        change_state(__LINE__, qvm, state_idle_pid_known);
        }
      else
        KERR("%s %d", qvm->name, msg_type);
      break;

    case state_reset_return_wait:
      if (msg_type == msg_type_rx_return)
        {
        change_state(__LINE__, qvm, state_idle_pid_known);
        }
      else
        KERR("%s %d", qvm->name, msg_type);
      break;

    case state_stop_return_wait:
      if (msg_type == msg_type_rx_return)
        {
        change_state(__LINE__, qvm, state_idle_pid_known);
        }
      else
        KERR("%s %d", qvm->name, msg_type);
      break;

    case state_cont_return_wait:
      if (msg_type == msg_type_rx_return)
        {
        change_state(__LINE__, qvm, state_idle_pid_known);
        qvm->probably_stopped_cpu = 0;
        }
      else
        KERR("%s %d", qvm->name, msg_type);
      break;

    case state_query_return_wait:
        change_state(__LINE__, qvm, state_idle_pid_known);
        KERR("%s %d", qvm->name, msg_type);
      break;


    default:
      KOUT("%s %d", qvm->name, qvm->qmp_auto_state);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int get_received_msg(char *name, char *qmp_msg)
{
  char *ptr_start = qmp_msg;
  int msg_type = msg_type_rx_unknown;
  if ((strstr(ptr_start,"QMP"))&&(strstr(ptr_start,"version")) &&
      (strstr(ptr_start,"qemu"))&&(strstr(ptr_start,"capabilities")))
    msg_type = msg_type_rx_capa;
  else if (strstr(ptr_start, "\"running\": true"))
    msg_type = msg_type_rx_running_true;
  else if (strstr(ptr_start, "\"running\": false"))
    msg_type = msg_type_rx_running_false;
  else if (strstr(ptr_start, "{\"return\": {}}"))
    msg_type = msg_type_rx_return;
  else if (strstr(ptr_start, "\"event\": \"RESET\""))
    msg_type = msg_type_rx_reset_event;
  else if (strstr(ptr_start, "\"event\": \"POWERDOWN\""))
    msg_type = msg_type_rx_powerdown_event;
  else if (strstr(ptr_start, "\"event\": \"SHUTDOWN\""))
    msg_type = msg_type_rx_shutdown_event;
  else if (strstr(ptr_start, "\"event\": \"SPICE_CONNECTED\""))
    msg_type = msg_type_rx_spice_event;
  else if (strstr(ptr_start, "\"event\": \"SPICE_DISCONNECTED\""))
    msg_type = msg_type_rx_spice_event;
  else if (strstr(ptr_start, "\"event\": \"SPICE_INITIALIZED\""))
    msg_type = msg_type_rx_spice_event;
  else if (strstr(ptr_start, "\"event\": \"RTC_CHANGE\""))
    msg_type = msg_type_rx_rtc_change_event;
  else if (strstr(ptr_start, "\"event\": \"BALLOON_CHANGE\""))
    msg_type = msg_type_rx_balloon_change_event;
//  else
//    KERR("%s UNKNOWN_RX: %s", name, ptr_start);
  return msg_type;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int get_probably_stopped_cpu(char *name)
{
  int result = 1;
  t_qmp_vm *qvm = vm_get_with_name(name);
  if (qvm)
    {
    result = qvm->probably_stopped_cpu;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void last_kill_action(char *name)
{
  t_qmp_vm *qvm = vm_get_with_name(name);
  if (qvm)
    {
    if (qvm->pid)
      {
      if (!kill(qvm->pid, SIGKILL))
        KERR("Brutalkill of vm");
      }
    wrapper_call_machine_death(qvm, 1);
    vm_release(qvm);
    }
  else
    KERR("QVM NOT FOUND %s", name);
  clownix_free(name, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_call_machine_death(void *data)
{
  t_mdeath *mdeath = (t_mdeath *) data;
  machine_death(mdeath->name, mdeath->err_type);
  clownix_free(data, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void wrapper_call_machine_death(t_qmp_vm *qvm, int dly)
{
  t_vm   *vm;
  t_mdeath *mdeath;
  vm = cfg_get_vm(qvm->name);
  if (vm)
    {
    mdeath = clownix_malloc(sizeof(t_mdeath), 7);
    memset(mdeath, 0, sizeof(t_mdeath));
    strncpy(mdeath->name, qvm->name, MAX_NAME_LEN-1);
    if (qvm->request_shutdown == 0)
      mdeath->err_type = error_death_qmp;
    clownix_timeout_add(dly,timer_call_machine_death,(void *)mdeath,NULL,NULL);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void vm_release(t_qmp_vm *qvm)
{
  if (!qvm)
    KOUT(" ");
  if (qvm->vm_qmv_llid)
    llid_trace_free(qvm->vm_qmv_llid, 0, __FUNCTION__);
  if (qvm->stop_sav_llid)
    llid_trace_free(qvm->stop_sav_llid, 0, __FUNCTION__);
  if (qvm->connect_abeat_timer)
    clownix_timeout_del(qvm->connect_abeat_timer, qvm->connect_ref_timer,
                        __FILE__, __LINE__);
  qvm->connect_abeat_timer = 0;
  qvm->connect_ref_timer = 0;
  if (qvm->delete_abeat_timer)
    clownix_timeout_del(qvm->delete_abeat_timer, qvm->delete_ref_timer,
                        __FILE__, __LINE__);
  qvm->delete_abeat_timer = 0;
  qvm->delete_ref_timer = 0;
  if (qvm->stop_abeat_timer)
    clownix_timeout_del(qvm->stop_abeat_timer, qvm->stop_ref_timer,
                        __FILE__, __LINE__);
  qvm->stop_abeat_timer = 0;
  qvm->stop_ref_timer = 0;
  if (qvm->balloon_abeat_timer)
    clownix_timeout_del(qvm->balloon_abeat_timer, qvm->balloon_ref_timer,
                        __FILE__, __LINE__);
  qvm->balloon_abeat_timer = 0;
  qvm->balloon_ref_timer = 0;
  if (qvm->prev)
    qvm->prev->next = qvm->next;
  if (qvm->next)
    qvm->next->prev = qvm->prev;
  if (qvm == head_qvm)
    head_qvm = qvm->next;
  if (nb_qmp == 0)
    KOUT(" ");
  nb_qmp--;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_qmp_vm *vm_alloc(char *name)
{
  t_qmp_vm *qvm = NULL;
  qvm = (t_qmp_vm *) clownix_malloc(sizeof(t_qmp_vm), 5);
  memset(qvm, 0, sizeof(t_qmp_vm));
  strncpy(qvm->name, name, MAX_NAME_LEN-1);
  if (head_qvm)
    head_qvm->prev = qvm;
  qvm->next = head_qvm;
  head_qvm = qvm;
  nb_qmp++;
  return qvm;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_qmp_vm *vm_get_with_name(char *name)
{
  t_qmp_vm *qvm = head_qvm;
  while (qvm && (strcmp(qvm->name, name)))
    qvm = qvm->next;
  return qvm;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static t_qmp_vm *vm_get_with_llid(int llid)
{
  t_qmp_vm *qvm = head_qvm;
  while (qvm && (qvm->vm_qmv_llid != llid))
    qvm = qvm->next;
  return qvm;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void process_llid_error( t_qmp_vm *qvm)
{
  if (qvm->vm_qmv_llid)
    llid_trace_free(qvm->vm_qmv_llid, 0, __FUNCTION__);
  qvm->vm_qmv_llid = 0;
  wrapper_call_machine_death(qvm, 500);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void vm_err_cb (void *ptr, int llid, int err, int from)
{
  t_qmp_vm *qvm;
  qvm = vm_get_with_llid(llid);
  if (qvm)
    {
    process_llid_error(qvm);
    }
  else
    KERR(" ");
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static int message_braces_complete(char *whole_rx)
{
  int j, i=0, count=0, result = 0;
  if (strchr(whole_rx, '{'))
    {
    do
      {
      j = whole_rx[i];
      if (j == '{')
        count += 1;
      if (j == '}')
        count -= 1;
      i += 1;
      } while (j);
    if (count == 0)
      result = 1;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void make_whole_rx_and_act(t_qmp_vm *qvm, int len, char *buf)
{
  int len_done, len_left, msg_type;
  len_done = strlen(qvm->whole_rx);
  if (len_done >= MAX_WHOLE_RX_LEN - 1)
    KOUT(" ");
  len_left = MAX_WHOLE_RX_LEN - len_done - 1;
  if (len < len_left)
    {
    strcat(qvm->whole_rx, buf);
    if (message_braces_complete(qvm->whole_rx))
      {
      msg_type = get_received_msg(qvm->name, qvm->whole_rx);
      if ((msg_type == msg_type_rx_capa) ||
          (msg_type == msg_type_rx_running_true) ||
          (msg_type == msg_type_rx_running_false) ||
          (msg_type == msg_type_rx_return))
        auto_state_msg_rx(qvm, msg_type);
      memset(qvm->whole_rx, 0, MAX_WHOLE_RX_LEN); 
      }
    }
  else
    {
    KERR("%s %d %d %s", qvm->name, len_left, len, buf);
    memset(qvm->whole_rx, 0, MAX_WHOLE_RX_LEN); 
    }
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static int vm_rx_cb(void *ptr, int llid, int fd)
{
  int len;
  t_qmp_vm *qvm;
  char buf[MAX_QMP_LEN+1];
  memset(buf, 0, MAX_QMP_LEN+1);
  len = util_read(buf, MAX_QMP_LEN, fd);
  qvm = vm_get_with_llid(llid);
  if (!qvm)
    KERR(" ");
  else
    {
    if (len < 0)
      {
      len = 0;
      KERR(" ");
      process_llid_error(qvm);
      }
    else
      {
      if (len != strlen(buf))
        KERR("%s %d %d", qvm->name, len, (int) strlen(buf));
      else
        make_whole_rx_and_act(qvm, len, buf);
      }
    }
  return len;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_qvm_delete(void *data)
{
  char *name;
  t_qmp_vm *qvm = (t_qmp_vm *) data;
  if ((!qvm) || (!qvm->name))
    KOUT(" ");
  qvm->delete_abeat_timer = 0;
  qvm->delete_ref_timer = 0;
  name = (char *) clownix_malloc(MAX_NAME_LEN, 9);
  memset(name, 0, MAX_NAME_LEN);
  strncpy(name, qvm->name, MAX_NAME_LEN-1);
  last_kill_action(name);
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static void rearm_timer_qvm_connect_qmp(t_qmp_vm *qvm)
{
  qvm->connect_count += 1;
  if (qvm->connect_count < 50)
    clownix_timeout_add(5, timer_qvm_connect_qmp, (void *) qvm,
                        &(qvm->connect_abeat_timer),
                        &(qvm->connect_ref_timer));
  else if (qvm->connect_count < 100)
    clownix_timeout_add(25, timer_qvm_connect_qmp, (void *) qvm,
                        &(qvm->connect_abeat_timer),
                        &(qvm->connect_ref_timer));
  else if (qvm->connect_count < 250)
    clownix_timeout_add(100, timer_qvm_connect_qmp, (void *) qvm,
                        &(qvm->connect_abeat_timer),
                        &(qvm->connect_ref_timer));
  else
    {
    KERR(" %s", qvm->name);
    wrapper_call_machine_death(qvm, 1);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_qvm_connect_qmp(void *data)
{ 
  t_qmp_vm *qvm = (t_qmp_vm *) data;
  char *qmon;
  int fd, llid;
  t_vm *vm;
  if ((!qvm) || (!qvm->name))
    KOUT(" ");
  qvm->connect_abeat_timer = 0;
  qvm->connect_ref_timer = 0;
  vm = cfg_get_vm(qvm->name);
  if (vm)
    { 
    if (qvm->vm_qmv_llid)
      {
      qvm->pid = utils_get_pid_of_machine(vm);
      if (!qvm->pid)
        rearm_timer_qvm_connect_qmp(qvm);
      else
        change_state(__LINE__, qvm, state_idle_pid_known);
      }
    else
      {
      qmon = utils_get_qmp_path(vm->vm_id);
      if (!util_nonblock_client_socket_unix(qmon, &fd))
        {
        if (fd <= 0)
          KOUT(" ");
        qvm->vm_qmv_fd = fd;
        llid=msg_watch_fd(qvm->vm_qmv_fd, vm_rx_cb, vm_err_cb, "qmon");
        if (llid == 0)
          KOUT(" ");
        llid_trace_alloc(llid,"QMP",0,0, type_llid_trace_unix_qmonitor);
        qvm->vm_qmv_llid = llid;
        }
      rearm_timer_qvm_connect_qmp(qvm);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_request_qemu_reboot(char *name)
{
  t_qmp_vm *qvm = vm_get_with_name(name);
  if (qvm)
    {
    if (working_vm_qmv_llid(qvm))
      {
      qvm->request_reset = 1;
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int qmp_request_qemu_stop_cont(char *name, int cont)
{
  int result = -1;
  t_qmp_vm *qvm = vm_get_with_name(name);
  if (qvm)
    {
    if (working_vm_qmv_llid(qvm))
      {
      if (cont)
        qvm->request_cont = 1;
      else
        {
        qvm->request_stop = 1;
        qvm->probably_stopped_cpu = 1;
        }
      result = 0;
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
int qmp_end_qemu_unix(char *name)
{
  int result = -1;
  t_qmp_vm *qvm = vm_get_with_name(name);
  if (qvm)
    {
    if (working_vm_qmv_llid(qvm))
      {
      if (qvm->request_shutdown == 0)
        {
        if (qvm->connect_abeat_timer)
          KERR("%s", qvm->name);
        clownix_timeout_add(200, timer_qvm_delete, (void *) qvm,
                            &(qvm->delete_abeat_timer),
                            &(qvm->delete_ref_timer));
        qvm->request_shutdown = 1;
        result = 0;
        }
      else if (!qvm->connect_abeat_timer)
        {
        if (qvm->delete_abeat_timer)
          clownix_timeout_del(qvm->delete_abeat_timer,
                              qvm->delete_ref_timer,
                              __FILE__, __LINE__);
        clownix_timeout_add(1, timer_qvm_delete, (void *) qvm,
                            &(qvm->delete_abeat_timer),
                            &(qvm->delete_ref_timer));
        }
      }
    else
      {
      if (qvm->delete_abeat_timer)
        clownix_timeout_del(qvm->delete_abeat_timer,qvm->delete_ref_timer,
                            __FILE__, __LINE__);
      clownix_timeout_add(500, timer_qvm_delete, (void *) qvm,
                          &(qvm->delete_abeat_timer),
                          &(qvm->delete_ref_timer));
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_begin_qemu_unix(char *name)
{
  t_qmp_vm *qvm = vm_alloc(name);
  rearm_timer_qvm_connect_qmp(qvm);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int qmp_still_present(void)
{
  return nb_qmp;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_scheduler(void *data)
{
  auto_state_time_scheduler();
  clownix_timeout_add(50, timer_scheduler, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void request_balloon(t_qmp_vm *qvm, int val)
{
  char str[MAX_NAME_LEN];
/*
  unsigned long long ullval = (unsigned long long) val;
  ullval *= 1000000;
  send_msg_to_qmp(qvm, msg_type_tx_capa, ullval);
  send_msg_to_qmp(qvm, msg_type_tx_capa, val);
*/
  memset(str, 0, MAX_NAME_LEN);
  snprintf(str, MAX_NAME_LEN-1, "balloon %d\r\n", val);
  qmonitor_send_string_to_cli(qvm->name, str);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_burst_balloon(void *data)
{
  char *name = (char *) data;
  t_vm   *vm;
  t_qmp_vm *qvm;
  vm = cfg_get_vm(name);
  qvm = vm_get_with_name(name);
  if (qvm)
    {
    qvm->balloon_abeat_timer = 0;
    qvm->balloon_ref_timer = 0;
    if (!vm)
      KERR("RANDOM BUG TRAPPED YES");
    }
  if (vm)
    {
    qvm = vm_get_with_name(name);
    if (qvm)
      request_balloon(qvm, vm->vm_params.mem);
    }
  clownix_free(name, __FUNCTION__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void qmp_agent_sysinfo(char *name, int used_mem_agent)
{
  t_vm   *vm;
  t_qmp_vm *qvm;
  char *nm;
  int a,b;
  vm = cfg_get_vm(name);
  if ((vm) && 
      (vm->vm_params.vm_config_flags & VM_CONFIG_FLAG_BALLOONING))
    {
    qvm = vm_get_with_name(name);
    if (qvm)
      {
      if (vm->vm_params.mem < 200)
        {
        a = 200000;
        b = 80; 
        }
      else if (vm->vm_params.mem < 400) 
        {
        a = 280000;
        b = 130; 
        }
      else if (vm->vm_params.mem < 1000) 
        {
        a = 370000;
        b = 180;
        }
      else if (vm->vm_params.mem < 2000) 
        {
        a = 450000;
        b = 250;
        }
      else
        {
        a = 500000;
        b = 300;
        }
      if ((vm->mem_rss - used_mem_agent) > a)
        {
        if (qvm->balloon_abeat_timer)
          clownix_timeout_del(qvm->balloon_abeat_timer,qvm->balloon_ref_timer,
                              __FILE__, __LINE__);
        nm = (char *) clownix_malloc(MAX_NAME_LEN, 9);
        memset(nm, 0, MAX_NAME_LEN);
        strncpy(nm, name, MAX_NAME_LEN-1);
        clownix_timeout_add(500, timer_burst_balloon, (void *)nm, 
                            &(qvm->balloon_abeat_timer), 
                            &(qvm->balloon_ref_timer));
        request_balloon(qvm, used_mem_agent/1000 + b);
//KERR("%d %d %d %d %d", vm->mem_rss, used_mem_agent, 
//                       vm->mem_rss - used_mem_agent, a, b);
        }
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void init_qmp(void)
{
  head_qvm = NULL;
  nb_qmp = 0;
  timer_scheduler(NULL);
}
/*--------------------------------------------------------------------------*/

