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
#include "util_sock.h"
#include "llid_trace.h"
#include "machine_create.h"
#include "utils_cmd_line_maker.h"
#include "pid_clone.h"
#include "commun_daemon.h"
#include "event_subscriber.h"
#include "qhvc0.h"
#include "doorways_mngt.h"
#include "doors_rpc.h"
#include "header_sock.h"




#define END_HVCO_CMD_MARKER "end_of_hvc0_cloonix_cmd_marker"

#define MAX_LEN_DROPBEAR 2000
#define CMD_START_DROPBEAR_CLOONIX " "\
  "cat > /tmp/dropbear_cloonix_agent.sh << \"INSIDE_EOF\"\n"\
  "#!/bin/sh\n"\
  "set +e\n"\
  "CONFIG=/mnt/cloonix_config_fs\n"\
  "APID=\"$(pidof cloonix_agent)\"\n"\
  "DPID=\"$(pidof dropbear_cloonix_sshd)\"\n"\
  "if [ \"$APID\" != \"\" ]; then\n"\
  "  kill $APID\n"\
  "fi\n"\
  "if [ \"$DPID\" != \"\" ]; then\n"\
  "  kill $DPID\n"\
  "fi\n"\
  "if [ ! -e ${CONFIG}/cloonix_agent ]; then\n"\
  "  mkdir -p /mnt/cloonix_config_fs\n"\
  "  umount /dev/sr0\n"\
  "  umount /dev/sr0\n"\
  "  mount /dev/sr0 /mnt/cloonix_config_fs\n"\
  "  mount -o remount,exec /dev/sr0\n"\
  "fi\n"\
  "${CONFIG}/cloonix_agent\n"\
  "${CONFIG}/dropbear_cloonix_sshd\n"\
  "APID=\"$(pidof cloonix_agent)\"\n"\
  "DPID=\"$(pidof dropbear_cloonix_sshd)\"\n"\
  "if [ \"$DPID\" != \"\" ]; then\n"\
  "  if [ \"$APID\" != \"\" ]; then\n"\
  "    echo i_think_cloonix_agent_is_up\n"\
  "  fi\n"\
  "fi\n"\
  "p9_host_share=$(cat ${CONFIG}/cloonix_vm_p9_host_share)\n"\
  "if [ \"${p9_host_share}\" = \"yes\" ]; then\n"\
  "  name=$(cat ${CONFIG}/cloonix_vm_name)\n"\
  "  SHRED=/mnt/p9_host_share\n"\
  "  mkdir -p ${SHRED}\n"\
  "  mount -t 9p -o trans=virtio,version=9p2000.L $name ${SHRED}\n"\
  "fi\n"\
  "INSIDE_EOF\n"\
  "chmod +x /tmp/dropbear_cloonix_agent.sh\n"\
  "/tmp/dropbear_cloonix_agent.sh\n"

#define MAX_QHVC_LEN 50000
#define MAX_TOT_RX_LEN 150000


#define REQ_VPORT_AG2CLOONIX "req_ag2cloonix_vport_is_cloonix_backdoor"
#define REQ_HVCO_AG2CLOONIX  "req_ag2cloonix_hvc0_is_cloonix_backdoor"
#define ACK_HVCO_AG2CLOONIX  "ack_ag2cloonix_hvc0_is_cloonix_backdoor"
#define RESP_HVCO_CLOONIX2AG "resp_cloonix2ag_hvc0_is_cloonix_backdoor"

enum {
  state_min = 0,
  state_waiting_resp_first_try,
  state_waiting_after_first_try_success,
  state_waiting_resp_launch_agent,
  state_waiting_cloonix_agent_req,
  state_waiting_hvc0_is_cloonix_backdoor,
  state_hvc0_is_cloonix_backdoor,
  state_vport_is_cloonix_backdoor,
  state_failure,
  state_max,
};

typedef struct t_rx_pktbuf
{
  char buf[MAX_A2D_LEN];
  int  offset;
  int  paylen;
  char *payload;
} t_rx_pktbuf;



typedef struct t_cloonix_handshake_timeout
{
  char name[MAX_NAME_LEN];
  int cloonix_handshake_id;
} t_cloonix_handshake_timeout;
/*--------------------------------------------------------------------------*/
typedef struct t_qhvc0_vm
{
  char name[MAX_NAME_LEN];
  int vm_config_flags;
  int cloonix_handshake_id;
  int vm_id;
  int vm_qhvc0_llid;
  int vm_qhvc0_fd;
  int door2ag_listen_llid;
  int door2ag_llid;
  long long heartbeat_abeat;
  int heartbeat_ref;
  long long connect_abs_beat_timer;
  int connect_ref_timer;
  int pid;
  char tot_rx[MAX_TOT_RX_LEN];
  char tot_rx_cmd[MAX_QHVC_LEN];
  int auto_state;
  int tot_rx_offset;
  int backdoor_connected;
  int ready_to_connect_hvc0;
  int send_ping_ready_timer_on;
  int send_ping_ready_first_time;
  int not_first_time_read;

  int timeout_cloonix_agent_handshake;
  int in_guest_ls_done;
  int in_guest_cloonix_agent_start_done;

  t_rx_pktbuf rx_pktbuf_fag;
  t_rx_pktbuf rx_pktbuf_tag;

  struct t_qhvc0_vm *prev;
  struct t_qhvc0_vm *next;
} t_qhvc0_vm;
/*--------------------------------------------------------------------------*/

static void ga_qhvc0_heartbeat_init(t_qhvc0_vm *cvm);
static void clean_connect_timer(t_qhvc0_vm *cvm);
static void clean_heartbeat_timer(t_qhvc0_vm *cvm);
static void timer_cvm_connect_qhvc0(void *data);
static void change_to_state(t_qhvc0_vm *cvm, int state);
static void arm_cloonix_agent_handshake_timeout(t_qhvc0_vm *cvm);
static int door2ag_fd_event_cb(void *ptr, int llid, int fd);
void door2ag_error_cb(void *ptr, int llid, int err, int from);
static int alloc_door2ag_llid(int is_listen, int llid, t_qhvc0_vm *cvm);

static t_qhvc0_vm *head_cvm;
static int nb_qhvc0;
static t_qhvc0_vm *g_door2ag_llid[CLOWNIX_MAX_CHANNELS];
static char g_buf[MAX_QHVC_LEN];


/****************************************************************************/
static int sock_header_test(char *rx)
{
  int result = 0;
  if (!(((rx[8] & 0xFF) == 0xDE) &&
       ((rx[9] & 0xFF) == 0xAD) &&
       ((rx[10] & 0xFF) == 0xCA) &&
       ((rx[11] & 0xFF) == 0xFE) &&
       ((rx[12] & 0xFF) == 0xDE) &&
       ((rx[13] & 0xFF) == 0xCA) &&
       ((rx[14] & 0xFF) == 0xBE) &&
       ((rx[15] & 0xFF) == 0xAF)))
    {
    KERR("%02X %02X %02X %02X %02X %02X %02X %02X",
         (rx[8] & 0xFF), (rx[9] & 0xFF), (rx[10] & 0xFF), (rx[11] & 0xFF),
         (rx[12] & 0xFF), (rx[13] & 0xFF), (rx[14] & 0xFF), (rx[15] & 0xFF));
    result = -1;
    }
  else
    result  = ((rx[2] & 0xFF) << 8) + (rx[3] & 0xFF);
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int working_vm_qhvc0_llid(t_qhvc0_vm *cvm)
{
  int result = 0;
  if (cvm->vm_qhvc0_llid)
    {
    if (msg_exist_channel(cvm->vm_qhvc0_llid))
      result = 1;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void protected_tx(t_qhvc0_vm *cvm, int len, char *buf)
{
  if (working_vm_qhvc0_llid(cvm))
    {
    watch_tx(cvm->vm_qhvc0_llid, len, buf);
    }
  else
    KERR(" ");
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void entry_in_state_automaton_hcv0_failure(t_qhvc0_vm *cvm, char *info)
{
  change_to_state(cvm, state_failure);
  KERR("%s %s", cvm->name, info);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void entry_in_state_automaton_1(t_qhvc0_vm *cvm)
{
  cvm->in_guest_ls_done = 0;
  change_to_state(cvm, state_waiting_resp_first_try);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void entry_in_state_automaton_2(t_qhvc0_vm *cvm)
{
  cvm->in_guest_cloonix_agent_start_done = 0;
  change_to_state(cvm, state_waiting_resp_launch_agent);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void entry_in_state_automaton_3(t_qhvc0_vm *cvm)
{
  change_to_state(cvm, state_waiting_cloonix_agent_req);
  arm_cloonix_agent_handshake_timeout(cvm);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void entry_in_state_automaton_4(t_qhvc0_vm *cvm, int is_hvc0)
{
  if (is_hvc0)
    {
    change_to_state(cvm, state_waiting_hvc0_is_cloonix_backdoor);
    protected_tx(cvm,strlen(RESP_HVCO_CLOONIX2AG)+1,RESP_HVCO_CLOONIX2AG);
    arm_cloonix_agent_handshake_timeout(cvm);
    }
  else
    {
    change_to_state(cvm, state_vport_is_cloonix_backdoor);
    doors_send_command(get_doorways_llid(),0,cvm->name,
                       CLOONIX_UP_VPORT_AND_RUNNING);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void entry_in_state_automaton_hvc0_is_backdoor(t_qhvc0_vm *cvm)
{
  int fd, llid;
  fd = util_socket_listen_unix(utils_get_qbackdoor_hvc0_path(cvm->vm_id));
  if (fd < 0)
    {
    entry_in_state_automaton_hcv0_failure(cvm, "DOORWAY NOT LISTENING");
    }
  else
    {
    llid = msg_watch_fd(fd, door2ag_fd_event_cb, 
                        door2ag_error_cb, "door2ag");
    if (llid <= 0)
      {
      entry_in_state_automaton_hcv0_failure(cvm, "DOORWAY PROBLEM");
      }
    else
      {
      if (alloc_door2ag_llid(1, llid, cvm))
        KERR("%s", cvm->name);
      change_to_state(cvm, state_hvc0_is_cloonix_backdoor);
      doors_send_command(get_doorways_llid(),0,cvm->name,
                         CLOONIX_UP_HVC_AND_RUNNING);
      doors_send_add_vm(get_doorways_llid(), 0, cvm->name,
                        utils_get_qbackdoor_hvc0_path(cvm->vm_id));
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static t_qhvc0_vm *vm_get_with_name(char *name)
{
  t_qhvc0_vm *cvm = head_cvm;
  while (cvm && (strcmp(cvm->name, name)))
    cvm = cvm->next;
  return cvm;
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
static void timer_entry_in_state_automaton_2(void *data)
{
  char *name = (char *) data;
  t_qhvc0_vm *cvm = vm_get_with_name(name);
  if (cvm)
    {
    if (cvm->auto_state != state_waiting_after_first_try_success)
      KERR("%d", cvm->auto_state);
    else
      entry_in_state_automaton_2(cvm);
    }
  clownix_free(name, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void arm_timer_entry_in_state_automaton_2(t_qhvc0_vm *cvm)
{
  char *name = (char *) clownix_malloc(MAX_NAME_LEN, 5);
  memset(name, 0, MAX_NAME_LEN);
  strncpy(name, cvm->name, MAX_NAME_LEN - 1);
  change_to_state(cvm, state_waiting_after_first_try_success);
  clownix_timeout_add(800, timer_entry_in_state_automaton_2, 
                      (void *) name, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static int rx_pktbuf_fill(int *len, char  *buf, t_rx_pktbuf *rx_pktbuf)
{
  int result, headsize = 16;
  int len_chosen, len_desired, len_avail = *len;
  if (rx_pktbuf->offset < headsize)
    {
    len_desired = headsize - rx_pktbuf->offset;
    if (len_avail >= len_desired)
      {
      len_chosen = len_desired;
      result = 1;
      }
    else
      {
      len_chosen = len_avail;
      result = 2;
      }
    }
  else
    {
    if (rx_pktbuf->paylen <= 0)
      KOUT(" ");
    len_desired = headsize + rx_pktbuf->paylen - rx_pktbuf->offset;
    if (len_avail >= len_desired)
      {
      len_chosen = len_desired;
      result = 3;
      }
    else
      {
      len_chosen = len_avail;
      result = 2;
      }
    }
  if (len_chosen + rx_pktbuf->offset > MAX_A2D_LEN)
    KOUT("%d %d", len_chosen, rx_pktbuf->offset);
  memcpy(rx_pktbuf->buf+rx_pktbuf->offset, buf, len_chosen);
  rx_pktbuf->offset += len_chosen;
  *len -= len_chosen;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int rx_pktbuf_get_paylen(t_rx_pktbuf *rx_pktbuf)
{
  int result = 0;
  int headsize=16;
  int hlen = sock_header_test(rx_pktbuf->buf);
  if (hlen == -1)
    {
    KERR("SYNC LOST");
    rx_pktbuf->offset = 0;
    rx_pktbuf->paylen = 0;
    rx_pktbuf->payload = NULL;
    result = -1;
    }
  else
    {
    rx_pktbuf->paylen = hlen;
    rx_pktbuf->payload = rx_pktbuf->buf + headsize;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void rx_pktbuf_process(t_qhvc0_vm *cvm, int from_ag, 
                              t_rx_pktbuf *rx_pktbuf)
{
  int headsize=16;
  if (!rx_pktbuf->payload)
    KOUT(" ");
  if (from_ag)
    watch_tx(cvm->door2ag_llid, rx_pktbuf->paylen+headsize, rx_pktbuf->buf);
  else
    watch_tx(cvm->vm_qhvc0_llid, rx_pktbuf->paylen+headsize, rx_pktbuf->buf);
  rx_pktbuf->offset = 0;
  rx_pktbuf->paylen = 0;
  rx_pktbuf->payload = NULL;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void rx_pktbuf_agent(t_qhvc0_vm *cvm, int from_ag, int len, char  *buf)
{
  int res, len_done, len_left_to_do = len;
  t_rx_pktbuf *rx_pktbuf;
  if (from_ag)
    rx_pktbuf = &(cvm->rx_pktbuf_fag);
  else
    rx_pktbuf = &(cvm->rx_pktbuf_tag);
  while (len_left_to_do)
    {
    len_done = len - len_left_to_do;
    res = rx_pktbuf_fill(&len_left_to_do, buf + len_done, rx_pktbuf);
    if (res == 1)
      {
      if (rx_pktbuf_get_paylen(rx_pktbuf))
        break;
      }
    else if (res == 2)
      {
      }
    else if (res == 3)
      {
      rx_pktbuf_process(cvm, from_ag, rx_pktbuf);
      }
    else
      KOUT("%d", res);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void rx_ag2door(char *name, int len, char *buf)
{
  t_qhvc0_vm *cvm = vm_get_with_name(name);
  if ((cvm) &&
      (cvm->auto_state == state_hvc0_is_cloonix_backdoor) &&
      (working_vm_qhvc0_llid(cvm)))
    {
    if ((!cvm->door2ag_llid) || (!msg_exist_channel(cvm->door2ag_llid)))
      KERR("%s %d", name, len);
    else
      {
      rx_pktbuf_agent(cvm, 1, len, buf);
      }
    }
  else
    KERR(" ");
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int alloc_door2ag_llid(int is_listen, int llid, t_qhvc0_vm *cvm)
{
  int result = -1;
  t_qhvc0_vm *cur = g_door2ag_llid[llid];
  if (!cur)
    {
    if (is_listen)
      cvm->door2ag_listen_llid = llid;
    else
      cvm->door2ag_llid = llid;
    g_door2ag_llid[llid] = cvm;
    result = 0;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void free_door2ag_llid(int is_listen, int llid)
{
  t_qhvc0_vm *cur = g_door2ag_llid[llid];
  if (llid)
    {
    if (msg_exist_channel(llid))
      msg_delete_channel(llid);
    if (!cur)
      KERR(" ");
    else
      {
      if (is_listen)
        {
        if (cur->door2ag_listen_llid != llid)
          KERR(" ");
        cur->door2ag_listen_llid = 0;
        }
      else
        {
        if (cur->door2ag_llid != llid)
          KERR(" ");
        cur->door2ag_llid = 0;
        }
      g_door2ag_llid[llid] = 0;
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
t_qhvc0_vm *get_door2ag_llid(int llid)
{
  t_qhvc0_vm *cur = g_door2ag_llid[llid];
  return cur;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void err_door2ag_cb (void *ptr, int llid, int err, int from)
{
  t_qhvc0_vm *cvm = get_door2ag_llid(llid);
  if (!cvm)
    KERR(" ");
  else
    KERR("%s", cvm->name);
  free_door2ag_llid(0, llid);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int rx_door2ag_cb(void *ptr, int llid, int fd)
{
  t_qhvc0_vm *cvm = get_door2ag_llid(llid);
  int len;
  len = util_read (g_buf, MAX_QHVC_LEN, fd);
  if (len <= 0)
    {
    free_door2ag_llid(0, llid);
    KERR(" ");
    }
  else
    {
    if (!cvm)
      KERR("%d", len);
    else
      {
      if ((!cvm->vm_qhvc0_llid) || (!msg_exist_channel(cvm->vm_qhvc0_llid)))
        KERR("%s %d", cvm->name, len);
      else
        {
        rx_pktbuf_agent(cvm, 0, len, g_buf);
        }
      }
    }
  return len;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void door2ag_error_cb(void *ptr, int llid, int err, int from)
{
  t_qhvc0_vm *cvm = get_door2ag_llid(llid);
  if (!cvm)
    KERR(" ");
  else
    KERR("%s", cvm->name);
  free_door2ag_llid(0, llid);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int door2ag_fd_event_cb(void *ptr, int llid, int fd)
{
  t_qhvc0_vm *cvm = get_door2ag_llid(llid);
  int traf_fd, traf_llid;
  if (!cvm)
    KERR(" ");
  else
    {
    if (cvm->door2ag_listen_llid != llid)
      KERR("%s %d %d", cvm->name, cvm->door2ag_listen_llid, llid);
    else
      {
      util_fd_accept(fd, &traf_fd, __FUNCTION__);
      if (traf_fd < 0)
        KERR("%s", cvm->name);
      else
        {
        traf_llid = msg_watch_fd(traf_fd, rx_door2ag_cb, 
                                 err_door2ag_cb, "door2ag");
        if (traf_llid <= 0) 
          KERR("%s", cvm->name);
        else
          {
          if (alloc_door2ag_llid(0, traf_llid, cvm))
            KERR("%s", cvm->name);
          }
        }
      }
    }
  return 0;
}
/*---------------------------------------------------------------------------*/



/*****************************************************************************/
static void change_to_state(t_qhvc0_vm *cvm, int state)
{

/*
  if (state != cvm->auto_state)
    {
    KERR("%s %d--->%d", cvm->name,  cvm->auto_state, state);
    if (state == state_hvc0_is_cloonix_backdoor)
      KERR("%s BACKDOOR USING HVC0", cvm->name);
    if (state == state_vport_is_cloonix_backdoor)
      KERR("%s BACKDOOR USING VPORT", cvm->name);
    }
*/

  cvm->auto_state = state;
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
static t_qhvc0_vm *vm_get_with_llid(int llid)
{
  t_qhvc0_vm *cvm = head_cvm;
  while (cvm && (cvm->vm_qhvc0_llid != llid))
    cvm = cvm->next;
  return cvm;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void init_rx_buf(t_qhvc0_vm *cvm)
{
  memset(cvm->tot_rx, 0, MAX_TOT_RX_LEN);
  memset(cvm->tot_rx_cmd, 0, MAX_QHVC_LEN);
  cvm->tot_rx_offset = 0;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static void cmd_rx_begin(t_qhvc0_vm *cvm, char *cmd)
{
  init_rx_buf(cvm);
  memset(cvm->tot_rx, ' ', strlen(END_HVCO_CMD_MARKER));
  cvm->tot_rx_offset = strlen(cvm->tot_rx);
  snprintf(cvm->tot_rx_cmd, MAX_QHVC_LEN-1, "%s\r\necho %s\r\n", 
           cmd, END_HVCO_CMD_MARKER);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void begin_and_send(t_qhvc0_vm *cvm, char *cmd)
{
  cmd_rx_begin(cvm, cmd);
  protected_tx(cvm, strlen(cvm->tot_rx_cmd), cvm->tot_rx_cmd);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void cloonix_handshake_timeout(void *data)
{
  t_cloonix_handshake_timeout *pt = (t_cloonix_handshake_timeout *) data;
  t_qhvc0_vm *cvm = vm_get_with_name(pt->name);
  if ((cvm) && (cvm->cloonix_handshake_id == pt->cloonix_handshake_id)) 
    {
    cvm->timeout_cloonix_agent_handshake = 0;
    if ((cvm->auto_state != state_vport_is_cloonix_backdoor) && 
        (cvm->auto_state != state_hvc0_is_cloonix_backdoor)) 
      {
      KERR("BAD BACKDOOR %s %d", cvm->name, cvm->auto_state);
      entry_in_state_automaton_1(cvm);
      }
    }
  else
    clownix_free(pt, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void arm_cloonix_agent_handshake_timeout(t_qhvc0_vm *cvm)
{
  t_cloonix_handshake_timeout *pt;
  cvm->cloonix_handshake_id += 1;
  cvm->timeout_cloonix_agent_handshake = 1;
  pt = (t_cloonix_handshake_timeout *) 
       clownix_malloc(sizeof(t_cloonix_handshake_timeout), 13);
  memset(pt, 0, sizeof(t_cloonix_handshake_timeout));
  strncpy(pt->name, cvm->name, MAX_NAME_LEN - 1);
  pt->cloonix_handshake_id = cvm->cloonix_handshake_id;
  clownix_timeout_add(3000, cloonix_handshake_timeout, (void *) pt, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static int pattern_found_in_rx(t_qhvc0_vm *cvm, char  *buf, 
                               char *pattern1, char *pattern2)
{
  int len_left, result = 0;
  char *ptr;
  len_left = MAX_TOT_RX_LEN - cvm->tot_rx_offset;
  ptr = cvm->tot_rx + cvm->tot_rx_offset;
  cvm->tot_rx_offset += snprintf(ptr, len_left-1, "%s", buf);
  if (strstr(cvm->tot_rx, pattern1))
    {
    if (!pattern2)
      {
      result = 1;
      init_rx_buf(cvm);
      }
    else
      {
      if (strstr(cvm->tot_rx, pattern2))
        {
        result = 1;
        init_rx_buf(cvm);
        }
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void qhvc0_rx(t_qhvc0_vm *cvm, int len, char  *buf)
{
  if (cvm->auto_state == state_hvc0_is_cloonix_backdoor) 
    {
    rx_ag2door(cvm->name, len, buf);
    }
  else if (cvm->auto_state == state_waiting_hvc0_is_cloonix_backdoor) 
    {
    if (pattern_found_in_rx(cvm, buf, ACK_HVCO_AG2CLOONIX, NULL)) 
      {
      entry_in_state_automaton_hvc0_is_backdoor(cvm);
      }
    }
  else if (cvm->auto_state == state_waiting_cloonix_agent_req) 
    {
    if (pattern_found_in_rx(cvm, buf, REQ_VPORT_AG2CLOONIX, NULL))
      {
      entry_in_state_automaton_4(cvm, 0);
      }
    else if (pattern_found_in_rx(cvm, buf, REQ_HVCO_AG2CLOONIX, NULL)) 
      {
      entry_in_state_automaton_4(cvm, 1);
      }
    } 
  else if (cvm->auto_state == state_waiting_resp_first_try)
    {
    if (pattern_found_in_rx(cvm, buf, END_HVCO_CMD_MARKER, "sbin"))
      {
      arm_timer_entry_in_state_automaton_2(cvm);
      }
    }
  else if (cvm->auto_state == state_waiting_resp_launch_agent)
    {
    if (pattern_found_in_rx(cvm, buf, END_HVCO_CMD_MARKER, 
                            "i_think_cloonix_agent_is_up"))
      {
      entry_in_state_automaton_3(cvm);
      }
    }
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
static void clean_connect_timer(t_qhvc0_vm *cvm)
{
  if (cvm->connect_abs_beat_timer)
    clownix_timeout_del(cvm->connect_abs_beat_timer, cvm->connect_ref_timer,
                        __FILE__, __LINE__);
  cvm->connect_abs_beat_timer = 0;
  cvm->connect_ref_timer = 0;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void clean_heartbeat_timer(t_qhvc0_vm *cvm)
{
  if (cvm->heartbeat_abeat)
    clownix_timeout_del(cvm->heartbeat_abeat, cvm->heartbeat_ref,
                        __FILE__, __LINE__);
  cvm->heartbeat_abeat = 0;
  cvm->heartbeat_ref = 0;
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
static void timer_hvc0_tx(void *data)
{ 
  char *name = (char *) data;
  t_qhvc0_vm *cvm = vm_get_with_name(name);
  if (cvm)
    {
    if (cvm->not_first_time_read == 0)
      KERR("%s may have a bad hvc0 configuration (exists?)", name);
    }
  clownix_free(name, __FUNCTION__);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void arm_timer_hvc0_tx(t_qhvc0_vm *cvm, int val)
{
  char *nm = (char *) clownix_malloc(MAX_NAME_LEN, 13);
  memset(nm, 0, MAX_NAME_LEN);
  strncpy(nm, cvm->name, MAX_NAME_LEN - 1);
  clownix_timeout_add(val, timer_hvc0_tx, (void *) nm, NULL, NULL);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void vm_release(t_qhvc0_vm *cvm)
{
  if (!cvm)
    KOUT(" ");
  clean_connect_timer(cvm);
  clean_heartbeat_timer(cvm);
  free_door2ag_llid(0, cvm->door2ag_llid);
  free_door2ag_llid(1, cvm->door2ag_listen_llid);
  if (cvm->vm_qhvc0_llid)
    llid_trace_free(cvm->vm_qhvc0_llid, 0, __FUNCTION__);
  if (cvm->prev)
    cvm->prev->next = cvm->next;
  if (cvm->next)
    cvm->next->prev = cvm->prev;
  if (cvm == head_cvm)
    head_cvm = cvm->next;
  if (nb_qhvc0 == 0)
    KOUT(" ");
  clownix_free(cvm, __FUNCTION__);
  nb_qhvc0--;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static t_qhvc0_vm *vm_alloc(char *name, t_vm *vm)
{
  t_qhvc0_vm *cvm = NULL;
  cvm = (t_qhvc0_vm *) clownix_malloc(sizeof(t_qhvc0_vm), 5);
  memset(cvm, 0, sizeof(t_qhvc0_vm));
  strncpy(cvm->name, name, MAX_NAME_LEN-1);
  cvm->vm_id = vm->kvm.vm_id;
  cvm->vm_config_flags = vm->kvm.vm_config_flags;
  if (head_cvm)
    head_cvm->prev = cvm;
  cvm->next = head_cvm;
  head_cvm = cvm;
  nb_qhvc0++;
  return cvm;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void err_llid_retry(int llid, t_qhvc0_vm *cvm)
{
  if (!cvm->vm_qhvc0_llid)
    KOUT(" ");
  if (llid != cvm->vm_qhvc0_llid)
    KOUT(" ");
  llid_trace_free(cvm->vm_qhvc0_llid, 0, __FUNCTION__);
  cvm->vm_qhvc0_llid = 0;
  clean_connect_timer(cvm);
  clean_heartbeat_timer(cvm);
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
static void vm_err_cb (void *ptr, int llid, int err, int from)
{
  t_qhvc0_vm *cvm;
  cvm = vm_get_with_llid(llid);
  if (cvm)
    {
    err_llid_retry(llid, cvm);
    }
  else
    KERR(" ");
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int vm_rx_cb(void *ptr, int llid, int fd)
{
  int len;
  t_qhvc0_vm *cvm;
  t_vm *vm;
  static char buf[MAX_QHVC_LEN];
  memset(buf, 0, MAX_QHVC_LEN);
  len = util_read(buf, MAX_QHVC_LEN, fd);
  cvm = vm_get_with_llid(llid);
  if (!cvm)
    KERR(" ");
  else
    {
    if (len < 0)
      {
      vm = cfg_get_vm(cvm->name);
      if (vm && (!vm->vm_to_be_killed))
        KERR("%s", cvm->name);
      err_llid_retry(llid, cvm);
      }
    else
      {
      if (cvm->not_first_time_read == 0)
        {
        cvm->not_first_time_read = 1;
        ga_qhvc0_heartbeat_init(cvm);
        }
      if (len > 0)
        qhvc0_rx(cvm, len, buf);
      }
    }
  return len;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void scheduler_heartbeat(t_qhvc0_vm *cvm)
{
  char script_start_dropbear[MAX_LEN_DROPBEAR]; 
  if (cvm->auto_state == state_waiting_resp_first_try)
    {
    if ((cvm->in_guest_ls_done == 0) || (cvm->in_guest_ls_done > 10))
      {
      cvm->in_guest_ls_done = 1;
      begin_and_send(cvm, "ls /"); 
      }
    cvm->in_guest_ls_done += 1;
    }
  else if (cvm->auto_state == state_waiting_resp_launch_agent)
    {
    if ((cvm->in_guest_cloonix_agent_start_done == 0) || 
        (cvm->in_guest_cloonix_agent_start_done > 20))
      {
      cvm->in_guest_cloonix_agent_start_done = 1;
      snprintf(script_start_dropbear, MAX_LEN_DROPBEAR, "%s", 
               CMD_START_DROPBEAR_CLOONIX);
      begin_and_send(cvm, script_start_dropbear);
      }
    cvm->in_guest_cloonix_agent_start_done++;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_ga_heartbeat(void *data)
{
  t_qhvc0_vm *cvm = (t_qhvc0_vm *) data;
  if (!cvm)
    KOUT(" ");
  cvm->heartbeat_abeat = 0;
  cvm->heartbeat_ref = 0;
  if (working_vm_qhvc0_llid(cvm))
    {
    scheduler_heartbeat(cvm);
    clownix_timeout_add(100, timer_ga_heartbeat, (void *) cvm,
                        &(cvm->heartbeat_abeat), &(cvm->heartbeat_ref));
    }
  else
    {
    entry_in_state_automaton_hcv0_failure(cvm, "BAD SOCK TO HVC0");
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void ga_qhvc0_heartbeat_init(t_qhvc0_vm *cvm)
{
  if ((!cvm) || (!cvm->name))
    KOUT(" ");
  if (working_vm_qhvc0_llid(cvm))
    {
    clean_heartbeat_timer(cvm);
    clownix_timeout_add(100, timer_ga_heartbeat, (void *) cvm,
                        &(cvm->heartbeat_abeat), &(cvm->heartbeat_ref));
    entry_in_state_automaton_1(cvm);
    }
  else
    KERR("%s", cvm->name);
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
static void timer_cvm_connect_qhvc0(void *data)
{ 
  t_qhvc0_vm *cvm = (t_qhvc0_vm *) data;
  char *qmon;
  int fd, llid;
  t_vm *vm;
  if ((!cvm) || (!cvm->name))
    KOUT(" ");
  cvm->connect_abs_beat_timer = 0;
  cvm->connect_ref_timer = 0;
  vm = cfg_get_vm(cvm->name);
  if (vm)
    {
    cvm->pid = utils_get_pid_of_machine(vm);
    if (!cvm->pid)
      clownix_timeout_add(100, timer_cvm_connect_qhvc0, (void *) cvm,
                          &(cvm->connect_abs_beat_timer),
                          &(cvm->connect_ref_timer));
    else if (!cvm->ready_to_connect_hvc0)
      {
      clownix_timeout_add(300, timer_cvm_connect_qhvc0, (void *) cvm,
                          &(cvm->connect_abs_beat_timer),
                          &(cvm->connect_ref_timer));
      cvm->ready_to_connect_hvc0 = 1;
      }
    else
      {
      if (!(cvm->vm_qhvc0_llid))
        { 
        qmon = utils_get_qhvc0_path(vm->kvm.vm_id);
        if (!util_nonblock_client_socket_unix(qmon, &fd))
          {
          if (fd <= 0)
            KOUT(" ");
          cvm->vm_qhvc0_fd = fd;
          llid=msg_watch_fd(cvm->vm_qhvc0_fd, vm_rx_cb, vm_err_cb, "cloon");
          if (llid == 0)
            KOUT(" ");
          llid_trace_alloc(llid,"CLOON",0,0, type_llid_trace_unix_qmonitor);
          cvm->vm_qhvc0_llid = llid;
          arm_timer_hvc0_tx(cvm, 36000);
          protected_tx(cvm, strlen("\r\n"), "\r\n");
          }
        else
          KERR("%s", cvm->name);
        }
      else
        KERR("%s", cvm->name);
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void flag_ping_to_cloonix_agent_ko(char *name)
{
  t_small_evt vm_evt;
  t_vm *vm;
  vm = cfg_get_vm(name);
  if ((vm) && (vm->kvm.vm_config_flags & VM_FLAG_CLOONIX_AGENT_PING_OK))
    {
    vm->kvm.vm_config_flags &= ~VM_FLAG_CLOONIX_AGENT_PING_OK;
    memset(&vm_evt, 0, sizeof(vm_evt));
    strncpy(vm_evt.name, name, MAX_NAME_LEN-1);
    vm_evt.evt = vm_evt_cloonix_ga_ping_ko;
    event_subscriber_send(topo_small_event, (void *) &vm_evt);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void flag_ping_to_cloonix_agent_ok(char *name)
{
  t_small_evt vm_evt;
  t_vm *vm;
  vm = cfg_get_vm(name);
  if ((vm) && 
      (!(vm->kvm.vm_config_flags & VM_FLAG_CLOONIX_AGENT_PING_OK)))
    {
    vm->kvm.vm_config_flags |= VM_FLAG_CLOONIX_AGENT_PING_OK;
    memset(&vm_evt, 0, sizeof(t_small_evt));
    strncpy(vm_evt.name, name, MAX_NAME_LEN-1);
    vm_evt.evt = vm_evt_cloonix_ga_ping_ok;
    event_subscriber_send(topo_small_event, (void *) &vm_evt);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void qhvc0_event_backdoor(char *name, int backdoor_evt)
{
  t_qhvc0_vm *cvm = vm_get_with_name(name);
  if (cvm)
    {
    if  (backdoor_evt == backdoor_evt_connected)
      {
      cvm->backdoor_connected = 1;
      }
    else if  (backdoor_evt == backdoor_evt_disconnected)
      {
      cvm->backdoor_connected = 0;
      }
    else if  (backdoor_evt == backdoor_evt_ping_ok)
      {
      flag_ping_to_cloonix_agent_ok(name);
      }
    else if  (backdoor_evt == backdoor_evt_ping_ko)
      {
      flag_ping_to_cloonix_agent_ko(name);
      if ((cvm->auto_state != state_waiting_resp_launch_agent)  &&
          (cvm->auto_state != state_waiting_resp_first_try)   &&
          (cvm->auto_state != state_waiting_after_first_try_success))
        {
        if (!cvm->timeout_cloonix_agent_handshake)
          {
          KERR("%s PING KO RESTART PROCEDURE", name);
          doors_send_command(get_doorways_llid(),0,cvm->name,
                             CLOONIX_DOWN_AND_NOT_RUNNING);
          entry_in_state_automaton_1(cvm);
          }
        }
      }
    else
      KOUT("%d", backdoor_evt);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void qhvc0_reinit_vm_in_doorways(void)
{
  int i, nb;
  t_vm *vm = cfg_get_first_vm(&nb);
  t_qhvc0_vm *cvm;
  for (i=0; i<nb; i++)
    {
    if (!vm)
      KOUT(" ");
    cvm = vm_get_with_name(vm->kvm.name);
    if (cvm)
      {
      doors_send_add_vm(get_doorways_llid(), 0, vm->kvm.name,
                        utils_get_qbackdoor_path(vm->kvm.vm_id));
      if (cvm->auto_state == state_hvc0_is_cloonix_backdoor)
        {
        doors_send_command(get_doorways_llid(),0,cvm->name,
                           CLOONIX_UP_HVC_AND_RUNNING);
        doors_send_add_vm(get_doorways_llid(), 0, cvm->name,
                          utils_get_qbackdoor_hvc0_path(cvm->vm_id));
        KERR("%s", vm->kvm.name);
        }
      else if (cvm->auto_state == state_vport_is_cloonix_backdoor)
        {
        doors_send_command(get_doorways_llid(),0,cvm->name,
                           CLOONIX_UP_VPORT_AND_RUNNING);
        KERR("%s", vm->kvm.name);
        }
      else
        entry_in_state_automaton_1(cvm);
      }
    vm =  vm->next;
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void qhvc0_begin_qemu_unix(char *name)
{
  t_vm *vm;
  t_qhvc0_vm *cvm = vm_get_with_name(name);
  vm = cfg_get_vm(name);
  if (vm && !cvm)
    {
    cvm = vm_alloc(name, vm);
    clownix_timeout_add(10, timer_cvm_connect_qhvc0, (void *) cvm,
                        &(cvm->connect_abs_beat_timer),
                        &(cvm->connect_ref_timer));
    }
  else if (cvm)
    {
    KERR("%s %d", cvm->name, cvm->auto_state);
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void qhvc0_end_qemu_unix(char *name)
{
  t_qhvc0_vm *cvm = vm_get_with_name(name);
  if (cvm)
    vm_release(cvm);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
int qhvc0_still_present(void)
{
  return nb_qhvc0;
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void init_qhvc0(void)
{
  head_cvm = NULL;
  nb_qhvc0 = 0;
}
/*--------------------------------------------------------------------------*/

