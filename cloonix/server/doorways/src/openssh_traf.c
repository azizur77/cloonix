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
#include "io_clownix.h"
#include "dispach.h"



#define MAX_RESP_LEN 500

typedef struct t_timer_resp
{
  int dido_llid;
  char buf[MAX_RESP_LEN];
} t_timer_resp;


/****************************************************************************/
static void fill_200_char_resp(char *buf, char *nat)
{
  char empyness[MAX_RESP_LEN];
  memset(buf, 0, MAX_RESP_LEN);
  memset(empyness, ' ', MAX_RESP_LEN);
  snprintf(buf, 200, "OPENSSH_DOORWAYS_RESP nat=%s %s", nat, empyness);
  buf[200] = 0;
  if (strlen(buf) != 199)
    KOUT("%d ", (int) strlen(buf));
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void send_to_openssh_client(int dido_llid, int val, int len, char *buf)
{
  if (dispach_send_to_openssh_client(dido_llid, val, len, buf))
    {
    KERR("%d %d %d", dido_llid, len, val);
    }
  else
    {
    if (val != doors_val_none)
      DOUT(NULL, FLAG_HOP_DOORS, "CLIENT_TX: %d %s", dido_llid, buf);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void timer_auto(void *data)
{
  t_timer_resp *resp = (t_timer_resp *) data;
  send_to_openssh_client(resp->dido_llid, doors_val_init_link_ok, 
                         strlen(resp->buf) + 1, resp->buf);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void arm_auto_timer_with_resp(int dido_llid, char *nat)
{
  t_timer_resp *resp;
  resp = (t_timer_resp *) clownix_malloc(sizeof(t_timer_resp), 10);
  memset(resp, 0, sizeof(t_timer_resp));
  resp->dido_llid = dido_llid;
  fill_200_char_resp(resp->buf, nat);
  clownix_timeout_add(100, timer_auto, (void *) resp, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void openssh_rx_from_client(int dido_llid, int len, char *buf_rx)
{
  char nat[MAX_NAME_LEN];

  if (sscanf(buf_rx, "OPENSSH_DOORWAYS_REQ nat=%s", nat) == 1)
    {
    arm_auto_timer_with_resp(dido_llid, nat);
    }
  else
    {
    send_to_openssh_client(dido_llid, doors_val_init_link_ko,
                           strlen("KO") + 1, "KO");
    }
}
/*--------------------------------------------------------------------------*/


