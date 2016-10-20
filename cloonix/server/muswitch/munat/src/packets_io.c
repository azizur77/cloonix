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
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "ioc.h"
#include "sock_fd.h"
#include "main.h"
#include "machine.h"
#include "utils.h"
#include "bootp_input.h"
#include "clo_tcp.h"
#include "packets_io.h"


/****************************************************************************/
void packet_input_from_slirptux(int len, char *data)
{
  t_machine *machine;
  int resp_len, proto;
  char *src_mac, *dst_mac, *arp_tip, *arp_sip, *resp_data;
  char *name;
  proto = get_proto(len, data);
  if ((proto == proto_arp_req) || (proto == proto_ip))
    {
    dst_mac = get_dst_mac(data);
    if ((data[0] & 0x01) || 
        (!strcmp(dst_mac, OUR_MAC_GW)) ||
        (!strcmp(dst_mac, OUR_MAC_DNS)))
      {
      src_mac = get_src_mac(data);
      name = get_name_with_mac(src_mac);
      if (name)
        {
        machine = look_for_machine_with_name(name);
        if (machine)
          {
          if (proto == proto_arp_req)
            {
            arp_tip = get_arp_tip(data);
            arp_sip = get_arp_sip(data);
            if ((!strcmp(arp_tip, get_gw_given2guests())) ||
                (!strcmp(arp_tip, get_dns_given2guests())))
              {
              resp_len = format_arp_resp(src_mac,arp_sip,arp_tip,&resp_data);
              packet_output_to_slirptux(resp_len, resp_data);
              }
            }
          else
            {
            packet_ip_input(machine, src_mac, dst_mac, len, data); 
            }
          }
        }
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static void timer_packets_io(t_all_ctx *all_ctx, void *data)
{

  clownix_timeout_add(get_all_ctx(), 100, timer_packets_io, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
void packet_output_to_slirptux(int len, char *data)
{
  t_blkd *blkd;
  blkd = blkd_create_tx_full_copy(len, data, 0, 0, 0);
  sock_fd_tx(get_all_ctx(), 0, blkd);
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void packets_io_init(void)
{

  clownix_timeout_add(get_all_ctx(), 100, timer_packets_io, NULL, NULL, NULL);
}
/*--------------------------------------------------------------------------*/



