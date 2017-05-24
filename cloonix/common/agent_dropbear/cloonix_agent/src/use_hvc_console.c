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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>


#include "sock.h"
#include "commun.h"


/*---------------------------------------------------------------------------*/

#define REQ_VPORT_AG2CLOONIX "req_ag2cloonix_vport_is_cloonix_backdoor"
#define REQ_HVCO_AG2CLOONIX  "req_ag2cloonix_hvc0_is_cloonix_backdoor"
#define ACK_HVCO_AG2CLOONIX  "ack_ag2cloonix_hvc0_is_cloonix_backdoor"
#define RESP_HVCO_CLOONIX2AG "resp_cloonix2ag_hvc0_is_cloonix_backdoor"

#define MAX_RX_LEN 500
static int  g_fd_tty;
static char g_buf[MAX_RX_LEN];


/*****************************************************************************/
static int open_pty(char *name)
{
  int ttyfd;
  struct termios tios;
  ttyfd = open(name, O_RDWR | O_NOCTTY);
  if (ttyfd < 0)
    KOUT("%s", name);
  else
    {
    if (tcgetattr(ttyfd, &tios) == 0)
      {
      tios.c_iflag = 0;
      tios.c_oflag = 0;
      tios.c_lflag = 0;
      tios.c_cflag = (CS8);
      tios.c_cc[VMIN] = 1;
      tios.c_cc[VTIME] = 0;
      if (tcsetattr(ttyfd, TCSAFLUSH, &tios) < 0)
        KOUT("couldn't set attributes %s", name);
      }
    else
      KOUT("couldn't get attributes %s", name);
    }
  return ttyfd;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static int write_fd_tty(int fd, int len, char *buf)
{
  int txlen;
  txlen = write(fd, buf, len);
  if (len <= 0)
    KOUT("%d %d", len, errno);
  else
    {
    if (txlen != len)
      KOUT("%d %d", len, txlen);
    }
  return len;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int event_fd_tty(int fd)
{
  int len, end_handshake = 0;
  len = read(fd, g_buf, MAX_RX_LEN);
  if (len == 0)
    KOUT(" ");
  else if (len < 0)
    {
    if ((errno != EAGAIN) && (errno != EINTR))
      KOUT("%d", errno);
    }
  else
    {
    if (!strcmp(g_buf, RESP_HVCO_CLOONIX2AG))
      {
      len = strlen(ACK_HVCO_AG2CLOONIX) + 1;
      write_fd_tty(g_fd_tty, len, ACK_HVCO_AG2CLOONIX);
      end_handshake = 1;
      }
    }
  return end_handshake;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void prepare_fd_set(fd_set *infd)
{
  FD_ZERO(infd);
  FD_SET(g_fd_tty, infd);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int get_biggest_fd(void)
{
  int result = g_fd_tty;
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int select_wait_handshake_loop(void)
{
  fd_set infd;
  int fd_max, result, end_handshake = 0;
  static struct timeval timeout;
  prepare_fd_set(&infd);
  fd_max = get_biggest_fd();
  result = select(fd_max + 1, &infd, NULL, NULL, &timeout);
  if ( result < 0 )
    KOUT(" ");
  else if (result == 0)
    {
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000;
    }
  else
    {
    if (FD_ISSET(g_fd_tty, &infd))
      {
      if (event_fd_tty(g_fd_tty))
        end_handshake = 1;
      }
    }
  return end_handshake;
}
/*--------------------------------------------------------------------------*/


/*****************************************************************************/
int use_hvc_console(int use_hvc)
{
  int len;
  if (use_hvc)
    {
    g_fd_tty = open_pty("/dev/hvc0");
    for (;;)
      {
      len = strlen(REQ_HVCO_AG2CLOONIX) + 1;
      write_fd_tty(g_fd_tty, len, REQ_HVCO_AG2CLOONIX);
      if (select_wait_handshake_loop())
        break;
      }
    KERR("END_HVC0_HANDSHAKE");
    }
  else
    {
    len = strlen(REQ_VPORT_AG2CLOONIX) + 1;
    usleep(10000);
    g_fd_tty = open_pty("/dev/hvc0");
    write_fd_tty(g_fd_tty, len, REQ_VPORT_AG2CLOONIX);
    close(g_fd_tty);
    g_fd_tty = 0;
    }
  return (g_fd_tty);
}
/*--------------------------------------------------------------------------*/

