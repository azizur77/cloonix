/****************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#include "sock_utils.h"

static int g_second_current;
static int g_second_offset;
static int g_fd;
static struct timeval g_timeout;


/*****************************************************************************/
static int get_sec(void)
{
  struct timespec ts;
  int result = -1;
  if (!clock_gettime(CLOCK_MONOTONIC, &ts))
    result = (unsigned int) (ts.tv_sec - g_second_offset);
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static int get_sec_init(void)
{
  struct timespec ts;
  int result = -1;
  if (!clock_gettime(CLOCK_MONOTONIC, &ts))
    {
    g_second_offset = ts.tv_sec;
    result = 0;
    }
  return result;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void action_read(int fd)
{
  int rx_len;
  char buf[101];
  rx_len = read (fd, buf, 100);
  if (rx_len == 0)
    {
    printf("Problem read 0\n");
    exit(1);
    }
  else if (rx_len < 0)
    {
    if ((errno == EAGAIN) || (errno ==EINTR))
      rx_len = 0;
    else
      {
      printf("Problem read -1\n");
      exit(1);
      }
    }
  else
    {
    if (!strcmp(buf, "Cliping"))
      write(g_fd, "Svrpong", strlen("Svrpong") + 1);
    printf("%s\n", buf);
    }
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static void action_heartbeat(int cur_sec)
{
  printf("Beat: %d\n", cur_sec);
  if (g_fd >= 0)
    write(g_fd, "ping", strlen("ping") + 1);
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static int select_wait_and_switch(void)
{
  fd_set infd;
  int cur_sec, ret, result = -1;
  FD_ZERO(&infd);
  FD_SET(g_fd, &infd);
  ret = select(g_fd + 1, &infd, NULL, NULL, &g_timeout);
  if (ret < 0)
    printf("Error select\n");
  else if (ret == 0) 
    {
    g_timeout.tv_sec = 1;
    g_timeout.tv_usec = 0;
    result = 0;
    }
  else if (ret > 0) 
    {
    if (FD_ISSET(g_fd, &infd))
      {
      action_read(g_fd);
      result = 0;
      }
    else
      printf("Wrong select\n");
    }
  if (result == 0)
    {
    cur_sec = get_sec();
    if (cur_sec != g_second_current)
      {
      g_second_current = cur_sec;
      action_heartbeat(cur_sec);
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void usage(char *name)
{
  printf("\n%s <port>\n", name);
  exit(1);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int main(int argc, char *argv[])
{ 
  if (argc != 2)
    usage(argv[0]);
  if (get_sec_init())
    printf("Problem clock\n");
  else
    {
    g_fd = util_server_socket_inet(argv[2]);
    if (g_fd < 0)
      printf("Problem socket\n");
    else
      {
      for (;;)
        if (select_wait_and_switch())
          printf("Problem select\n");
      }
    }
  return 0;
}
/*--------------------------------------------------------------------------*/
