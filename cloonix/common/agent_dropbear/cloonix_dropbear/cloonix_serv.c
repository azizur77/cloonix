#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <asm/types.h>
#include <signal.h>



#include "io_clownix.h"
#include "cloonix_timer.h"
#include "util_sock.h"
#include "queue.h"
#include "packet.h"
#include "session.h"



#define XAUTH_BIN1 "/usr/bin/X11/xauth"
#define XAUTH_BIN2 "/usr/bin/xauth"
#define XAUTH_BIN3 "/bin/xauth"
#define MAX_BIN_PATH_LEN 100
#define XAUTH_CMD_LEN 500

#define ERRFD_IS_READ(channel) ((channel)->extrabuf == NULL)
#define ERRFD_IS_WRITE(channel) (!ERRFD_IS_READ(channel))

int writechannel(struct Channel* channel, int fd, circbuffer *cbuf);
void send_msg_channel_data(struct Channel *channel, int isextended);
void check_close(struct Channel *channel);


struct sshsession *get_srv_session_loop(void);


/*---------------------------------------------------------------------------*/
void rpct_recv_app_msg(void *ptr, int llid, int tid, char *line){KOUT(" ");}
void rpct_recv_diag_msg(void *ptr, int llid, int tid, char *line){KOUT(" ");}
void rpct_recv_evt_msg(void *ptr, int llid, int tid, char *line){KOUT(" ");}
void rpct_recv_cli_req(void *ptr, int llid, int tid,
                    int cli_llid, int cli_tid, char *line){KOUT(" ");}
void rpct_recv_cli_resp(void *ptr, int llid, int tid,
                     int cli_llid, int cli_tid, char *line){KOUT(" ");}
void rpct_recv_pid_req(void *ptr, int llid, int tid, int secoffset, char *name){KOUT(" ");}
void rpct_recv_pid_resp(void *ptr, int llid, int tid, char *name, int pid){KOUT(" ");}
void rpct_recv_hop_sub(void *ptr, int llid, int tid, int flags_hop){KOUT(" ");}
void rpct_recv_hop_unsub(void *ptr, int llid, int tid){KOUT(" ");}
void rpct_recv_hop_msg(void *ptr, int llid, int tid,
                      int flags_hop, char *txt){KOUT(" ");}
void rpct_recv_report(void *ptr, int llid, t_blkd_item *item) {KOUT(" ");}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
static char *get_xauth_bin(void)
{
  static char path[MAX_BIN_PATH_LEN];
  memset(path, 0, MAX_BIN_PATH_LEN);
  if (!access(XAUTH_BIN1, F_OK))
    strncpy(path, XAUTH_BIN1, MAX_BIN_PATH_LEN-1);
  else if (!access(XAUTH_BIN2, F_OK))
    strncpy(path, XAUTH_BIN2, MAX_BIN_PATH_LEN-1);
  else if (!access(XAUTH_BIN3, F_OK))
    strncpy(path, XAUTH_BIN3, MAX_BIN_PATH_LEN-1);
  else
    strncpy(path, "xauth", MAX_BIN_PATH_LEN-1);
  return path;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void cloonix_serv_xauth_cookie_key(char *display, char *cookie_key)
{
  char cmd[XAUTH_CMD_LEN];
  char *xauthority = getenv("XAUTHORITY");
  memset(cmd, 0, XAUTH_CMD_LEN);
  snprintf(cmd, XAUTH_CMD_LEN-1, "%s add %s MIT-MAGIC-COOKIE-1 %s",
               get_xauth_bin(), display, cookie_key);
  if ((xauthority) && (access(xauthority, W_OK)))
    KERR("%s not writable", xauthority);
  else
    system(cmd);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int cloonix_socket_listen_unix(char *pname)
{
  int ret, fd, len;
  struct sockaddr_un serv;
  mode_t old_mask;
  if (strlen(pname) >= 108)
    KOUT("%d", (int)(strlen(pname)));
  old_mask = umask (0000);
  unlink (pname);
  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    KOUT("%d %d\n", fd, errno);
  memset (&serv, 0, sizeof (struct sockaddr_un));
  serv.sun_family = AF_UNIX;
  strncpy (serv.sun_path, pname, strlen(pname));
  len = sizeof (serv.sun_family) + strlen (serv.sun_path);
  ret = bind (fd, (struct sockaddr *) &serv, len);
  if (ret == 0)
    {
    ret = listen (fd, 50);
    if (ret == 0)
      umask (old_mask);
    else
      {
      close(fd);
      fd = -1;
      printf("listen failure\n");
      }
    }
  else
    {
    close(fd);
    fd = -1;
    printf("bind failure %s %d\n", pname, errno);
    }
  return fd;
}
/*--------------------------------------------------------------------------*/


/****************************************************************************/
size_t cloonix_read(int fd, void *ibuf, size_t count)
{
  size_t len = read(fd, ibuf, count);
  return len;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
size_t cloonix_write(int fd, const void *ibuf, size_t count)
{
  size_t len = write(fd, ibuf, count);
  return len;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void cloonix_dequeue(struct Queue* queue)
{
  dequeue(queue);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void cloonix_enqueue(struct Queue* queue, void* item)
{
  enqueue(queue, item);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static int ident_readln(int fd, char* buf, int count) 
{
        char in, result;
        int pos = 0;
        int num = 0;
        fd_set fds;
        struct timeval timeout;
        if (count < 1) {
                return -1;
        }
        FD_ZERO(&fds);
        while (pos < count-1) {
                FD_SET(fd, &fds);
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;
                result = select(fd+1, &fds, NULL, NULL, &timeout);
                if (result < 0) {
                        if ((errno == EINTR) || (errno == EAGAIN)) {
                                continue;
                        }
                        return -1;
                KERR("%d %d", pos, count);
                }
                if (result == 0)
                  KERR("%d %d", pos, count);
                if (FD_ISSET(fd, &fds)) {
                        num = read(fd, &in, 1);
                        if (num < 0) {
                                if ((errno == EINTR) || (errno == EAGAIN)) {
                                        continue; /* not a real error */
                                }
                                return -1;
                        }
                        if (num == 0) {
                                return -1;
                        }
                        if (in == '\n') {
                                break;
                        }
                        if (in != '\r') {
                                buf[pos] = in;
                                pos++;
                        }
                }
        }
        buf[pos] = '\0';
        return pos+1;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void read_session_identification() 
{
  char linebuf[256];
  int i, len = 0;
  char done = 0;
  for (i = 0; i < 50; i++)
    {
    len = ident_readln(ses.sock_in, linebuf, sizeof(linebuf));
    if (len < 0 && ((errno != EINTR) && (errno != EAGAIN)))
      {
      KERR("IDERR");
      break;
      }
    if (len >= 4 && memcmp(linebuf, "SSH-", 4) == 0)
      {
      done = 1;
      break;
      }
    }
  if (!done)
    {
    KERR("ERR_NOT_DONE: %s", linebuf);
    ses.remoteclosed();
    }
  else
    {
    ses.remoteident = m_malloc(len);
    memcpy(ses.remoteident, linebuf, len);
    }
  if (strcmp(ses.remoteident, LOCAL_IDENT) != 0)
     KOUT("%s %s", linebuf, ses.remoteident);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void channelio(fd_set *readfds, fd_set *writefds)
{
  struct Channel *channel = &ses.channel;
  int do_check_close = 0;
  if (channel->init_done)
    {
    if (channel->readfd >= 0 && FD_ISSET(channel->readfd, readfds))
      {
      send_msg_channel_data(channel, 0);
      do_check_close = 1;
      }
    if ((ERRFD_IS_READ(channel)) && 
        (channel->errfd >= 0) &&
        (FD_ISSET(channel->errfd, readfds))) 
      {
      send_msg_channel_data(channel, 1);
      do_check_close = 1;
      }
    if (channel->writefd >= 0 && FD_ISSET(channel->writefd, writefds)) 
      {
      if (writechannel(channel, channel->writefd, channel->writebuf))
        KOUT(" ");
      do_check_close = 1;
      }
    if ((ERRFD_IS_WRITE(channel)) &&
        (channel->errfd >= 0 && FD_ISSET(channel->errfd, writefds)))
      {
      if (writechannel(channel, channel->errfd, channel->extrabuf))
        KOUT(" ");
      do_check_close = 1;
      }
    if (ses.channel_signal_pending)
      {
      do_check_close = 1;
      ses.channel_signal_pending = 0;
      }
    if (do_check_close)
      {
      check_close(channel);
      }
    }
}
/*--------------------------------------------------------------------------*/

/*****************************************************************************/
static int delta_ms(struct timeval *cur, struct timeval *last)
{
  int delta = 0;
  delta = (cur->tv_sec - last->tv_sec)*1000;
  delta += cur->tv_usec/1000;
  delta -= last->tv_usec/1000;
  return delta;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
static void my_gettimeofday(struct timeval *tv)
{
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    KOUT(" ");
  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec/1000;
}
/*---------------------------------------------------------------------------*/

/****************************************************************************/
void cloonix_srv_session_loop(void) 
{
  static struct timeval last_heartbeat;
  fd_set readfd, writefd;
  int val, delta;
  char x;
  struct sshsession *ses = get_srv_session_loop();
  struct timeval cur;
  cloonix_timer_init();
  my_gettimeofday(&last_heartbeat);
  for(;;)
    {
    if ((ses->sock_in == -1) || (ses->sock_out == -1))
      KOUT("%d %d", ses->sock_in, ses->sock_out);
    FD_ZERO(&writefd);
    FD_ZERO(&readfd);
    if (ses->payload)
      KOUT(" ");
    if (ses->remoteident || isempty(&ses->writequeue))
      FD_SET(ses->sock_in, &readfd);
    if (!isempty(&ses->writequeue))
      FD_SET(ses->sock_out, &writefd);
    FD_SET(ses->signal_pipe[0], &readfd);
    setchannelfds(&readfd, &writefd);
    val = select(ses->maxfd+1, &readfd, &writefd, NULL, NULL);
    if (exitflag)
      KOUT("Terminated by signal");
    if (val < 0 && ((errno != EINTR) && (errno != EAGAIN)))
      KOUT("Error in select %d %d %d", errno, ses->sock_in, ses->sock_out);
    if (val > 0)
      {
      if (FD_ISSET(ses->signal_pipe[0], &readfd))
        {
        while (read(ses->signal_pipe[0], &x, 1) > 0) {}
        }
      if (FD_ISSET(ses->sock_in, &readfd))
        {
        if (!ses->remoteident)
          read_session_identification();
        else
          read_packet();
        }
      if (ses->payload != NULL)
        process_packet();
      maybe_flush_reply_queue();
      channelio(&readfd, &writefd);
      if (!isempty(&ses->writequeue))
        write_packet();
      }
    my_gettimeofday(&cur);
    delta = delta_ms(&cur, &last_heartbeat);
    memcpy(&last_heartbeat, &cur, sizeof(struct timeval));
    if (delta > 100)
      cloonix_timer_beat();
    }
}
/*--------------------------------------------------------------------------*/
