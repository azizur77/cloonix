/****************************************************************************/
/* Copy-pasted-modified for cloonix                License GPL-3.0+         */
/*--------------------------------------------------------------------------*/
/* Original code from:                                                      */
/*                            Dropbear SSH                                  */
/*                            Matt Johnston                                 */
/****************************************************************************/
#include "includes.h"
#include "session.h"
#include "packet.h"
#include "ssh.h"
#include "buffer.h"
#include "circbuffer.h"
#include "dbutil.h"
#include "channel.h"
#include "ssh.h"
#include "listener.h"
#include "runopts.h"
#include "chansession.h"
#include "io_clownix.h"

int main_i_run_in_kvm(void);
void delay_before_exit(struct Channel *channel);
size_t cloonix_read(int fd, void *ibuf, size_t count);
size_t cloonix_write(int fd, const void *ibuf, size_t count);
static void send_msg_channel_open_failure(unsigned int remotechan, int reason,
		                          char *text, char *lang);
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow, 
		unsigned int recvmaxpacket);
int writechannel(struct Channel* channel, int fd, circbuffer *cbuf);
static void send_msg_channel_window_adjust(struct Channel *channel, 
		unsigned int incr);
int send_msg_channel_data(struct Channel *channel, int isextended);
static void send_msg_channel_eof(struct Channel *channel);
static void send_msg_channel_close(struct Channel *channel);
static void remove_channel(struct Channel *channel);
void check_in_progress(struct Channel *channel);
static unsigned int write_pending(struct Channel * channel);
void check_close(struct Channel *channel);
static void close_chan_fd(struct Channel *channel, int fd);


#define ERRFD_IS_READ(channel) ((channel)->extrabuf == NULL)
#define ERRFD_IS_WRITE(channel) (!ERRFD_IS_READ(channel))

/* allow space for:
 * 1 byte  byte      SSH_MSG_CHANNEL_DATA
 * 4 bytes uint32    recipient channel
 * 4 bytes string    data
 */
#define RECV_MAX_CHANNEL_DATA_LEN (RECV_MAX_PAYLOAD_LEN-(1+4+4))


/****************************************************************************/
void chancleanup() 
{
  remove_channel(&ses.channel);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void chan_initwritebuf(struct Channel *channel)
{
  if (channel->init_done)
    {
    if ((channel->writebuf->size != 0) || (channel->recvwindow != 0))
      KOUT("%d %d ", channel->writebuf->size, channel->recvwindow);
    cbuf_free(channel->writebuf);
    channel->writebuf = cbuf_new(opts.recv_window);
    channel->recvwindow = opts.recv_window;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static struct Channel* getchannel_msg(const char* kind)
{
  unsigned int chan;
  chan = buf_getint(ses.payload);
  if (chan != 0)
    KOUT("%s  %d", kind, chan);
  if (ses.channel.init_done)
    return &(ses.channel);
  else
    return NULL;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
struct Channel* getchannel() {
	return getchannel_msg(NULL);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static unsigned int write_pending(struct Channel * channel) 
{
  int result = 0;
  if (channel->init_done)
    {
    if ((channel->writefd >= 0) && 
        (cbuf_getused(channel->writebuf) > 0)) 
      result = 1;
    else if ((channel->errfd >= 0) && 
             (channel->extrabuf) && 
             (cbuf_getused(channel->extrabuf) > 0))
      result = 1;
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void check_close(struct Channel *channel) 
{
  int close_allowed = 0;
  call_child_death_detection();
  if ((!channel->flushing) && 
      (!channel->close_handler_done) &&
      (channel->ctype->check_close) &&
      (channel->ctype->check_close(channel)))
    channel->flushing = 1;
  if ((!channel->ctype->check_close) ||
      (channel->close_handler_done)  ||
      (channel->ctype->check_close(channel))) 
    close_allowed = 1;
  if ((channel->recv_close) && 
      (!write_pending(channel)) &&
      (close_allowed))
    {
    KERR(" ");
    if (!channel->sent_close) 
      send_msg_channel_close(channel);
    remove_channel(channel);
    return;
    }
  if ((channel->recv_eof) && 
      (!write_pending(channel)))
    {
KERR("1close channel ");
    close_chan_fd(channel, channel->writefd);
    }
  if ((channel->ctype->check_close) && 
      (close_allowed))
    {
KERR("2close channel ");
    close_chan_fd(channel, channel->writefd);
    }
  if (channel->flushing) 
    {
KERR("1flux ");
    if ((channel->readfd >= 0) && 
        (channel->transwindow > 0)) 
      {
      send_msg_channel_data(channel, 0);
KERR("2flux ");
      }
    if ((ERRFD_IS_READ(channel)) && 
        (channel->errfd >= 0 ) &&
        (channel->transwindow > 0))
      {
      send_msg_channel_data(channel, 1);
KERR("3flux ");
      }
    }
  if ((!channel->sent_eof) &&
      (channel->readfd == -1) && 
      ((ERRFD_IS_WRITE(channel)) || (channel->errfd == -1))) 
    {
KERR("send eof ");
    send_msg_channel_eof(channel);
    }
  if ((channel->readfd == -1) &&
      (channel->writefd == -1) && 
      ((ERRFD_IS_WRITE(channel)) || (channel->errfd == -1)) &&
      (!channel->sent_close) &&
      (close_allowed) &&
      (!write_pending(channel)))
    {
KERR("DELiA ");
    delay_before_exit(channel);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void check_in_progress(struct Channel *channel)
{
  int val;
  socklen_t vallen = sizeof(val);
  if ((getsockopt(channel->writefd, SOL_SOCKET, SO_ERROR, &val, &vallen))|| 
      (val != 0))
    {
    KERR(" ");
    send_msg_channel_open_failure(channel->remotechan,
    SSH_OPEN_CONNECT_FAILED, "", "");
    close(channel->writefd);
    remove_channel(channel);
    }
  else
    {
    chan_initwritebuf(channel);
    send_msg_channel_open_confirmation(channel,
                                       channel->recvwindow,
                                       channel->recvmaxpacket);
    channel->readfd = channel->writefd;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void send_msg_channel_close(struct Channel *channel) 
{
  KERR(" ");
  if (channel->ctype->closehandler 
      && !channel->close_handler_done) 
    {
    KERR(" ");
    channel->ctype->closehandler(channel);
    channel->close_handler_done = 1;
    }
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_CLOSE);
  buf_putint(ses.writepayload, channel->remotechan);
  encrypt_packet();
  channel->sent_eof = 1;
  channel->sent_close = 1;
  close_chan_fd(channel, channel->readfd);
  close_chan_fd(channel, channel->errfd);
  close_chan_fd(channel, channel->writefd);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void send_msg_channel_eof(struct Channel *channel) 
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_EOF);
  buf_putint(ses.writepayload, channel->remotechan);
  encrypt_packet();
  channel->sent_eof = 1;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int writechannel(struct Channel* channel, int fd, circbuffer *cbuf) 
{
  int len, maxlen, result = 0;
  maxlen = cbuf_readlen(cbuf);
  len = cloonix_write(fd, cbuf_readptr(cbuf, maxlen), maxlen);
  if (len <= 0) 
    {
    if (len < 0 && ((errno != EINTR) && (errno != EAGAIN))) 
      {
      KERR("%d", errno);
      result = -1;
      close_chan_fd(channel, fd);
      }
    return result;
    }
  if (len != maxlen)
    result = -2;
  cbuf_incrread(cbuf, len);
  channel->recvdonelen += len;
  if (channel->recvdonelen >= RECV_WINDOWEXTEND)
    {
    send_msg_channel_window_adjust(channel, channel->recvdonelen);
    channel->recvwindow += channel->recvdonelen;
    channel->recvdonelen = 0;
    }
  if (channel->recvwindow > opts.recv_window)
    KOUT(" ");
  if (channel->recvwindow > cbuf_getavail(channel->writebuf))
    KOUT(" ");
  if ((channel->extrabuf) && 
      (channel->recvwindow > cbuf_getavail(channel->extrabuf)))
    KOUT(" ");
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void setchannelfds(fd_set *readfds, fd_set *writefds) 
{
  struct Channel *channel = &ses.channel;
  if (channel->init_done)
    {
    if (channel->transwindow > 0) 
      {
      if (channel->readfd >= 0) 
        FD_SET(channel->readfd, readfds);
      if (ERRFD_IS_READ(channel) && channel->errfd >= 0) 
        FD_SET(channel->errfd, readfds);
      }
    if ((channel->writefd >= 0) && 
        (cbuf_getused(channel->writebuf) > 0)) 
      FD_SET(channel->writefd, writefds);
    if ((ERRFD_IS_WRITE(channel)) && 
        (channel->errfd >= 0) && 
        (cbuf_getused(channel->extrabuf)) > 0) 
      FD_SET(channel->errfd, writefds);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_msg_channel_eof() 
{
  struct Channel * channel;
  KERR(" ");
  channel = getchannel_msg("EOF");
  if (channel)
    {
    channel->recv_eof = 1;
    check_close(channel);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_msg_channel_close() 
{
  struct Channel * channel;
  KERR(" ");
  channel = getchannel_msg("Close");
  if (channel)
    {
    channel->recv_eof = 1;
    channel->recv_close = 1;
    check_close(channel);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void remove_channel(struct Channel * channel) 
{
  if (channel->init_done)
  {
  cbuf_free(channel->writebuf);
  channel->writebuf = NULL;
  if (channel->extrabuf)
    {
    cbuf_free(channel->extrabuf);
    channel->extrabuf = NULL;
    }
  if (IS_DROPBEAR_SERVER || (channel->writefd != STDOUT_FILENO)) 
    {
    close(channel->writefd);
    close(channel->readfd);
    close(channel->errfd);
    }
  if (!(channel->close_handler_done) &&
       (channel->ctype->closehandler))
    {
    channel->ctype->closehandler(channel);
    channel->close_handler_done = 1;
    }
  if (!isempty(&ses.writequeue))
    KERR("not empty");
  }
  memset(channel, 0, sizeof(struct Channel)); 
  wrapper_exit(0, (char *)__FILE__, __LINE__);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_msg_channel_request()
{
  int wantreply;
  struct Channel *channel;
  channel = getchannel();
  if (!channel)
    KERR(" ");
  else if (channel->sent_close)
    KERR(" ");
  else if ((channel->ctype->reqhandler) && 
           (!channel->close_handler_done))
    channel->ctype->reqhandler(channel);
  else
    {
    buf_eatstring(ses.payload);
    wantreply = buf_getbool(ses.payload);
    if (wantreply)
      send_msg_channel_failure(channel);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int send_msg_channel_data(struct Channel *channel, int isextended)
{
  int len, result = 0;
  size_t maxlen, size_pos;
  int fd;
  if(channel->sent_close)
    KOUT(" ");
  if (isextended)
    fd = channel->errfd;
  else
    fd = channel->readfd;
  if (fd < 0)
    KOUT(" ");
  maxlen = MIN(channel->transwindow, channel->transmaxpacket);
  maxlen = MIN(maxlen,
               ses.writepayload->size - 1 - 4 - 4 - (isextended ? 4 : 0));
  if (maxlen > 0)
    {
    buf_putbyte(ses.writepayload, 
    isextended ? SSH_MSG_CHANNEL_EXTENDED_DATA : SSH_MSG_CHANNEL_DATA);
    buf_putint(ses.writepayload, channel->remotechan);
    if (isextended)
      buf_putint(ses.writepayload, SSH_EXTENDED_DATA_STDERR);
    size_pos = ses.writepayload->pos;
    buf_putint(ses.writepayload, 0);
    len = cloonix_read(fd, buf_getwriteptr(ses.writepayload, maxlen), maxlen);
    if (len <= 0)
      {
      if (len == 0 || ((errno != EINTR) && (errno != EAGAIN)))
        {
        KERR("%d ", errno);
        close_chan_fd(channel, fd);
        result = -1;
        }
      buf_setpos(ses.writepayload, 0);
      buf_setlen(ses.writepayload, 0);
      }
    else
      {
      buf_incrwritepos(ses.writepayload, len);
      buf_setpos(ses.writepayload, size_pos);
      buf_putint(ses.writepayload, len);
      channel->transwindow -= len;
      encrypt_packet();
      if (channel->flushing && len < (ssize_t)maxlen)
        KERR("%d %d ", len, (int) maxlen);
      }
    }
  return result;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_msg_channel_data()
{
  struct Channel *channel;
  channel = getchannel();
  if (!channel)
    KERR(" ");
  else
    common_recv_msg_channel_data(channel,
                                 channel->writefd,
                                 channel->writebuf);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void common_recv_msg_channel_data(struct Channel *channel, 
                                  int fd, circbuffer * cbuf)
{
  unsigned int datalen;
  unsigned int maxdata;
  unsigned int buflen;
  unsigned int len;
  if (channel->recv_eof)
    KOUT("Received data after eof");
  if ((fd >= 0) && (cbuf))
    {
    datalen = buf_getint(ses.payload);
    maxdata = cbuf_getavail(cbuf);
    if (datalen > maxdata)
      KOUT("Oversized packet %d %d", datalen, maxdata);
    len = datalen;
    while (len > 0)
      {
      buflen = cbuf_writelen(cbuf);
      buflen = MIN(buflen, len);
      memcpy(cbuf_writeptr(cbuf, buflen), 
             buf_getptr(ses.payload, buflen), buflen);
      cbuf_incrwrite(cbuf, buflen);
      buf_incrpos(ses.payload, buflen);
      len -= buflen;
      }
    if (channel->recvwindow < datalen)
      KOUT(" ");
    channel->recvwindow -= datalen;
    if (channel->recvwindow > opts.recv_window)
      KOUT(" ");
    }
  else
    KERR(" ");
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_msg_channel_window_adjust(void)
{
  struct Channel * channel;
  unsigned int incr;
  channel = getchannel();
  if (!channel)
    KERR(" ");
  else
    {
    incr = buf_getint(ses.payload);
    channel->transwindow += incr;
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void send_msg_channel_window_adjust(struct Channel* channel, 
                                           unsigned int incr)
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_WINDOW_ADJUST);
  buf_putint(ses.writepayload, channel->remotechan);
  buf_putint(ses.writepayload, incr);
  encrypt_packet();
}
/*--------------------------------------------------------------------------*/
	
/****************************************************************************/
void recv_msg_channel_open(void) 
{
  char *type;
  unsigned int typelen, transmaxpacket;
  struct Channel *channel = &ses.channel;
  unsigned int errtype = SSH_OPEN_UNKNOWN_CHANNEL_TYPE;
  int ret;
  type = buf_getstring(ses.payload, &typelen);
  channel->remotechan =  buf_getint(ses.payload);
  channel->transwindow = buf_getint(ses.payload);
  transmaxpacket = buf_getint(ses.payload);
  transmaxpacket = MIN(transmaxpacket, TRANS_MAX_PAYLOAD_LEN);
  channel->transmaxpacket = transmaxpacket;
  channel->init_done = 1;
  channel->writefd = -2;
  channel->readfd = -2;
  channel->errfd = -1;
  channel->writebuf = cbuf_new(0);
  channel->recvmaxpacket = RECV_MAX_CHANNEL_DATA_LEN;
  channel->i_run_in_kvm = main_i_run_in_kvm();


  if (typelen > MAX_NAME_LEN) 
    {
    send_msg_channel_open_failure(channel->remotechan, errtype, "", "");
    KERR("%d %s", typelen, type);
    }
  else if (strcmp(type, ses.chantype->name)) 
    {
    send_msg_channel_open_failure(channel->remotechan, errtype, "", "");
    KERR("%d %s", typelen, type);
    }
  else
    {
    
    if (channel->ctype->inithandler) 
      {
      ret = channel->ctype->inithandler(channel);
      if (ret == SSH_OPEN_IN_PROGRESS) 
        {
	m_free(type);
        }
      else if (ret > 0) 
        {
        errtype = ret;
        KERR("%p", channel);
        remove_channel(channel);
        send_msg_channel_open_failure(channel->remotechan, errtype, "", "");
        KERR("%d %s", typelen, type);
	}
      else
        {
	chan_initwritebuf(channel);
	send_msg_channel_open_confirmation(channel, channel->recvwindow,
			channel->recvmaxpacket);
	m_free(type);
        }
      }
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void send_msg_channel_failure(struct Channel *channel)
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_FAILURE);
  buf_putint(ses.writepayload, channel->remotechan);
  encrypt_packet();
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void send_msg_channel_success(struct Channel *channel)
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_SUCCESS);
  buf_putint(ses.writepayload, channel->remotechan);
  encrypt_packet();
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void send_msg_channel_open_failure(unsigned int remotechan, 
                                          int reason, char *text, 
                                          char *lang)
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_FAILURE);
  buf_putint(ses.writepayload, remotechan);
  buf_putint(ses.writepayload, reason);
  buf_putstring(ses.writepayload, text, strlen((char*)text));
  buf_putstring(ses.writepayload, lang, strlen((char*)lang));
  encrypt_packet();
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void send_msg_channel_open_confirmation(struct Channel* channel,
                                               unsigned int recvwindow, 
                                               unsigned int recvmaxpacket)
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
  buf_putint(ses.writepayload, channel->remotechan);
  buf_putint(ses.writepayload, 0);
  buf_putint(ses.writepayload, recvwindow);
  buf_putint(ses.writepayload, recvmaxpacket);
  encrypt_packet();
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
static void close_chan_fd(struct Channel *channel, int fd)
{
  int closein = 0, closeout = 0;
  close(fd);
  closein = closeout = 1;
  if (closeout && (fd == channel->readfd))
    channel->readfd = -1;
  if (closeout && ERRFD_IS_READ(channel) && (fd == channel->errfd))
    channel->errfd = -1;
  if (closein && fd == channel->writefd)
    channel->writefd = -1;
  if (closein && ERRFD_IS_WRITE(channel) && (fd == channel->errfd))
    channel->errfd = -1;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
int send_msg_channel_open_init(int fd) 
{
  struct Channel *chan = &ses.channel;
  chan->init_done = 1;
  chan->writefd = fd;
  chan->readfd = fd;
  chan->errfd = -1; 
  chan->recvmaxpacket = RECV_MAX_CHANNEL_DATA_LEN;
  chan->i_run_in_kvm = main_i_run_in_kvm();
  chan->writebuf = cbuf_new(opts.recv_window);
  chan->recvwindow = opts.recv_window;
  setnonblocking(fd);
  ses.maxfd = MAX(ses.maxfd, fd);
  chan->await_open = 1;
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN);
  buf_putstring(ses.writepayload, "session", strlen("session"));
  buf_putint(ses.writepayload, 0);
  buf_putint(ses.writepayload, opts.recv_window);
  buf_putint(ses.writepayload, RECV_MAX_CHANNEL_DATA_LEN);
  return DROPBEAR_SUCCESS;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_msg_channel_open_confirmation()
{
  struct Channel * channel;
  channel = getchannel();
  if (!channel)
    KERR(" ");
  else
    {
    if (!channel->await_open)
      KOUT("Unexpected channel reply");
    channel->await_open = 0;
    channel->remotechan =  buf_getint(ses.payload);
    channel->transwindow = buf_getint(ses.payload);
    channel->transmaxpacket = buf_getint(ses.payload);
    if (channel->ctype->inithandler)
      channel->ctype->inithandler(channel);
    }
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void recv_msg_channel_open_failure() 
{
  struct Channel * channel;
  channel = getchannel();
  KERR("%p", channel);
  if (!channel)
    return;
  if (!channel->await_open) 
    KOUT("Unexpected channel reply");
  channel->await_open = 0;
  remove_channel(channel);
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void send_msg_request_success() 
{
  buf_putbyte(ses.writepayload, SSH_MSG_REQUEST_SUCCESS);
  encrypt_packet();
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void send_msg_request_failure() 
{
  buf_putbyte(ses.writepayload, SSH_MSG_REQUEST_FAILURE);
  encrypt_packet();
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
struct Channel* get_any_ready_channel() 
{
  struct Channel *chan = &ses.channel;
  if ((!(chan->sent_eof) || (chan->recv_eof)) &&
      (!(chan->await_open))) 
    return chan;
  else
    return NULL;
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void start_send_channel_request(struct Channel *channel, char *type) 
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
  buf_putint(ses.writepayload, channel->remotechan);
  buf_putstring(ses.writepayload, type, strlen(type));
}
/*--------------------------------------------------------------------------*/

/****************************************************************************/
void wrapper_exit(int val, char *file, int line)
{
  KERR("%s %d", file, line); 
  exit(val);
}
/*--------------------------------------------------------------------------*/
