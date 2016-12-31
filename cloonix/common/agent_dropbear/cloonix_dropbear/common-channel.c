/*
 * Dropbear SSH
 * Copyright (c) 2002-2004 Matt Johnston
 * Copy-pasted for cloonix
*/


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

static void send_msg_channel_open_failure(unsigned int remotechan, int reason,
		                          char *text, char *lang);
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow, 
		unsigned int recvmaxpacket);
int writechannel(struct Channel* channel, int fd, circbuffer *cbuf);
static void send_msg_channel_window_adjust(struct Channel *channel, 
		unsigned int incr);
void send_msg_channel_data(struct Channel *channel, int isextended);
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

void delay_before_exit(struct Channel *channel);


void chancleanup() 
{
  remove_channel(&ses.channel);
}

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

struct Channel* getchannel() {
	return getchannel_msg(NULL);
}


/* Returns true if there is data remaining to be written to stdin or
 * stderr of a channel's endpoint. */
static unsigned int write_pending(struct Channel * channel) 
{
  if (channel->init_done)
    {
	if (channel->writefd >= 0 && cbuf_getused(channel->writebuf) > 0) {
		return 1;
	} else if (channel->errfd >= 0 && channel->extrabuf && 
			cbuf_getused(channel->extrabuf) > 0) {
		return 1;
	}
    }
  return 0;
}


/* EOF/close handling */
void check_close(struct Channel *channel) 
{
  int close_allowed = 0;
  if (!channel->flushing 
      && !channel->close_handler_done
      && channel->ctype->check_close
      && channel->ctype->check_close(channel))
    {
    channel->flushing = 1;
KERR("flush ");
    }
	
	/* if a type-specific check_close is defined we will only exit
	   once that has been triggered. this is only used for a server "session"
	   channel, to ensure that the shell has exited (and the exit status 
	   retrieved) before we close things up. */
  if (!channel->ctype->check_close	
      || channel->close_handler_done
      || channel->ctype->check_close(channel)) 
    {
    close_allowed = 1;
KERR("close allowed ");
    }

  if (channel->recv_close && !write_pending(channel) && close_allowed) 
    {
    if (!channel->sent_close) 
      {
      send_msg_channel_close(channel);
      }
    KERR(" ");
    remove_channel(channel);
    return;
    }

	/* have a server "session" and child has exited */
  if (channel->recv_eof && !write_pending(channel))
    {
KERR("1close channel ");
    close_chan_fd(channel, channel->writefd);
    }

  if (channel->ctype->check_close && close_allowed)
    {
KERR("2close channel ");
    close_chan_fd(channel, channel->writefd);
    }


	/* Special handling for flushing read data after an exit. We
	   read regardless of whether the select FD was set,
	   and if there isn't data available, the channel will get closed. */
  if (channel->flushing) 
    {
KERR("flux ");
    if (channel->readfd >= 0 && channel->transwindow > 0) 
      {
      send_msg_channel_data(channel, 0);
KERR("flux ");
      }
    if (ERRFD_IS_READ(channel) && channel->errfd >= 0 
        && channel->transwindow > 0) 
      {
      send_msg_channel_data(channel, 1);
KERR("flux ");
      }
    }

	/* If we're not going to send any more data, send EOF */
  if (!channel->sent_eof
       && (channel->readfd == -1) 
       && (ERRFD_IS_WRITE(channel) || channel->errfd == -1)) 
    {
KERR("send eof ");
    send_msg_channel_eof(channel);
    }

	/* And if we can't receive any more data from them either, close up */
  if (channel->readfd == -1
      && channel->writefd == -1 
      && (ERRFD_IS_WRITE(channel) || channel->errfd == -1)
      && !channel->sent_close
      && close_allowed
      && !write_pending(channel))
    {
KERR("DELiA ");
    delay_before_exit(channel);
    }
}

/* Check whether a deferred (EINPROGRESS) connect() was successful, and
 * if so, set up the channel properly. Otherwise, the channel is cleaned up, so
 * it is important that the channel reference isn't used after a call to this
 * function */
void check_in_progress(struct Channel *channel) {

	int val;
	socklen_t vallen = sizeof(val);


	if (getsockopt(channel->writefd, SOL_SOCKET, SO_ERROR, &val, &vallen)
			|| val != 0) {
		send_msg_channel_open_failure(channel->remotechan,
				SSH_OPEN_CONNECT_FAILED, "", "");
		close(channel->writefd);
                KERR(" ");
		remove_channel(channel);
	} else {
		chan_initwritebuf(channel);
		send_msg_channel_open_confirmation(channel, channel->recvwindow,
				channel->recvmaxpacket);
		channel->readfd = channel->writefd;
	}
}


/* Send the close message and set the channel as closed */
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

/* call this when trans/eof channels are closed */
static void send_msg_channel_eof(struct Channel *channel) 
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_EOF);
  buf_putint(ses.writepayload, channel->remotechan);
  encrypt_packet();
  channel->sent_eof = 1;
}

size_t cloonix_write(int fd, const void *ibuf, size_t count);

/* Called to write data out to the local side of the channel. 
 * Only called when we know we can write to a channel, writes as much as
 * possible */
int writechannel(struct Channel* channel, int fd, circbuffer *cbuf) 
{
  int len, maxlen, result = 0;
  maxlen = cbuf_readlen(cbuf);
  len = cloonix_write(fd, cbuf_readptr(cbuf, maxlen), maxlen);
  if (len <= 0) 
    {
    if (len < 0 && ((errno != EINTR) && (errno != EAGAIN))) 
      {
      result = -1;
      KERR("%d", errno);
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

/* Set the file descriptors for the main select in session.c
 * This avoid channels which don't have any window available, are closed, etc*/
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

/* handle the channel EOF event, by closing the channel filedescriptor. The
 * channel isn't closed yet, it is left until the incoming (from the program
 * etc) FD is also EOF */
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


/* Handle channel closure(), respond in kind and close the channels */
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

/* Remove a channel entry, this is only executed after both sides have sent
 * channel close */
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

/* Handle channel specific requests, passing off to corresponding handlers
 * such as chansession or x11fwd */
void recv_msg_channel_request() {

	struct Channel *channel;

	channel = getchannel();
if (!channel)
return;

	if (channel->sent_close) {
		return;
	}

	if (channel->ctype->reqhandler 
			&& !channel->close_handler_done) {
		channel->ctype->reqhandler(channel);
	} else {
		int wantreply;
		buf_eatstring(ses.payload);
		wantreply = buf_getbool(ses.payload);
		if (wantreply) {
			send_msg_channel_failure(channel);
		}
	}


}

size_t cloonix_read(int fd, void *ibuf, size_t count);

/* Reads data from the server's program/shell/etc, and puts it in a
 * channel_data packet to send.
 * chan is the remote channel, isextended is 0 if it is normal data, 1
 * if it is extended data. if it is extended, then the type is in
 * exttype */
void send_msg_channel_data(struct Channel *channel, int isextended) {

	int len;
	size_t maxlen, size_pos;
	int fd;

if(channel->sent_close)
KOUT(" ");

	if (isextended) {
		fd = channel->errfd;
	} else {
		fd = channel->readfd;
	}
if (fd < 0)
KOUT(" ");

	maxlen = MIN(channel->transwindow, channel->transmaxpacket);
	/* -(1+4+4) is SSH_MSG_CHANNEL_DATA, channel number, string length, and 
	 * exttype if is extended */
	maxlen = MIN(maxlen, 
			ses.writepayload->size - 1 - 4 - 4 - (isextended ? 4 : 0));
	if (maxlen == 0) {
		return;
	}

	buf_putbyte(ses.writepayload, 
			isextended ? SSH_MSG_CHANNEL_EXTENDED_DATA : SSH_MSG_CHANNEL_DATA);
	buf_putint(ses.writepayload, channel->remotechan);
	if (isextended) {
		buf_putint(ses.writepayload, SSH_EXTENDED_DATA_STDERR);
	}
	/* a dummy size first ...*/
	size_pos = ses.writepayload->pos;
	buf_putint(ses.writepayload, 0);

	/* read the data */
	len = cloonix_read(fd, buf_getwriteptr(ses.writepayload, maxlen), maxlen);

	if (len <= 0) {
		if (len == 0 || ((errno != EINTR) && (errno != EAGAIN))) {
                        KERR("%d ", errno);
		}
		buf_setpos(ses.writepayload, 0);
		buf_setlen(ses.writepayload, 0);
		return;
	}

	buf_incrwritepos(ses.writepayload, len);
	buf_setpos(ses.writepayload, size_pos);
	buf_putint(ses.writepayload, len);

	channel->transwindow -= len;

	encrypt_packet();
	
	if (channel->flushing && len < (ssize_t)maxlen)
	{
                KERR("%d %d ", len, (int) maxlen);
	}
}

/* We receive channel data */
void recv_msg_channel_data() {

	struct Channel *channel;

	channel = getchannel();
if (!channel)
return;

	common_recv_msg_channel_data(channel, channel->writefd, channel->writebuf);
}

/* Shared for data and stderr data - when we receive data, put it in a buffer
 * for writing to the local file descriptor */
void common_recv_msg_channel_data(struct Channel *channel, int fd, 
		circbuffer * cbuf) {

	unsigned int datalen;
	unsigned int maxdata;
	unsigned int buflen;
	unsigned int len;


	if (channel->recv_eof) {
		KOUT("Received data after eof");
	}

	if (fd < 0 || !cbuf) {
		/* If we have encountered failed write, the far side might still
		 * be sending data without having yet received our close notification.
		 * We just drop the data. */
		return;
	}

	datalen = buf_getint(ses.payload);

	maxdata = cbuf_getavail(cbuf);

	/* Whilst the spec says we "MAY ignore data past the end" this could
	 * lead to corrupted file transfers etc (chunks missed etc). It's better to
	 * just die horribly */
	if (datalen > maxdata) {
		KOUT("Oversized packet %d %d", datalen, maxdata);
	}

	/* We may have to run throught twice, if the buffer wraps around. Can't
	 * just "leave it for next time" like with writechannel, since this
	 * is payload data */
	len = datalen;
	while (len > 0) {
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

/* Increment the outgoing data window for a channel - the remote end limits
 * the amount of data which may be transmitted, this window is decremented
 * as data is sent, and incremented upon receiving window-adjust messages */
void recv_msg_channel_window_adjust() {

	struct Channel * channel;
	unsigned int incr;
	channel = getchannel();
if (!channel)
return;
	incr = buf_getint(ses.payload);
	channel->transwindow += incr;

}

/* Increment the incoming data window for a channel, and let the remote
 * end know */
static void send_msg_channel_window_adjust(struct Channel* channel, 
		unsigned int incr) {


	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_WINDOW_ADJUST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, incr);

	encrypt_packet();
}
	
/* Handle a new channel request, performing any channel-type-specific setup */
void recv_msg_channel_open() 
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

/* Send a failure message */
void send_msg_channel_failure(struct Channel *channel) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_FAILURE);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
}

/* Send a success message */
void send_msg_channel_success(struct Channel *channel) {


	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_SUCCESS);
	buf_putint(ses.writepayload, channel->remotechan);

	encrypt_packet();
}

/* Send a channel open failure message, with a corresponding reason
 * code (usually resource shortage or unknown chan type) */
static void send_msg_channel_open_failure(unsigned int remotechan, 
		int reason, char *text, char *lang) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_FAILURE);
	buf_putint(ses.writepayload, remotechan);
	buf_putint(ses.writepayload, reason);
	buf_putstring(ses.writepayload, text, strlen((char*)text));
	buf_putstring(ses.writepayload, lang, strlen((char*)lang));

	encrypt_packet();
}

/* Confirm a channel open, and let the remote end know what number we've
 * allocated and the receive parameters */
static void send_msg_channel_open_confirmation(struct Channel* channel,
		unsigned int recvwindow, 
		unsigned int recvmaxpacket) {

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putint(ses.writepayload, 0);
	buf_putint(ses.writepayload, recvwindow);
	buf_putint(ses.writepayload, recvmaxpacket);

	encrypt_packet();
}

static void close_chan_fd(struct Channel *channel, int fd) {

	int closein = 0, closeout = 0;
		close(fd);
		closein = closeout = 1;

	if (closeout && (fd == channel->readfd)) {
		channel->readfd = -1;
	}
	if (closeout && ERRFD_IS_READ(channel) && (fd == channel->errfd)) {
		channel->errfd = -1;
	}

	if (closein && fd == channel->writefd) {
		channel->writefd = -1;
	}
	if (closein && ERRFD_IS_WRITE(channel) && (fd == channel->errfd)) {
		channel->errfd = -1;
	}

}


/* Create a new channel, and start the open request. This is intended
 * for X11, agent, tcp forwarding, and should be filled with channel-specific
 * options, with the calling function calling encrypt_packet() after
 * completion. It is mandatory for the caller to encrypt_packet() if
 * a channel is returned. NULL is returned on failure. */
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

/* Confirmation that our channel open request (for forwardings) was 
 * successful*/
void recv_msg_channel_open_confirmation() {

	struct Channel * channel;
	int ret;


	channel = getchannel();
if (!channel)
return;

	if (!channel->await_open) {
		KOUT("Unexpected channel reply");
	}
	channel->await_open = 0;

	channel->remotechan =  buf_getint(ses.payload);
	channel->transwindow = buf_getint(ses.payload);
	channel->transmaxpacket = buf_getint(ses.payload);
	

	/* Run the inithandler callback */
	if (channel->ctype->inithandler) {
		ret = channel->ctype->inithandler(channel);
		if (ret > 0) {
                        KERR("%p", channel);
			remove_channel(channel);
			return;
		}
	}

}

/* Notification that our channel open request failed */
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

void send_msg_request_success() 
{
  buf_putbyte(ses.writepayload, SSH_MSG_REQUEST_SUCCESS);
  encrypt_packet();
}

void send_msg_request_failure() 
{
  buf_putbyte(ses.writepayload, SSH_MSG_REQUEST_FAILURE);
  encrypt_packet();
}

struct Channel* get_any_ready_channel() 
{
  struct Channel *chan = &ses.channel;
  if ((!(chan->sent_eof) || (chan->recv_eof)) &&
      (!(chan->await_open))) 
    return chan;
  else
    return NULL;
}

void start_send_channel_request(struct Channel *channel, char *type) 
{
  buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
  buf_putint(ses.writepayload, channel->remotechan);
  buf_putstring(ses.writepayload, type, strlen(type));
}

void wrapper_exit(int val, char *file, int line)
{
  KERR("%s %d", file, line); 
  exit(val);
}
