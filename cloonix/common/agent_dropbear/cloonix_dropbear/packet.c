/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#include "includes.h"
#include "packet.h"
#include "session.h"
#include "dbutil.h"
#include "ssh.h"
#include "algo.h"
#include "buffer.h"
#include "service.h"
#include "channel.h"
#include "queue.h"
#include "io_clownix.h"


static int read_packet_init();
size_t cloonix_read(int fd, void *buf, size_t count);
size_t cloonix_write(int fd, const void *buf, size_t count);
void cloonix_enqueue(struct Queue* queue, void* item);
void cloonix_dequeue(struct Queue* queue);


/***************************************************************************/
int write_packet(void)
{
  int result = 0;
  int len, written;
  buffer * writebuf = NULL;
  if (isempty(&ses.writequeue))
    result = -1;
  else
    {
    writebuf = (buffer*)examine(&ses.writequeue);
    len = writebuf->len - 1 - writebuf->pos;
    if (len <= 0)
      KOUT(" ");
    written = cloonix_write(ses.sock_out, buf_getptr(writebuf, len), len);
    if (written < 0) 
      {
      if ((errno != EINTR) && (errno != EAGAIN)) 
        KOUT("Error writing: %s", strerror(errno));
      result = -1;
      } 
    else if (written == 0) 
      {
      KERR("ERR_0_WRITE");
      ses.remoteclosed();
      result = -1;
      }
    else if (written == len) 
      {
      cloonix_dequeue(&ses.writequeue);
      buf_free(writebuf);
      writebuf = NULL;
      } 
    else 
      {
      buf_incrpos(writebuf, written);
      KERR("%d %d", written, len);
      }
    }
  return result;
}
/*-------------------------------------------------------------------------*/


/***************************************************************************/
void read_packet()
{
  int ret, len, maxlen;
  unsigned char blocksize;
  blocksize = ses.keys->recv.algo_crypt->blocksize;
  if (ses.readbuf == NULL || ses.readbuf->len < blocksize) 
    {
    ret = read_packet_init();
    if (ret == DROPBEAR_FAILURE) 
      return;
    }
  maxlen = ses.readbuf->len - ses.readbuf->pos;
  if (maxlen < 0)
    KOUT("%d %d", ses.readbuf->len, ses.readbuf->pos);
  else if (maxlen == 0) 
    {
    len = 0;
    } 
  else 
    {
    len = cloonix_read(ses.sock_in, buf_getptr(ses.readbuf, maxlen), maxlen);
    if (len < 0)
      {
      if ((errno != EINTR) && (errno != EAGAIN)) 
        KOUT("Error reading %s", strerror(errno));
      } 
    else if (len == 0)
      {
      KERR("ERR_0_WRITE");
      ses.remoteclosed();
      }
    else
      {
      buf_incrpos(ses.readbuf, len);
      if (len == maxlen) 
        {
        decrypt_packet();
        }
      }
    }
}

/* Function used to read the initial portion of a packet, and determine the
 * length. Only called during the first BLOCKSIZE of a packet. */
/* Returns DROPBEAR_SUCCESS if the length is determined, 
 * DROPBEAR_FAILURE otherwise */
static int read_packet_init() {

	unsigned int maxlen;
	int slen;
	unsigned int len;
	unsigned int blocksize;
	unsigned int macsize;


	blocksize = ses.keys->recv.algo_crypt->blocksize;
	macsize = ses.keys->recv.algo_mac->hashsize;

	if (ses.readbuf == NULL) {
		/* start of a new packet */
		ses.readbuf = buf_new(INIT_READBUF);
	}

	maxlen = blocksize - ses.readbuf->pos;
			
	/* read the rest of the packet if possible */
	slen = cloonix_read(ses.sock_in, buf_getwriteptr(ses.readbuf, maxlen), maxlen);
	if (slen == 0) {
		ses.remoteclosed();
	}
	if (slen < 0) {
			return DROPBEAR_FAILURE;
	}

	buf_incrwritepos(ses.readbuf, slen);

	if ((unsigned int)slen != maxlen) {
		/* don't have enough bytes to determine length, get next time */
		return DROPBEAR_FAILURE;
	}

	/* now we have the first block, need to get packet length, so we decrypt
	 * the first block (only need first 4 bytes) */
	buf_setpos(ses.readbuf, 0);
	if (ses.keys->recv.crypt_mode->decrypt(buf_getptr(ses.readbuf, blocksize), 
				buf_getwriteptr(ses.readbuf, blocksize),
				blocksize, NULL)) {
		KOUT("Error decrypting");
	}
	len = buf_getint(ses.readbuf) + 4 + macsize;



	/* check packet length */
	if ((len > RECV_MAX_PACKET_LEN) ||
		(len < MIN_PACKET_LEN + macsize) ||
		((len - macsize) % blocksize != 0)) {
		KOUT("Integrity error (bad packet size %u)", len);
	}

	if (len > ses.readbuf->size) {
		buf_resize(ses.readbuf, len);		
	}
	buf_setlen(ses.readbuf, len);
	buf_setpos(ses.readbuf, blocksize);
	return DROPBEAR_SUCCESS;
}

/* handle the received packet */
void decrypt_packet() {

	unsigned char blocksize;
	unsigned char macsize;
	unsigned int padlen;
	unsigned int len;

	blocksize = ses.keys->recv.algo_crypt->blocksize;
	macsize = ses.keys->recv.algo_mac->hashsize;


	/* we've already decrypted the first blocksize in read_packet_init */
	buf_setpos(ses.readbuf, blocksize);

	/* decrypt it in-place */
	len = ses.readbuf->len - macsize - ses.readbuf->pos;
	if (ses.keys->recv.crypt_mode->decrypt(
				buf_getptr(ses.readbuf, len), 
				buf_getwriteptr(ses.readbuf, len),
				len, NULL)) {
		KOUT("Error decrypting");
	}
	buf_incrpos(ses.readbuf, len);

	/* get padding length */
	buf_setpos(ses.readbuf, PACKET_PADDING_OFF);
	padlen = buf_getbyte(ses.readbuf);
		
	/* payload length */
	/* - 4 - 1 is for LEN and PADLEN values */
	len = ses.readbuf->len - padlen - 4 - 1 - macsize;
	if ((len > RECV_MAX_PAYLOAD_LEN) || (len < 1)) {
		KOUT("Bad packet size %u", len);
	}

	buf_setpos(ses.readbuf, PACKET_PAYLOAD_OFF);

	/* copy payload */
	ses.payload = buf_new(len);
	memcpy(ses.payload->data, buf_getptr(ses.readbuf, len), len);
	buf_incrlen(ses.payload, len);

	buf_free(ses.readbuf);
	ses.readbuf = NULL;
	buf_setpos(ses.payload, 0);

	ses.recvseq++;

}


void maybe_flush_reply_queue() 
{
	struct packetlist *tmp_item = NULL, *curr_item = NULL;
	for (curr_item = ses.reply_queue_head; curr_item; ) {
		buf_putbytes(ses.writepayload,
			curr_item->payload->data, curr_item->payload->len);
			
		buf_free(curr_item->payload);
		tmp_item = curr_item;
		curr_item = curr_item->next;
		m_free(tmp_item);
		encrypt_packet();
	}
	ses.reply_queue_head = ses.reply_queue_tail = NULL;
}
	
/* encrypt the writepayload, putting into writebuf, ready for write_packet()
 * to put on the wire */
void encrypt_packet() {

	unsigned char padlen;
	unsigned char blocksize, mac_size;
	buffer * writebuf; /* the packet which will go on the wire. This is 
	                      encrypted in-place. */
	unsigned char packet_type;
	unsigned int len, encrypt_buf_size;

	time_t now;
	buf_setpos(ses.writepayload, 0);
	packet_type = buf_getbyte(ses.writepayload);
	buf_setpos(ses.writepayload, 0);

	blocksize = ses.keys->trans.algo_crypt->blocksize;
	mac_size = ses.keys->trans.algo_mac->hashsize;

	/* Encrypted packet len is payload+5. We need to then make sure
	 * there is enough space for padding or MIN_PACKET_LEN. 
	 * Add extra 3 since we need at least 4 bytes of padding */
	encrypt_buf_size = (ses.writepayload->len+4+1) 
		+ MAX(MIN_PACKET_LEN, blocksize) + 3
	/* add space for the MAC at the end */
				+ mac_size
	/* and an extra cleartext (stripped before transmission) byte for the
	 * packet type */
				+ 1;

	writebuf = buf_new(encrypt_buf_size);
	buf_setlen(writebuf, PACKET_PAYLOAD_OFF);
	buf_setpos(writebuf, PACKET_PAYLOAD_OFF);

	memcpy(buf_getwriteptr(writebuf, ses.writepayload->len),
			buf_getptr(ses.writepayload, ses.writepayload->len),
			ses.writepayload->len);
	buf_incrwritepos(writebuf, ses.writepayload->len);

	/* finished with payload */
	buf_setpos(ses.writepayload, 0);
	buf_setlen(ses.writepayload, 0);

	/* length of padding - packet length must be a multiple of blocksize,
	 * with a minimum of 4 bytes of padding */
	padlen = blocksize - (writebuf->len) % blocksize;
	if (padlen < 4) {
		padlen += blocksize;
	}
	/* check for min packet length */
	if (writebuf->len + padlen < MIN_PACKET_LEN) {
		padlen += blocksize;
	}

	buf_setpos(writebuf, 0);
	/* packet length excluding the packetlength uint32 */
	buf_putint(writebuf, writebuf->len + padlen - 4);

	/* padding len */
	buf_putbyte(writebuf, padlen);
	/* actual padding */
	buf_setpos(writebuf, writebuf->len);
	buf_incrlen(writebuf, padlen);

	/* do the actual encryption, in-place */
	buf_setpos(writebuf, 0);
	/* encrypt it in-place*/
	len = writebuf->len;
	if (ses.keys->trans.crypt_mode->encrypt(
				buf_getptr(writebuf, len),
				buf_getwriteptr(writebuf, len),
				len, NULL)) {
		KOUT("Error encrypting");
	}
	buf_incrpos(writebuf, len);


	/* The last byte of the buffer stores the cleartext packet_type. It is not
	 * transmitted but is used for transmit timeout purposes */
	buf_putbyte(writebuf, packet_type);
	/* enqueue the packet for sending. It will get freed after transmission. */
	buf_setpos(writebuf, 0);
cloonix_enqueue(&ses.writequeue, (void*)writebuf);

	/* Update counts */
	ses.transseq++;
	now = monotonic_now();
	ses.last_packet_time_any_sent = now;
	/* idle timeout shouldn't be affected by responses to keepalives.
	send_msg_keepalive() itself also does tricks with 
	ses.last_packet_idle_time - read that if modifying this code */
	if (packet_type != SSH_MSG_REQUEST_FAILURE
		&& packet_type != SSH_MSG_UNIMPLEMENTED
		&& packet_type != SSH_MSG_IGNORE) {
		ses.last_packet_time_idle = now;

	}

}


