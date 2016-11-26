
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
#include "buffer.h"
#include "session.h"
#include "dbutil.h"
#include "channel.h"
#include "chansession.h"
#include "sshpty.h"
#include "termcodes.h"
#include "ssh.h"
#include "runopts.h"

#include "io_clownix.h"

/* Handles sessions (either shells or programs) requested by the client */


static void sesssigchild_handler(int UNUSED(dummy));
static int sessioncommand(struct Channel *channel, struct ChanSess *chansess,
                int iscmd, int issubsys);
static int sessionpty(struct ChanSess * chansess);
static int sessionsignal(struct ChanSess *chansess);
static int noptycommand(struct Channel *channel, struct ChanSess *chansess);
static int ptycommand(struct Channel *channel, struct ChanSess *chansess);
static int sessionwinchange(struct ChanSess *chansess);
static void execchild(struct ChanSess *chansess);
static void addchildpid(struct ChanSess *chansess, pid_t pid);
static void closechansess(struct Channel *channel);
static int newchansess(struct Channel *channel);
static void chansessionrequest(struct Channel *channel);
static int sesscheckclose(struct Channel *channel);

static void send_exitsignalstatus(struct Channel *channel);
static void send_msg_chansess_exitstatus(struct Channel * channel,
                struct ChanSess * chansess);
static void send_msg_chansess_exitsignal(struct Channel * channel,
                struct ChanSess * chansess);
static void get_termmodes(struct ChanSess *chansess);

const struct ChanType svrchansess = {
        "session", /* name */
        newchansess, /* inithandler */
        sesscheckclose, /* checkclosehandler */
        chansessionrequest, /* reqhandler */
        closechansess, /* closehandler */
};

/* required to clear environment */
extern char** environ;







static void svr_sigchild_initialise(void)
{
  struct sigaction sa_chld;
  sa_chld.sa_handler = sesssigchild_handler;
  sa_chld.sa_flags = SA_NOCLDSTOP;
  sigemptyset(&sa_chld.sa_mask);
  if (sigaction(SIGCHLD, &sa_chld, NULL) < 0)
    KOUT("signal() error");
}




/* Handler for childs exiting, store the state for return to the client */

/* There's a particular race we have to watch out for: if the forked child
 * executes, exits, and this signal-handler is called, all before the parent
 * gets to run, then the childpids[] array won't have the pid in it. Hence we
 * use the svr_ses.lastexit struct to hold the exit, which is then compared by
 * the parent when it runs. This work correctly at least in the case of a
 * single shell spawned (ie the usual case) */
static void sesssigchild_handler(int UNUSED(dummy))
{
  int status;
  pid_t pid;
  unsigned int i;
  struct exitinfo *nexit = NULL;
  const int saved_errno = errno;
  /* Make channel handling code look for closed channels */
  ses.channel_signal_pending = 1;
  while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
    {
    nexit = NULL;
    /* find the corresponding chansess */
    for (i = 0; i < svr_ses.childpidsize; i++)
      {
      if (svr_ses.childpids[i].pid == pid)
        {
        nexit = &svr_ses.childpids[i].chansess->exit;
        break;
        }
      }
    /* If the pid wasn't matched, then we might have hit the race mentioned
     * above. So we just store the info for the parent to deal with */
    if (nexit == NULL)
      {
      KERR("using lastexit");
      nexit = &svr_ses.lastexit;
      }
    nexit->exitpid = pid;
    if (WIFEXITED(status))
      {
      nexit->exitstatus = WEXITSTATUS(status);
      }
    if (WIFSIGNALED(status))
      {
      nexit->exitsignal = WTERMSIG(status);
      nexit->exitcore = 0;
      }
    else
      {
      /* we use this to determine how pid exited */
      nexit->exitsignal = -1;
      }
    /* Make sure that the main select() loop wakes up */
    while (1) 
      {
      /* isserver is just a random byte to write. We can't do anything
         about an error so should just ignore it */
      if (write(ses.signal_pipe[1], &ses.isserver, 1) == 1
          || errno != EINTR)
        {
        break;
        }
      }
    }
  errno = saved_errno;
  exit(0);
}



static int spawn_command( struct ChanSess *chansess,
                          int *ret_writefd, int *ret_readfd, 
                          int *ret_errfd, pid_t *ret_pid) {
	int infds[2];
	int outfds[2];
	int errfds[2];
	pid_t pid;

	const int FDIN = 0;
	const int FDOUT = 1;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	/* redirect stdin/stdout/stderr */
	if (pipe(infds) != 0) {
                KERR(" ");
		return DROPBEAR_FAILURE;
	}
	if (pipe(outfds) != 0) {
                KERR(" ");
		return DROPBEAR_FAILURE;
	}
	if (ret_errfd && pipe(errfds) != 0) {
                KERR(" ");
		return DROPBEAR_FAILURE;
	}
	pid = fork();
	if (pid < 0) {
                KERR(" ");
		return DROPBEAR_FAILURE;
	}

	if (!pid) {
		/* child */

		prctl(PR_SET_PDEATHSIG, SIGKILL);

		/* redirect stdin/stdout */

		if ((dup2(infds[FDIN], STDIN_FILENO) < 0) ||
			(dup2(outfds[FDOUT], STDOUT_FILENO) < 0) ||
			(ret_errfd && dup2(errfds[FDOUT], STDERR_FILENO) < 0)) {
			KOUT("Child dup2() failure");
		}

		close(infds[FDOUT]);
		close(infds[FDIN]);
		close(outfds[FDIN]);
		close(outfds[FDOUT]);
		if (ret_errfd)
		{
			close(errfds[FDIN]);
			close(errfds[FDOUT]);
		}
                execchild(chansess);
	} else {
		/* parent */
		close(infds[FDIN]);
		close(outfds[FDOUT]);

		setnonblocking(outfds[FDIN]);
		setnonblocking(infds[FDOUT]);

		if (ret_errfd) {
			close(errfds[FDOUT]);
			setnonblocking(errfds[FDIN]);
		}

		if (ret_pid) {
			*ret_pid = pid;
		}

		*ret_writefd = infds[FDOUT];
		*ret_readfd = outfds[FDIN];
		if (ret_errfd) {
			*ret_errfd = errfds[FDIN];
		}
		return DROPBEAR_SUCCESS;
	}
}

/* Runs a command with "sh -c". Will close FDs (except stdin/stdout/stderr) and
 * re-enabled SIGPIPE. If cmd is NULL, will run a login shell.
 */
static void run_shell_command(const char *cmd, unsigned int maxfd, 
                       char *usershell, char *login) 
{
  char *argv[7];
  char *baseshell = NULL;
  char *cmd_sleep;
  unsigned int i;
  int len;
  int is_login=0;
  baseshell = basename(usershell);
  if (cmd != NULL) 
    {
    cmd_sleep = m_malloc(strlen(cmd) + 30);
    sprintf(cmd_sleep, "%s ; sleep 0.01", cmd);
    argv[0] = baseshell;
    argv[1] = "--noprofile";
    argv[2] = "--norc";
    argv[3] = "-c";
    argv[4] = (char*)cmd_sleep;
    argv[5] = NULL;
    } 
  else 
    {
    if (login)
      {
      is_login = 1;
      argv[0] = login;
      argv[1] = "-p";
      argv[2] = "-f";
      argv[3] = "root";
      argv[4] = NULL;
      }
    else
      {
      len = strlen(baseshell) + 2;
      argv[0] = (char*)m_malloc(len);
      snprintf(argv[0], len, "-%s", baseshell);
      argv[1] = NULL;
      }
    }
  if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
    KOUT("signal() error");
  if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
    KOUT("signal() error");
  for (i = 3; i <= maxfd; i++)
    {
    m_close(i);
    }
  if (is_login)
    execv(login, argv);
  else
    execv(usershell, argv);
}



static int sesscheckclose(struct Channel *channel) 
{
  struct ChanSess *chansess = (struct ChanSess*)channel->typedata;
  int result = (chansess->exit.exitpid != -1);
  return result;
}

/* send the exit status or the signal causing termination for a session */
static void send_exitsignalstatus(struct Channel *channel)
{
  struct ChanSess *chansess = (struct ChanSess*)channel->typedata;
  if (chansess->exit.exitpid >= 0) 
    {
    if (chansess->exit.exitsignal > 0) 
      {
      send_msg_chansess_exitsignal(channel, chansess);
      }
    else 
      {
      send_msg_chansess_exitstatus(channel, chansess);
      }
    }
}

/* send the exitstatus to the client */
static void send_msg_chansess_exitstatus(struct Channel * channel,
		struct ChanSess * chansess) {
if (chansess->exit.exitpid == -1)
KOUT(" ");
if(chansess->exit.exitsignal != -1)
KOUT(" ");

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putstring(ses.writepayload, "exit-status", 11);
	buf_putbyte(ses.writepayload, 0); /* boolean FALSE */
	buf_putint(ses.writepayload, chansess->exit.exitstatus);

	encrypt_packet();

}

/* send the signal causing the exit to the client */
static void send_msg_chansess_exitsignal(struct Channel * channel,
		struct ChanSess * chansess) {

	int i;
	char* signame = NULL;
if (chansess->exit.exitpid == -1)
KOUT(" ");
if (chansess->exit.exitsignal <= 0)
KOUT(" ");

	KERR("send_msg_chansess_exitsignal %d", chansess->exit.exitsignal);


	/* we check that we can match a signal name, otherwise
	 * don't send anything */
	for (i = 0; signames[i].name != NULL; i++) {
		if (signames[i].signal == chansess->exit.exitsignal) {
			signame = signames[i].name;
			break;
		}
	}

	if (signame == NULL) {
		return;
	}

	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
	buf_putint(ses.writepayload, channel->remotechan);
	buf_putstring(ses.writepayload, "exit-signal", 11);
	buf_putbyte(ses.writepayload, 0); /* boolean FALSE */
	buf_putstring(ses.writepayload, signame, strlen(signame));
	buf_putbyte(ses.writepayload, chansess->exit.exitcore);
	buf_putstring(ses.writepayload, "", 0); /* error msg */
	buf_putstring(ses.writepayload, "", 0); /* lang */

	encrypt_packet();
}

/* set up a session channel */
static int newchansess(struct Channel *channel) {

	struct ChanSess *chansess;

if (channel->typedata)
KOUT("%p", channel->typedata);

	chansess = (struct ChanSess*)m_malloc(sizeof(struct ChanSess));
	chansess->cmd = NULL;
	chansess->pid = 0;

	/* pty details */
	chansess->master = -1;
	chansess->slave = -1;
	chansess->tty = NULL;
//	chansess->term = NULL;

	chansess->exit.exitpid = -1;

        chansess->i_run_in_kvm = channel->i_run_in_kvm;
	channel->typedata = chansess;

	return 0;

}

/* clean a session channel */
static void closechansess(struct Channel *channel)
{
  struct ChanSess *chansess;
  unsigned int i;
  chansess = (struct ChanSess*)channel->typedata;
  if (chansess != NULL) 
    {
    send_exitsignalstatus(channel);
    m_free(chansess->cmd);
    if (chansess->tty) 
      {
      pty_release(chansess->tty);
      m_free(chansess->tty);
      }

    /* clear child pid entries */
    for (i = 0; i < svr_ses.childpidsize; i++) 
      {
      if (svr_ses.childpids[i].chansess == chansess) 
        {
        if (svr_ses.childpids[i].pid <= 0)
          KOUT(" ");
        svr_ses.childpids[i].pid = -1;
        svr_ses.childpids[i].chansess = NULL;
        }
      }
    memset(chansess, 0, sizeof(struct ChanSess));
    m_free(chansess);
    }
}

/* Handle requests for a channel. These can be execution requests,
 * or x11/authagent forwarding. These are passed to appropriate handlers */
static void chansessionrequest(struct Channel *channel) {

	char *type = NULL;
	unsigned int typelen;
	unsigned char wantreply;
	int ret = 1;
	struct ChanSess *chansess;

	type = buf_getstring(ses.payload, &typelen);
	wantreply = buf_getbool(ses.payload);

	if (typelen > MAX_NAME_LEN) {
		KERR("leave chansessionrequest: type too long");
		goto out;
	}

	chansess = (struct ChanSess*)channel->typedata;
if (chansess == NULL)
KOUT(" ");

	if (strcmp(type, "window-change") == 0) {
		ret = sessionwinchange(chansess);
	} else if (strcmp(type, "shell") == 0) {
		ret = sessioncommand(channel, chansess, 0, 0);
	} else if (strcmp(type, "pty-req") == 0) {
        	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
          		KOUT("signal() error");
	 	ret = sessionpty(chansess);
        	svr_sigchild_initialise();
	} else if (strcmp(type, "exec") == 0) {
		ret = sessioncommand(channel, chansess, 1, 0);
	} else if (strcmp(type, "subsystem") == 0) {
		ret = sessioncommand(channel, chansess, 1, 1);
	} else if (strcmp(type, "signal") == 0) {
		ret = sessionsignal(chansess);
	} else {
		/* etc, todo "env", "subsystem" */
	}

out:

	if (wantreply) {
		if (ret == DROPBEAR_SUCCESS) {
			send_msg_channel_success(channel);
		} else {
			send_msg_channel_failure(channel);
		}
	}

	m_free(type);
}


/* Send a signal to a session's process as requested by the client*/
static int sessionsignal(struct ChanSess *chansess) {

	int sig = 0;
	char *signame = NULL;
	int i;

	if (chansess->pid == 0) {
		/* haven't got a process pid yet */
                KERR(" ");
		return DROPBEAR_FAILURE;
	}

	signame = buf_getstring(ses.payload, NULL);

	i = 0;
	while (signames[i].name != 0) {
		if (strcmp(signames[i].name, signame) == 0) {
			sig = signames[i].signal;
			break;
		}
		i++;
	}

	m_free(signame);

	if (sig == 0) {
		/* failed */
                KERR(" ");
		return DROPBEAR_FAILURE;
	}
			
	if (kill(chansess->pid, sig) < 0) {
                KERR(" ");
		return DROPBEAR_FAILURE;
	} 

	return DROPBEAR_SUCCESS;
}

/* Let the process know that the window size has changed, as notified from the
 * client. Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int sessionwinchange(struct ChanSess *chansess) {

	int termc, termr, termw, termh;

	if (chansess->master < 0) {
		/* haven't got a pty yet */
                KERR(" ");
		return DROPBEAR_FAILURE;
	}
			
	termc = buf_getint(ses.payload);
	termr = buf_getint(ses.payload);
	termw = buf_getint(ses.payload);
	termh = buf_getint(ses.payload);
	
	pty_change_window_size(chansess->master, termr, termc, termw, termh);

	return DROPBEAR_SUCCESS;
}

static void get_termmodes(struct ChanSess *chansess) {

	struct termios termio;
	unsigned char opcode;
	unsigned int value;
	const struct TermCode * termcode;
	unsigned int len;
	/* Term modes */
	/* We'll ignore errors and continue if we can't set modes.
	 * We're ignoring baud rates since they seem evil */
	if (tcgetattr(chansess->master, &termio) == -1) {
		return;
	}

	len = buf_getint(ses.payload);
	if (len != ses.payload->len - ses.payload->pos) {
	KERR("ERROR %d %d %d", len, ses.payload->len, ses.payload->pos);
	}

	if (len == 0) {
		KERR("leave get_termmodes: empty terminal modes string");
		return;
	}

	while (((opcode = buf_getbyte(ses.payload)) != 0x00) && opcode <= 159) {

		/* must be before checking type, so that value is consumed even if
		 * we don't use it */
		value = buf_getint(ses.payload);

		/* handle types of code */
		if (opcode > MAX_TERMCODE) {
			continue;
		}
		termcode = &termcodes[(unsigned int)opcode];
		

		switch (termcode->type) {

			case TERMCODE_NONE:
				break;

			case TERMCODE_CONTROLCHAR:
				termio.c_cc[termcode->mapcode] = value;
				break;

			case TERMCODE_INPUT:
				if (value) {
					termio.c_iflag |= termcode->mapcode;
				} else {
					termio.c_iflag &= ~(termcode->mapcode);
				}
				break;

			case TERMCODE_OUTPUT:
				if (value) {
					termio.c_oflag |= termcode->mapcode;
				} else {
					termio.c_oflag &= ~(termcode->mapcode);
				}
				break;

			case TERMCODE_LOCAL:
				if (value) {
					termio.c_lflag |= termcode->mapcode;
				} else {
					termio.c_lflag &= ~(termcode->mapcode);
				}
				break;

			case TERMCODE_CONTROL:
				if (value) {
					termio.c_cflag |= termcode->mapcode;
				} else {
					termio.c_cflag &= ~(termcode->mapcode);
				}
				break;
				
		}
	}
	if (tcsetattr(chansess->master, TCSANOW, &termio) < 0) {
		KERR("Error setting terminal attributes");
	}
}

        
void cloonix_serv_xauth_cookie_key(char *display, char *cookie_key);

/* Set up a session pty which will be used to execute the shell or program.
 * The pty is allocated now, and kept for when the shell/program executes.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int sessionpty(struct ChanSess * chansess) {
	unsigned int len;
	unsigned char namebuf[65];
        chansess->cloonix_name = buf_getstring(ses.payload, &len);
        chansess->cloonix_display = buf_getstring(ses.payload, &len);
        chansess->cloonix_xauth_cookie_key = buf_getstring(ses.payload, &len);
	if (chansess->master != -1) {
		KOUT("Multiple pty requests");
	}
	if (pty_allocate(&chansess->master, &chansess->slave, namebuf, 64) == 0) {
		KERR("leave sessionpty: failed to allocate pty");
		return DROPBEAR_FAILURE;
	}
	chansess->tty = (char*)m_strdup(namebuf);
	if (!chansess->tty) {
		KOUT("Out of memory");
	}
	sessionwinchange(chansess);
	get_termmodes(chansess);
	return DROPBEAR_SUCCESS;
}


/* Handle a command request from the client. This is used for both shell
 * and command-execution requests, and passes the command to
 * noptycommand or ptycommand as appropriate.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int sessioncommand(struct Channel *channel, struct ChanSess *chansess,
		int iscmd, int issubsys) {

	unsigned int cmdlen;
	int ret;
	if (chansess->cmd != NULL) {
		/* Note that only one command can _succeed_. The client might try
		 * one command (which fails), then try another. Ie fallback
		 * from sftp to scp */
                KERR(" ");
		return DROPBEAR_FAILURE;
	}

	if (iscmd) {
		/* "exec" */
		if (chansess->cmd == NULL) {
			chansess->cmd = buf_getstring(ses.payload, &cmdlen);

			if (cmdlen > MAX_CMD_LEN) {
				m_free(chansess->cmd);
                                KERR("%d %d", cmdlen, MAX_CMD_LEN);
				return DROPBEAR_FAILURE;
			}
		}
		if (issubsys) {
			{
				m_free(chansess->cmd);
                                KERR(" ");
				return DROPBEAR_FAILURE;
			}
		}
	}
	
	if (chansess->tty == NULL) {
		ret = noptycommand(channel, chansess);
	} else {
		ret = ptycommand(channel, chansess);
	}

	if (ret == DROPBEAR_FAILURE) {
                KERR(" ");
		m_free(chansess->cmd);
	}
	return ret;
}

/* Execute a command and set up redirection of stdin/stdout/stderr without a
 * pty.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int noptycommand(struct Channel *channel, struct ChanSess *chansess) {
	int ret;
	ret = spawn_command(chansess, &channel->writefd, &channel->readfd, 
                            &channel->errfd, &chansess->pid);

	if (ret == DROPBEAR_FAILURE) {
                KERR(" ");
		return ret;
	}

	ses.maxfd = MAX(ses.maxfd, channel->writefd);
	ses.maxfd = MAX(ses.maxfd, channel->readfd);
	ses.maxfd = MAX(ses.maxfd, channel->errfd);

	addchildpid(chansess, chansess->pid);

	if (svr_ses.lastexit.exitpid != -1) {
		unsigned int i;
		KERR("parent side: lastexitpid is %d", 
                     svr_ses.lastexit.exitpid);
		/* The child probably exited and the signal handler triggered
		 * possibly before we got around to adding the childpid. So we fill
		 * out its data manually */
		for (i = 0; i < svr_ses.childpidsize; i++) {
			if (svr_ses.childpids[i].pid == svr_ses.lastexit.exitpid) {
				KERR("found match for lastexitpid");
				svr_ses.childpids[i].chansess->exit = svr_ses.lastexit;
				svr_ses.lastexit.exitpid = -1;
				break;
			}
		}
	}
	return DROPBEAR_SUCCESS;
}

/* Execute a command or shell within a pty environment, and set up
 * redirection as appropriate.
 * Returns DROPBEAR_SUCCESS or DROPBEAR_FAILURE */
static int ptycommand(struct Channel *channel, struct ChanSess *chansess) 
{
  pid_t pid;
  int result = DROPBEAR_FAILURE;
  if (chansess->master == -1 || chansess->tty == NULL) 
    {
    KERR("No pty was allocated, couldn't execute %d %p", 
         chansess->master, chansess->tty);
    }
  else
    {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    pid = fork();
    if (pid < 0)
      KERR("Bad fork");
    else if (pid == 0)
      {
      prctl(PR_SET_PDEATHSIG, SIGKILL);
      close(chansess->master);
      pty_make_controlling_tty(&chansess->slave, chansess->tty);
      if ((chansess->cloonix_xauth_cookie_key) && (chansess->cloonix_display))
        {
        if (strcmp(chansess->cloonix_xauth_cookie_key, "NO_X11_FORWARDING_COOKIE"))
          {
          if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
            KOUT("signal() error");
          cloonix_serv_xauth_cookie_key(chansess->cloonix_display,
                                        chansess->cloonix_xauth_cookie_key);
          svr_sigchild_initialise();
          }
        }
      if ((dup2(chansess->slave, STDIN_FILENO) < 0) ||
          (dup2(chansess->slave, STDERR_FILENO) < 0) ||
          (dup2(chansess->slave, STDOUT_FILENO) < 0)) 
        KERR("leave ptycommand: error redirecting filedesc");
      else
        {
        close(chansess->slave);
        execchild(chansess);
        result = DROPBEAR_SUCCESS;
        }
      } 
    else 
      {
      chansess->pid = pid;
      addchildpid(chansess, pid);
      channel->writefd = chansess->master;
      channel->readfd = chansess->master;
      ses.maxfd = MAX(ses.maxfd, chansess->master);
      setnonblocking(chansess->master);
      result = DROPBEAR_SUCCESS;
      }
    }
  return result;
}

/* Add the pid of a child to the list for exit-handling */
static void addchildpid(struct ChanSess *chansess, pid_t pid) {

	unsigned int i;
	for (i = 0; i < svr_ses.childpidsize; i++) {
		if (svr_ses.childpids[i].pid == -1) {
			break;
		}
	}

	/* need to increase size */
	if (i == svr_ses.childpidsize) {
		svr_ses.childpids = (struct ChildPid*)m_realloc(svr_ses.childpids,
				sizeof(struct ChildPid) * (svr_ses.childpidsize+1));
		svr_ses.childpidsize++;
	}
	
	svr_ses.childpids[i].pid = pid;
	svr_ses.childpids[i].chansess = chansess;

}

/* Clean up, drop to user privileges, set up the environment and execute
 * the command/shell. This function does not return. */
static void execchild(struct ChanSess *chansess)
{
  char *usershell = NULL;
  char *login = NULL;
  char *pth="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
  if (chansess->i_run_in_kvm)
    {
    clearenv();
    addnewvar("PATH", pth); 
    addnewvar("USER", "root");
    addnewvar("HOME", "/root");
    addnewvar("TERM", "xterm");
    addnewvar("XAUTHORITY", "/root/.Xauthority");
    if (chansess->cloonix_name)
      addnewvar("PROMPT_COMMAND", chansess->cloonix_name);
    if (chansess->cloonix_display)
      addnewvar("DISPLAY", chansess->cloonix_display);
    if (chdir("/root") < 0)
      KOUT("Error changing directory");
    if (!access("/bin/login", X_OK))
      {
      if (access("/etc/coreos", F_OK))
        login = m_strdup("/bin/login");
      }
    }
  else
    {
    addnewvar("USER", getenv("USER"));
    addnewvar("HOME", getenv("HOME"));
    unsetenv("PATH");
    addnewvar("PATH", pth); 
    addnewvar("TERM", "xterm");
    if (chansess->cloonix_display)
      addnewvar("DISPLAY", chansess->cloonix_display);
    }
  if (chansess->tty)
    addnewvar("SSH_TTY", chansess->tty);

  if (!access("/bin/bash", X_OK))
    {
    addnewvar("SHELL", "/bin/bash");
    usershell = m_strdup("/bin/bash");
    }
  else if (!access("/bin/ash", X_OK))
    {
    addnewvar("SHELL", "/bin/ash");
    usershell = m_strdup("/bin/ash");
    }
  else
    {
    addnewvar("SHELL", "/bin/sh");
    usershell = m_strdup("/bin/sh");
    }
  run_shell_command(chansess->cmd, ses.maxfd, usershell, login);
}




/* Set up the general chansession environment, in particular child-exit
 * handling */
void svr_chansessinitialise() {

	/* single child process intially */
	svr_ses.childpids = (struct ChildPid*)m_malloc(sizeof(struct ChildPid));
	svr_ses.childpids[0].pid = -1; /* unused */
	svr_ses.childpids[0].chansess = NULL;
	svr_ses.childpidsize = 1;
	svr_ses.lastexit.exitpid = -1; /* Nothing has exited yet */
        svr_sigchild_initialise(); 
}

/* add a new environment variable, allocating space for the entry */
void addnewvar(const char* param, const char* var) {

	char* newvar = NULL;
	int plen, vlen;

	plen = strlen(param);
	vlen = strlen(var);

	newvar = m_malloc(plen + vlen + 2); /* 2 is for '=' and '\0' */
	memcpy(newvar, param, plen);
	newvar[plen] = '=';
	memcpy(&newvar[plen+1], var, vlen);
	newvar[plen+vlen+1] = '\0';
	/* newvar is leaked here, but that's part of putenv()'s semantics */
	if (putenv(newvar) < 0) {
		KOUT("environ error");
	}
}
