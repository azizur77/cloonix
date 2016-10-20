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
int sock_unix_read (char *buf, int max, int fd);
/*--------------------------------------------------------------------------*/
int sock_unix_write(char *buf, int len, int fd, int *get_out);
/*--------------------------------------------------------------------------*/
int sock_client_unix(char *pname, int *fd);
/*--------------------------------------------------------------------------*/
int sock_listen_unix(char *pname);
/*--------------------------------------------------------------------------*/
void sock_unix_fd_accept(int fd_listen, int *fd);
/*---------------------------------------------------------------------------*/




