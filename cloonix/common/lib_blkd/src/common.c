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
#include <time.h>
#include <sys/syscall.h>


#include "ioc_top.h"

static char g_name[MAX_NAME_LEN];
static int g_start_off_second_offset;
static int g_pid;

/*****************************************************************************/
char *cloonix_get_short(const char *full_name)
{
  char *ptr = strrchr(full_name, '/');
  if (ptr != NULL)
    ptr += 1;
  else
    ptr = (char *) full_name;
  return ptr;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cloonix_set_sec_offset(int offset)
{
  g_start_off_second_offset = offset;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cloonix_get_sec_offset(void)
{
  return g_start_off_second_offset;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
unsigned int cloonix_get_msec(void)
{
  struct timespec ts;
  unsigned int result;
//  if (clock_gettime(CLOCK_MONOTONIC, &ts))
  if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC_COARSE, &ts))
    KOUT(" ");
  result = (unsigned int) (ts.tv_sec - g_start_off_second_offset);
  result *= 1000;
  result += ((unsigned int) ts.tv_nsec) / 1000000;
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
long long cloonix_get_usec(void)
{
  struct timespec ts;
  long long result;
//  if (clock_gettime(CLOCK_MONOTONIC, &ts))
  if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC_COARSE, &ts))
    KOUT(" ");
  result = (long long) (ts.tv_sec - g_start_off_second_offset);
  result *= 1000000;
  result += ts.tv_nsec / 1000;
  return result;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cloonix_set_pid(int pid)
{
  g_pid = pid;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
int cloonix_get_pid(void)
{
  return g_pid;
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
void cloonix_set_name(char *name)
{
  char *ptr;
  if (strlen(g_name))
    {
    /*QEMU_ETH_FORMAT*/
    memset(g_name, 0, MAX_NAME_LEN);
    strncpy(g_name, name, MAX_NAME_LEN-1);
    ptr = strrchr(g_name, '_'); 
    if (ptr)
      *ptr = 0;
    if (!strlen(g_name))
      {
      strcpy(g_name, "error_name");
      KERR(" ");
      }
    }
  else
    {
    memset(g_name, 0, MAX_NAME_LEN);
    strncpy(g_name, name, MAX_NAME_LEN-1);
    }
}
/*---------------------------------------------------------------------------*/

/*****************************************************************************/
char *cloonix_get_name(void)
{
  return g_name;
}
/*---------------------------------------------------------------------------*/

