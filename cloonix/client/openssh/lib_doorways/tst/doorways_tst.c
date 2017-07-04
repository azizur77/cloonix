/*****************************************************************************/
/*    Copyright (C) 2006-2017 cloonix@cloonix.net License AGPL-3             */
/*                                                                           */
/*  This program is free software: you can redistribute it and/or modify     */
/*  it under the terms of the GNU Affero General Public License as           */
/*  published by the Free Software Foundation, either version 3 of the       */
/*  License, or (at your option) any later version.                          */
/*                                                                           */
/*  This program is distributed in the hope that it will be useful,          */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of           */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            */
/*  GNU Affero General Public License for more details.a                     */
/*                                                                           */
/*  You should have received a copy of the GNU Affero General Public License */
/*  along with this program.  If not, see <http://www.gnu.org/licenses/>.    */
/*                                                                           */
/*****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include "lib_doorways.h"


/*****************************************************************************/
static void usage(char *name)
{
  printf("%s\n", name);
  printf("?\n");
  exit (0);
}
/*---------------------------------------------------------------------------*/


/*****************************************************************************/
int main (int argc, char *argv[])
{
  int ip, port;
  char *full_bin = get_full_bin_path(argv[0]);
  if (argc != 3)
    {
    fprintf(stderr, "Bad param number: %d\n", argc);
    usage(argv[0]);
    }
  if (get_ip_port_from_path(argv[1], &ip, &port))
    {
    fprintf(stderr, "Bad doorways address: %s\n", argv[1]);
    usage(argv[0]);
    }
  fprintf(stdout, "Full path: %s\n", full_bin);
  doorways_init(argv[1], argv[2]);
  doorways_loop();
  return 0;
}
/*--------------------------------------------------------------------------*/


