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
#define TOPO_MAX_NAME_LEN 4
/*---------------------------------------------------------------------------*/
typedef struct t_subelem
{
  char name[TOPO_MAX_NAME_LEN];
  struct t_subelem *next;
} t_subelem;
/*---------------------------------------------------------------------------*/
typedef struct t_subsets
{
  t_subelem *subelem;
  struct t_subsets *next;
} t_subsets;
/*---------------------------------------------------------------------------*/
void sub_init(int max_nodes, int max_neigh);
void sub_mak_link(char *a, char *b);
void sub_breakdown(void);
t_subsets *get_subsets(void);
void free_subsets(void);
/*---------------------------------------------------------------------------*/






