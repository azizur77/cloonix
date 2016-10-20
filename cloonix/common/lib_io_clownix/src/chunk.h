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
void chain_delete(t_data_chunk **start, t_data_chunk **last);
int make_a_buf_copy(t_data_chunk *first, int bound_start_offset,
                           char **buf_copy);
int chain_get_prev_len(t_data_chunk *start, int bound_start_offset);
void chain_del(t_data_chunk **start, t_data_chunk *last);
void chain_pop(t_data_chunk **start);
void chain_append(t_data_chunk **start, int len, char *nrx);
t_data_chunk *chain_get_last_chunk(t_data_chunk *start);
void push_done_limit(t_data_chunk *first, t_data_chunk *target);
void chain_append_tx(t_data_chunk **start, t_data_chunk **last,
                         int len, char *nrx);
void first_elem_delete(t_data_chunk **start, t_data_chunk **last);








