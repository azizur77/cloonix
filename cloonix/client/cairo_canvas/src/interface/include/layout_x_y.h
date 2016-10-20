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
void set_node_layout_x_y(char *name, int color_choice,
                         double x, double y, int hidden_on_graph, 
                         double *tx, double *ty,
                         int *thidden_on_graph);
/*---------------------------------------------------------------------------*/
void get_node_layout_x_y(char *name, int *color_choice, 
                         double *x, double *y, int *hidden_on_graph, 
                         double *tx, double *ty,
                         int *thidden_on_graph);
/*---------------------------------------------------------------------------*/
void set_gene_layout_x_y(int bank_type, char *name, int mutype, 
                         double x, double y, 
                         double xa, double ya,
                         double xb, double yb,
                         int hidden_on_graph);
/*---------------------------------------------------------------------------*/
void get_gene_layout_x_y(int bank_type, char *name, int mutype, 
                         double *x, double *y, 
                         double *xa, double *ya,
                         double *xb, double *yb,
                         int *hidden_on_graph);
/****************************************************************************/












