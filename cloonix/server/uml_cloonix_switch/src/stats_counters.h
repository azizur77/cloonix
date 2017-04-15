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
void stats_counters_update_tux_tx(t_tux *tux, unsigned int ms, 
                                  int num, int pkts, int bytes);
void stats_counters_update_eth_tx(t_eth *eth, unsigned int ms, 
                                  int pkts, int bytes);
void stats_counters_update_tux_rx(t_tux *tux, unsigned int ms, 
                                  int num, int pkts, int bytes);
void stats_counters_update_eth_rx(t_eth *eth, unsigned int ms, 
                                  int pkts, int bytes);
void stats_counters_heartbeat(void);
void stats_counters_vm_death(char *name);
void stats_counters_llid_close(int llid);
void stats_counters_sat_death(char *name);
void stats_counters_init(void);
