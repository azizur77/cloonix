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
#define MAX_CLOWNIX_BOUND_LEN      64
#define MIN_CLOWNIX_BOUND_LEN      2


/*---------------------------------------------------------------------------*/
#define HOP_GET_LIST_NAME    "<hop_get_list_name>\n"\
                             "  <tid> %d </tid>\n"\
                             "</hop_get_list_name>"
/*---------------------------------------------------------------------------*/
#define HOP_LIST_NAME_O  "<hop_list_name>\n"\
                         "<tid> %d </tid>\n"\
                         "<nb_items> %d </nb_items>\n"

#define HOP_LIST_NAME_I  "<hop_type_item> %d </hop_type_item>\n"\
                         "<hop_name_item> %s </hop_name_item>\n"\
                         "<hop_eth_item> %d </hop_eth_item>\n"

#define HOP_LIST_NAME_C \
                          "</hop_list_name>"
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
#define HOP_EVT_DOORS_O "<hop_evt_doors>\n"\
                        "  <tid> %d </tid>\n"\
                        "  <flags_hop> %d </flags_hop>\n"\
                        "  <name> %s </name>\n"\

#define HOP_EVT_DOORS_C "</hop_evt_doors>"
/*---------------------------------------------------------------------------*/
#define HOP_EVT_DOORS_SUB_O  "<hop_evt_doors_sub>\n"\
                             "  <tid> %d </tid>\n"\
                             "  <flags_hop> %d </flags_hop>\n"\
                             "  <nb_items> %d </nb_items>\n"

#define HOP_EVT_DOORS_SUB_C \
                          "</hop_evt_doors_sub>"
/*---------------------------------------------------------------------------*/
#define HOP_EVT_DOORS_UNSUB "<hop_evt_doors_unsub>\n"\
                            "  <tid> %d </tid>\n"\
                            "</hop_evt_doors_unsub>"
/*---------------------------------------------------------------------------*/



/*---------------------------------------------------------------------------*/
#define STATUS_OK        "<ok>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <txt> %s </txt>\n"\
                         "</ok>"
#define STATUS_KO        "<ko>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <txt> %s </txt>\n"\
                         "</ko>"
/*---------------------------------------------------------------------------*/
#define MUCLI_DIALOG_REQ_O "<mucli_req_dialog>\n"\
                           "  <tid> %d </tid>\n"\
                           "  <name> %s </name>\n"\
                           "  <eth> %d </eth>\n"

#define MUCLI_DIALOG_REQ_I "  <mucli_dialog_req_bound>%s</mucli_dialog_req_bound>\n"

#define MUCLI_DIALOG_REQ_C "</mucli_req_dialog>"
/*---------------------------------------------------------------------------*/
#define MUCLI_DIALOG_RESP_O "<mucli_resp_dialog>\n"\
                            "  <tid> %d </tid>\n"\
                            "  <name> %s </name>\n"\
                            "  <eth> %d </eth>\n"\
                            "  <status> %d </status>\n"

#define MUCLI_DIALOG_RESP_I "  <mucli_dialog_resp_bound>%s</mucli_dialog_resp_bound>\n"

#define MUCLI_DIALOG_RESP_C "</mucli_resp_dialog>"
/*---------------------------------------------------------------------------*/
#define WORK_DIR_REQ     "<work_dir_req>\n"\
                         "  <tid> %d </tid>\n"\
                         "</work_dir_req>"

#define WORK_DIR_RESP    "<work_dir_resp>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <version> %s </version>\n"\
                         "  <network_name> %s </network_name>\n"\
                         "  <username> %s </username>\n"\
                         "  <server_port> %d </server_port>\n"\
                         "  <work_dir> %s </work_dir>\n"\
                         "  <bulk_dir> %s </bulk_dir>\n"\
                         "  <bin_dir> %s </bin_dir>\n"\
                         "  <flags> %d </flags>\n"\
                         "</work_dir_resp>"
/*---------------------------------------------------------------------------*/
#define EVENTFULL_SUB    "<eventfull_sub>\n"\
                         "  <tid> %d </tid>\n"\
                         "</eventfull_sub>"
/*---------------------------------------------------------------------------*/
#define EVENTFULL_SAT    "<eventfull_sat>\n"\
                         "  <name> %s </name>\n"\
                         "  <sat_is_ok> %d </sat_is_ok>\n"\
                         "  <pkt_rx0> %d </pkt_rx0>\n"\
                         "  <pkt_tx0> %d </pkt_tx0>\n"\
                         "  <pkt_rx1> %d </pkt_rx1>\n"\
                         "  <pkt_tx1> %d </pkt_tx1>\n"\
                         "</eventfull_sat>"

#define EVENTFULL_ETH    "<eventfull_eth>\n"\
                         "  <eth> %d </eth>\n"\
                         "  <pkt_rx> %d </pkt_rx>\n"\
                         "  <pkt_tx> %d </pkt_tx>\n"\
                         "</eventfull_eth>"

#define EVENTFULL_VM_O   "<eventfull_vm>\n"\
                         "  <name> %s </name>\n"\
                         "  <ram> %d </ram>\n"\
                         "  <cpu> %d </cpu>\n"\
                         "  <nb_eth> %d </nb_eth>\n"

#define EVENTFULL_VM_C   "</eventfull_vm>"


#define EVENTFULL_O      "<eventfull>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <nb_vm> %d </nb_vm>\n"\
                         "  <nb_sat> %d </nb_sat>\n"

#define EVENTFULL_C \
                         "</eventfull>"
/*---------------------------------------------------------------------------*/
#define ADD_VM_O         "<add_vm>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <name> %s </name>\n"\
                         "  <vm_config_flags> %d </vm_config_flags>\n"\
                         "  <cpu> %d </cpu>\n"\
                         "  <mem> %d </mem>\n"\
                         "  <nb_eth> %d </nb_eth>"

#define ADD_VM_ETH_PARAMS "<eth_params>\n"\
                          "  <mac> %02X %02X %02X %02X %02X %02X </mac>\n"\
                          "  <is_promisc> %d </is_promisc>\n"\
                          "</eth_params>"

#define ADD_VM_C         "  <linux_kernel> %s </linux_kernel>\n"\
                         "  <rootfs_input> %s </rootfs_input>\n"\
                         "  <bdisk> %s </bdisk>\n"\
                         "  <p9_host_share> %s </p9_host_share>\n"\
                         "</add_vm>"

#define SAV_VM           "<sav_vm>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <name> %s </name>\n"\
                         "  <save_type> %d </save_type>\n"\
                         "  <sav_rootfs_path> %s </sav_rootfs_path>\n"\
                         "</sav_vm>"

#define SAV_VM_ALL       "<sav_vm_all>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <save_type> %d </save_type>\n"\
                         "  <sav_rootfs_path> %s </sav_rootfs_path>\n"\
                         "</sav_vm_all>"


#define EVT_ADD_ETH      "<add_eth>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <name> %s </name>\n"\
                         "  <eth> %d </eth>\n"\
                         "</add_eth>"


#define ADD_SAT          "<add_sat>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <name> %s </name>\n"\
                         "  <musat_type> %d </musat_type>\n"\
                         "  <c2c_slave> %s </c2c_slave>\n"\
                         "  <ip_slave> %d </ip_slave>\n"\
                         "  <port_slave> %d </port_slave>\n"\
                         "  <passwd_slave> %s </passwd_slave>\n"\
                         "</add_sat>"

#define DEL_SAT          "<del_sat>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <name> %s </name>\n"\
                         "</del_sat>"

#define ADD_LAN_SAT     "<add_lan_sat>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <name> %s </name>\n"\
                         "  <vl> %s </vl>\n"\
                         "  <num> %d </num>\n"\
                         "</add_lan_sat>"

#define DEL_LAN_SAT     "<del_lan_sat>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <name> %s </name>\n"\
                         "  <vl> %s </vl>\n"\
                         "  <num> %d </num>\n"\
                         "</del_lan_sat>"

/*---------------------------------------------------------------------------*/
#define KILL_UML_CLOWNIX      "<kill_uml_clownix>\n"\
                              "  <tid> %d </tid>\n"\
                              "</kill_uml_clownix>"

#define DEL_ALL               "<del_all>\n"\
                              "  <tid> %d </tid>\n"\
                              "</del_all>"
/*---------------------------------------------------------------------------*/
#define LIST_PID              "<list_pid_req>\n"\
                              "  <tid> %d </tid>\n"\
                              "</list_pid_req>"

#define LIST_PID_O            "<list_pid_resp>\n"\
                              "  <tid> %d </tid>\n"\
                              "  <qty> %d </qty>\n"
#define LIST_PID_ITEM         "  <pid> %s %d </pid>\n"
#define LIST_PID_C \
                              "</list_pid_resp>"
/*---------------------------------------------------------------------------*/
#define LIST_COMMANDS         "<list_commands_req>\n"\
                              "  <tid> %d </tid>\n"\
                              "</list_commands_req>"
/*---------------------------------------------------------------------------*/
#define LIST_COMMANDS_O       "<list_commands_resp>\n"\
                              "  <tid> %d </tid>\n"\
                              "  <qty> %d </qty>\n"
#define LIST_COMMANDS_ITEM    "<item_list_command_delimiter>%s</item_list_command_delimiter>\n"

#define LIST_COMMANDS_C       "</list_commands_resp>"
/*---------------------------------------------------------------------------*/
#define EVENT_PRINT_SUB       "<event_print_sub>\n"\
                              "  <tid> %d </tid>\n"\
                              "</event_print_sub>"

#define EVENT_PRINT_UNSUB     "<event_print_unsub>\n"\
                              "  <tid> %d </tid>\n"\
                              "</event_print_unsub>"

#define EVENT_PRINT           "<event_print>\n"\
                              "  <tid> %d </tid>\n"\
                              "  <txt> %s </txt>\n"\
                              "</event_print>"
/*---------------------------------------------------------------------------*/
#define EVENT_SYS_SUB         "<event_sys_sub>\n"\
                              "  <tid> %d </tid>\n"\
                              "</event_sys_sub>"

#define EVENT_SYS_UNSUB       "<event_sys_unsub>\n"\
                              "  <tid> %d </tid>\n"\
                              "</event_sys_unsub>"
/*---------------------------------------------------------------------------*/
#define EVENT_SYS_ITEM_Q      "<Qtx>\n"\
                              "  <peak_size> %d </peak_size>\n"\
                              "  <size> %d </size>\n"\
                              "  <llid> %d </llid>\n"\
                              "  <qfd> %d </qfd>\n"\
                              "  <waked_in> %d </waked_in>\n"\
                              "  <waked_out> %d </waked_out>\n"\
                              "  <waked_err> %d </waked_err>\n"\
                              "  <out> %d </out>\n"\
                              "  <in> %d </in>\n"\
                              "  <name> %s </name>\n"\
                              "  <id> %d </id>\n"\
                              "  <type> %d </type>\n"\
                              "</Qtx>"
/*---------------------------------------------------------------------------*/
#define EVENT_SYS_O           "<system_info>\n"\
                              "  <tid> %d </tid>\n"\
                              "  <nb_mallocs> %d </nb_mallocs>\n"

#define EVENT_SYS_M   "<m> %lu </m>\n" 
 
#define EVENT_SYS_FN  "<nb_fds_used> %d </nb_fds_used>\n"
#define EVENT_SYS_FU  "<fd> %lu </fd>\n" 

#define EVENT_SYS_R   "<r> selects: %d \n"\
                      "cur_channels: %d max_channels: %d \n"\
                      "channels_recv: %d  channels_send: %d \n"\
                      "clients: %d\n"\
                      "max_time:%d avg_time: %d above50ms: %d \n"\
                      "above20ms: %d above15ms: %d \n"\
                      "nb_Q_not_empty: %d </r>\n"

#define EVENT_SYS_C \
                      "</system_info>"
/*---------------------------------------------------------------------------*/
#define BLKD_REPORTS_SUB "<blkd_reports_sub>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <sub> %d </sub>\n"\
                         "</blkd_reports_sub>"

#define BLKD_REPORTS_O "<blkd_reports>\n"\
                       "  <tid> %d </tid>\n"\
                       "  <nb_reports> %d </nb_reports>\n"


#define BLKD_REPORTS_C "</blkd_reports>"
/*---------------------------------------------------------------------------*/
#define TOPO_SMALL_EVENT_SUB      "<topo_small_event_sub>\n"\
                              "  <tid> %d </tid>\n"\
                              "</topo_small_event_sub>"

#define TOPO_SMALL_EVENT_UNSUB    "<topo_small_event_unsub>\n"\
                              "  <tid> %d </tid>\n"\
                              "</topo_small_event_unsub>"

#define TOPO_SMALL_EVENT          "<topo_small_event>\n"\
                              "  <tid> %d </tid>\n"\
                              "  <name> %s </name>\n"\
                              "  <param1> %s </param1>\n"\
                              "  <param2> %s </param2>\n"\
                              "  <evt> %d </evt>\n"\
                              "</topo_small_event>"

/*---------------------------------------------------------------------------*/
#define EVENT_TOPO_SUB        "<event_topo_sub>\n"\
                              "  <tid> %d </tid>\n"\
                              "</event_topo_sub>"

#define EVENT_TOPO_UNSUB      "<event_topo_unsub>\n"\
                              "  <tid> %d </tid>\n"\
                              "</event_topo_unsub>"

#define EVENT_TOPO_O          "<event_topo>\n"\
                              "  <tid> %d </tid>\n"\
                              "  <network_name> %s </network_name>\n"\
                              "  <username> %s </username>\n"\
                              "  <server_port> %d </server_port>\n"\
                              "  <work_dir> %s </work_dir>\n"\
                              "  <bulk_dir> %s </bulk_dir>\n"\
                              "  <bin_dir> %s </bin_dir>\n"\
                              "  <nb_vm> %d </nb_vm> \n"\
                              "  <nb_sat> %d </nb_sat>\n"

#define TOPO_VM_O        "  <vm>\n"\
                         "    name: %s \n"\
                         "    bdisk: %s \n"\
                         "    p9_host_share: %s \n"\
                         "    linux_kernel: %s \n"\
                         "    rootfs_used: %s \n"\
                         "    rootfs_backing: %s \n"\
                         "    vm_id: %d vm_config_flags: %d \n"\
                         "    nb_eth: %d mem: %d cpu: %d \n"
                        

#define TOPO_LAN        "      <lan> %s </lan>\n"

#define TOPO_ALAN        "      <alan> %s </alan>\n"

#define TOPO_BLAN        "      <blan> %s </blan>\n"

#define TOPO_ETH_O       "      <eth_infos>\n"\
                         "      id: %d nb_lan: %d \n"

#define TOPO_ETH_C       " </eth_infos>\n"

#define TOPO_VM_C        "  </vm>\n"

#define TOPO_SAT_O       "  <sat>\n"\
                         "    name: %s \n"\
                         "    <musat_type> %d </musat_type>\n"\
                         "    recpath: %s capture_on: %d \n"\
                         "    master: %s slave: %s \n"\
                         "    local_is_master:%d peered: %d \n"\
                         "    ip_slave: %d port_slave: %d \n"\
                         "    nb_lan0: %d nb_lan1: %d\n"

#define TOPO_SAT_C       "  </sat>\n"


#define EVENT_TOPO_C \
                      "</event_topo>"
/*---------------------------------------------------------------------------*/
#define EVENT_SPY_SUB          "<event_spy_sub> \n"\
                               "  <tid> %d </tid>\n"\
                               "  <nm>  %s </nm> \n"\
                               "  <if>  %s </if> \n"\
                               "  <dir> %s </dir> \n"\
                               "</event_spy_sub>"

#define EVENT_SPY_UNSUB        "<event_spy_unsub> \n"\
                               "  <tid> %d </tid>\n"\
                               "  <nm>  %s </nm> \n"\
                               "  <if>  %s </if> \n"\
                               "  <dir> %s </dir> \n"\
                               "</event_spy_unsub>"

#define EVENT_SPY_O           "<event_spy> \n"\
                              "  <tid> %d </tid>\n"\
                              "  <nm>  %s </nm> \n"\
                              "  <if>  %s </if> \n"\
                              "  <dir> %s </dir> \n"\
                              "  <secs>  %d </secs> \n"\
                              "  <usecs>  %d </usecs> \n"\
                              "  <qty> %d </qty> \n"\
                              "  <msg>"
#define EVENT_SPY_C           "</msg>\n"\
                              "</event_spy>"
/*---------------------------------------------------------------------------*/
#define VMCMD            "<vmcmd>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <name> %s </name>\n"\
                         "  <cmd> %d </cmd>\n"\
                         "  <param> %d </param>\n"\
                         "</vmcmd>"
/*---------------------------------------------------------------------------*/
#define SUB_EVT_STATS_ETH "<sub_evt_stats_eth>\n"\
                          "  <tid> %d </tid>\n"\
                          "  <name> %s </name>\n"\
                          "  <eth> %d </eth>\n"\
                          "  <sub_on> %d </sub_on>\n"\
                          "</sub_evt_stats_eth>\n"
/*---------------------------------------------------------------------------*/
#define EVT_STATS_TX_ITEM   "<tx_item>\n"\
                            "  ms: %d p: %d b: %d \n"\
                            "</tx_item>"
/*---------------------------------------------------------------------------*/
#define EVT_STATS_RX_ITEM   "<rx_item>\n"\
                            "  ms: %d p: %d b: %d \n"\
                            "</rx_item>"
/*---------------------------------------------------------------------------*/
#define EVT_STATS_ETH_O  "<evt_stats_eth>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <network_name> %s </network_name>\n"\
                         "  <name> %s </name>\n"\
                         "  <eth> %d </eth>\n"\
                         "  <status> %d </status>\n"\
                         "  <nb_tx_items> %d </nb_tx_items>\n"\
                         "  <nb_rx_items> %d </nb_rx_items>\n"
/*---------------------------------------------------------------------------*/
#define EVT_STATS_ETH_C  "</evt_stats_eth>\n"\
/*---------------------------------------------------------------------------*/
#define SUB_EVT_STATS_SAT "<sub_evt_stats_sat>\n"\
                          "  <tid> %d </tid>\n"\
                          "  <name> %s </name>\n"\
                          "  <sub_on> %d </sub_on>\n"\
                          "</sub_evt_stats_sat>\n"
/*---------------------------------------------------------------------------*/
#define EVT_STATS_SAT_O  "<evt_stats_sat>\n"\
                         "  <tid> %d </tid>\n"\
                         "  <network_name> %s </network_name>\n"\
                         "  <name> %s </name>\n"\
                         "  <status> %d </status>\n"\
                         "  <nb_tx_items> %d </nb_tx_items>\n"\
                         "  <nb_rx_items> %d </nb_rx_items>\n"
/*---------------------------------------------------------------------------*/
#define EVT_STATS_SAT_C  "</evt_stats_sat>"
/*---------------------------------------------------------------------------*/
#define SUB_EVT_STATS_SYSINFO "<sub_evt_stats_sysinfo>\n"\
                              "  <tid> %d </tid>\n"\
                              "  <name> %s </name>\n"\
                              "  <sub_on> %d </sub_on>\n"\
                              "</sub_evt_stats_sysinfo>\n"
/*---------------------------------------------------------------------------*/
#define EVT_STATS_SYSINFOO "<evt_stats_sysinfo>\n"\
                           "  <tid> %d </tid>\n"\
                           "  <network_name> %s </network_name>\n"\
                           "  <name> %s </name>\n"\
                           "  <status> %d </status>\n"\
                           "  time_ms: %d uptime: %lu \n"\
                           "  load1: %lu load5: %lu load15: %lu \n"\
                           "  totalram: %lu freeram: %lu \n"\
                           "  cachedram: %lu sharedram: %lu bufferram: %lu \n"\
                           "  totalswap: %lu freeswap: %lu procs: %lu \n"\
                           "  totalhigh: %lu freehigh: %lu mem_unit: %lu \n"\
                           "  process_utime: %lu process_stime: %lu \n"\
                           "  process_cutime: %lu process_cstime: %lu \n"\
                           "  process_rss: %lu \n"


#define EVT_STATS_SYSINFOC "</evt_stats_sysinfo>\n"
/*---------------------------------------------------------------------------*/






