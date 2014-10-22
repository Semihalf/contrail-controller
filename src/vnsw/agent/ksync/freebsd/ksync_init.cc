/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include "vr_os.h"

#if 0
#include <io/event_manager.h>
#include <db/db_entry.h>
#include <db/db_table.h>
#include <db/db_table_partition.h>
#include <cmn/agent_cmn.h>
#include <ksync/ksync_index.h>
#include <ksync/ksync_entry.h>
#include <ksync/ksync_object.h>
#include <ksync/ksync_netlink.h>
#include <ksync/ksync_sock.h>

#include "ksync_init.h"
#include "ksync/interface_ksync.h"
#include "ksync/route_ksync.h"
#include "ksync/mirror_ksync.h"
#include "ksync/vrf_assign_ksync.h"
#include "ksync/vxlan_ksync.h"
#include "ksync/sandesh_ksync.h"
#include "nl_util.h"
#include "vhost.h"
#include "vr_message.h"
#endif
#include "ksync_init.h"

void KSyncFreeBSD::CreateVhostIntf() {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_UP;

    int s = socket(PF_LOCAL, SOCK_DGRAM, 0);
    assert(s > 0);

    strncpy(ifr.ifr_name, agent_->vhost_interface_name().c_str(),
        sizeof(ifr.ifr_name));

    assert(ioctl(s, SIOCSIFFLAGS, &ifr) != -1);
    close(s);
}

void KSyncFreeBSD::UpdateVhostMac() {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    int s = socket(PF_LOCAL, SOCK_DGRAM, 0);
    assert(s >= 0);

    strncpy(ifr.ifr_name, agent_->vhost_interface_name().c_str(),
            sizeof(ifr.ifr_name));

    PhysicalInterfaceKey key(agent_->fabric_interface_name());
    Interface *eth = static_cast<Interface *>
        (agent_->interface_table()->FindActiveEntry(&key));
    ifr.ifr_addr = eth->mac();

    ifr.ifr_addr.sa_len = eth->mac().size();

    assert(ioctl(s, SIOCSIFLLADDR, &ifr) != -1);

    close(s);
}

