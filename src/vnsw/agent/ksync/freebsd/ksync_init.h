/*
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef freebsd_vnsw_agent_ksync_init_h
#define freebsd_vnsw_agent_ksync_init_h

#include <ksync/flowtable_ksync.h>
#include <ksync/mpls_ksync.h>
#include <ksync/nexthop_ksync.h>
#include <ksync/mirror_ksync.h>
#include <ksync/route_ksync.h>
#include <ksync/vxlan_ksync.h>
#include <ksync/vrf_assign_ksync.h>
#include <ksync/interface_scan.h>
#include "ksync/ksync_init_base.h"

class KSyncFreeBSD : public KSyncBase {
public:
    KSyncFreeBSD(Agent *agent) : KSyncBase(agent) {
    }
    virtual void UpdateVhostMac();
    virtual void CreateVhostIntf();
    DISALLOW_COPY_AND_ASSIGN(KSyncFreeBSD);
};

typedef KSyncFreeBSD KSync;

#endif //freebsd_vnsw_agent_ksync_init_h
