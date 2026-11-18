#include <string.h>
// Before dwc/ext.h: MWCC builds Think's copies of the servers' packets in place, as the ROM does, only when <string.h>
// declares memcpy
#include "dwc/NATify.h"
#include "dwc/ext.h"
#include "dwc/natneg.h"

// GameSpy's NAT detection (NATify.c). The ROM names neither the file nor its functions: the file, AddressToString,
// GetLocalIP, Think, NatifyThink and DetermineNatType are GameSpy's, as pret's pokerevo Wii build has them
// (NATify.s), and GetLocalPort, OutputMapping and the statics are named after the later SDK

static gsi_bool gotERT1;
static gsi_bool gotERT2;
static gsi_bool gotERT3;
static gsi_bool gotADDRESS1a;
static gsi_bool gotADDRESS1b;
static gsi_bool gotADDRESS2;
static gsi_bool gotADDRESS3;

static unsigned int GetLocalIP(void);
static unsigned short GetLocalPort(SOCKET sock);
static int Think(SOCKET sock, NAT *nat);

const char *AddressToString(unsigned int ip, unsigned short port, char string[22]) {
    static char strAddressArray[2][22];
    static int nIndex;
    char *strAddress;

    if (string != NULL) {
        strAddress = string;
    } else {
        nIndex ^= 1;
        strAddress = strAddressArray[nIndex];
    }
    if (ip != 0) {
        SOCInAddr inAddr;

        inAddr.addr = ip;
        if (port != 0) {
            OS_SPrintf(strAddress, "%s:%d", SOC_InetNtoA(inAddr), port);
        } else {
            OS_SPrintf(strAddress, "%s", SOC_InetNtoA(inAddr));
        }
    } else if (port != 0) {
        OS_SPrintf(strAddress, ":%d", port);
    } else {
        strAddress[0] = '\0';
    }
    return strAddress;
}

// The first address of the console that isn't the loopback one and is a private one, else the last one
static unsigned int GetLocalIP(void) {
    int i;
    HOSTENT *host;
    IN_ADDR *addr;
    gsi_u32 localIp = 0;

    host = getlocalhost();
    if (host == NULL) {
        return 0;
    }
    for (i = 0;; i++) {
        if (host->addrList[i] == NULL) {
            break;
        }
        addr = (IN_ADDR *)host->addrList[i];
        if (addr->addr == NN_SWAP32(0x7f000001)) {
            continue;
        }
        localIp = addr->addr;
        if (IsPrivateIP(addr)) {
            return localIp;
        }
    }
    return localIp;
}

// The port (in network order) that a socket is bound to, or 0
static unsigned short GetLocalPort(SOCKET sock) {
    SOCSockAddrIn address;
    int size = sizeof(SOCSockAddrIn);

    if (getsockname(sock, (SOCKADDR *)&address, &size) == -1) {
        return 0;
    }
    return address.port;
}

void OutputMapping(const AddressMapping *mapping) {
    if (mapping == NULL) {
        gsDebugFormat(GSIDebugCat_NatNeg, GSIDebugType_Network, GSIDebugLevel_Comment,
                      "ERROR: Port mapping not available.");
    } else {
        gsDebugFormat(GSIDebugCat_NatNeg, GSIDebugType_Network, GSIDebugLevel_Comment, "Discovered map: [%s] -> [%s]\n",
                      AddressToString(mapping->privateIp, mapping->privatePort, NULL),
                      AddressToString(mapping->publicIp, mapping->publicPort, NULL));
    }
}

static int Think(SOCKET sock, NAT *nat) {
    static char data[NNINBUF_LEN];
    int length;
    gsi_u8 type;
    NatNegPacket packet;
    SOCSockAddrIn from;
    int fromSize = sizeof(SOCSockAddrIn);

    if (gotERT1 && gotERT2 && gotERT3 && gotADDRESS1a && gotADDRESS1b && gotADDRESS2 && gotADDRESS3) {
        return gsi_false;
    }
    if (sock != -1) {
        while (CanReceiveOnSocket(sock)) {
            length = recvfrom(sock, data, sizeof(data), 0, (SOCKADDR *)&from, &fromSize);
            if (length == -1) {
                gsDebugFormat(GSIDebugCat_NatNeg, GSIDebugType_Network, GSIDebugLevel_Notice, "RECV SOCKET ERROR: %d\n",
                              GOAGetLastError(sock));
                break;
            }
            if (memcmp(data, NNMagicData, NATNEG_MAGIC_LEN) != 0) {
                return gsi_true;
            }
            type = data[BASEPACKET_TYPE_OFFSET];
            if (length < INITPACKET_SIZE) {
                return gsi_true;
            }
            if (type == NN_ERTTEST) {
                // The packet's fields after the port type are not aligned on the wire
                memcpy(&packet, data, INITPACKET_SIZE);
                memcpy(&packet.Packet.init.localip, &data[INITPACKET_ADDRESS_OFFSET], 4);
                memcpy(&packet.Packet.init.localport, &data[INITPACKET_ADDRESS_OFFSET + 4], 2);
                switch (packet.Packet.init.porttype) {
                case NN_PT_NN1:
                    gotERT1 = gsi_true;
                    gsDebugFormat(GSIDebugCat_NatNeg, GSIDebugType_Network, GSIDebugLevel_Comment,
                                  "(1) Got the solicited ERT from: %s\n",
                                  AddressToString(from.addr.addr, NN_SWAP16(from.port), NULL));
                    break;
                case NN_PT_NN2:
                    nat->ipRestricted = gsi_false;
                    gotERT2 = gsi_true;
                    gsDebugFormat(GSIDebugCat_NatNeg, GSIDebugType_Network, GSIDebugLevel_Comment,
                                  "(2) Got the unsolicited (address) ERT from: %s\n",
                                  AddressToString(from.addr.addr, NN_SWAP16(from.port), NULL));
                    break;
                case NN_PT_NN3:
                    nat->portRestricted = gsi_false;
                    gotERT3 = gsi_true;
                    gsDebugFormat(GSIDebugCat_NatNeg, GSIDebugType_Network, GSIDebugLevel_Comment,
                                  "(3) Got the unsolicited (port) ERT from: %s\n",
                                  AddressToString(from.addr.addr, NN_SWAP16(from.port), NULL));
                    break;
                }
            } else if (type == NN_ADDRESS_REPLY) {
                memcpy(&packet, data, INITPACKET_SIZE);
                memcpy(&packet.Packet.init.localip, &data[INITPACKET_ADDRESS_OFFSET], 4);
                memcpy(&packet.Packet.init.localport, &data[INITPACKET_ADDRESS_OFFSET + 4], 2);
                packet.cookie = NN_SWAP32(packet.cookie);
                switch (packet.cookie) {
                case packet_map1a:
                    gotADDRESS1a = gsi_true;
                    break;
                case packet_map1b:
                    gotADDRESS1b = gsi_true;
                    break;
                case packet_map2:
                    gotADDRESS2 = gsi_true;
                    break;
                case packet_map3:
                    gotADDRESS3 = gsi_true;
                    break;
                }
                nat->mappings[packet.cookie].privateIp = GetLocalIP();
                nat->mappings[packet.cookie].privatePort = NN_SWAP16(GetLocalPort(sock));
                nat->mappings[packet.cookie].publicIp = packet.Packet.init.localip;
                nat->mappings[packet.cookie].publicPort = NN_SWAP16(packet.Packet.init.localport);
                gsDebugFormat(GSIDebugCat_NatNeg, GSIDebugType_Network, GSIDebugLevel_Comment,
                              "Got ADDRESS REPLY %d from: %s\n", packet.cookie,
                              AddressToString(from.addr.addr, NN_SWAP16(from.port), NULL));
                OutputMapping(&nat->mappings[packet.cookie]);
            }
            if (sock == -1) {
                break;
            }
        }
    }
    return gsi_true;
}

int NatifyThink(SOCKET sock, NAT *nat) {
    return Think(sock, nat);
}

gsi_bool DetermineNatType(NAT *nat) {
    nat->natType = unknown;
    nat->promiscuity = promiscuity_not_applicable;
    nat->qr2Compatible = gsi_true;
    if (nat->mappings[packet_map1a].publicIp == 0 || nat->mappings[packet_map2].publicIp == 0 ||
        nat->mappings[packet_map3].publicIp == 0) {
        return gsi_false;
    }
    if (!nat->portRestricted && !nat->ipRestricted &&
        nat->mappings[packet_map1a].publicIp == nat->mappings[packet_map1a].privateIp) {
        nat->natType = no_nat;
    } else if (nat->mappings[packet_map1a].publicIp == nat->mappings[packet_map1a].privateIp) {
        nat->natType = firewall_only;
    } else if (!nat->ipRestricted && !nat->portRestricted &&
               abs(nat->mappings[packet_map3].publicPort - nat->mappings[packet_map2].publicPort) >= 1) {
        nat->natType = symmetric;
        nat->promiscuity = promiscuous;
    } else if (nat->ipRestricted && !nat->portRestricted &&
               abs(nat->mappings[packet_map3].publicPort - nat->mappings[packet_map2].publicPort) >= 1) {
        nat->natType = symmetric;
        nat->promiscuity = port_promiscuous;
    } else if (!nat->ipRestricted && nat->portRestricted &&
               abs(nat->mappings[packet_map3].publicPort - nat->mappings[packet_map2].publicPort) >= 1) {
        nat->natType = symmetric;
        nat->promiscuity = ip_promiscuous;
    } else if (nat->ipRestricted && nat->portRestricted &&
               abs(nat->mappings[packet_map3].publicPort - nat->mappings[packet_map2].publicPort) >= 1) {
        nat->natType = symmetric;
        nat->promiscuity = not_promiscuous;
    } else if (nat->portRestricted) {
        nat->natType = port_restricted_cone;
    } else if (nat->ipRestricted && !nat->portRestricted) {
        nat->natType = restricted_cone;
    } else if (!nat->ipRestricted && !nat->portRestricted) {
        nat->natType = full_cone;
    } else {
        nat->natType = unknown;
    }
    if (nat->mappings[packet_map1a].publicPort == nat->mappings[packet_map1a].privatePort &&
        nat->mappings[packet_map2].publicPort == nat->mappings[packet_map2].privatePort &&
        nat->mappings[packet_map3].publicPort == nat->mappings[packet_map3].privatePort) {
        nat->mappingScheme = private_as_public;
    } else if (nat->mappings[packet_map1a].publicPort == nat->mappings[packet_map2].publicPort &&
               nat->mappings[packet_map2].publicPort == nat->mappings[packet_map3].publicPort) {
        nat->mappingScheme = consistent_port;
    } else if (nat->mappings[packet_map1a].publicPort == nat->mappings[packet_map1a].privatePort &&
               nat->mappings[packet_map3].publicPort - nat->mappings[packet_map2].publicPort == 1) {
        nat->mappingScheme = mixed;
    } else if (nat->mappings[packet_map3].publicPort - nat->mappings[packet_map2].publicPort == 1) {
        nat->mappingScheme = incremental;
    } else {
        nat->mappingScheme = unrecognized;
    }
    if (nat->mappings[packet_map1b].publicPort != 0 &&
        nat->mappings[packet_map1a].publicPort != nat->mappings[packet_map1b].publicPort) {
        nat->qr2Compatible = gsi_false;
    }
    return gsi_true;
}
