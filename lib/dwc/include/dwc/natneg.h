#ifndef POKEBW2_DWC_NATNEG_H
#define POKEBW2_DWC_NATNEG_H

#include "dwc/NATify.h"
#include "dwc/nonport.h"
#include "nitrowifi/soc.h"

// GameSpy's NAT negotiation (natneg.c), in overlay 11: two consoles behind NATs find each other's public address
// through the servers natneg1, natneg2 and natneg3 of the game's domain, which match them by a cookie that both give,
// and then ping each other until a packet gets through. The packets start with the six magic bytes, the protocol's
// version (4) and a type: 0 init, 1 its ack, 2 an ERT test, 3 its ack, 5 connect, 6 its ack, 7 a ping, 10 an address
// check, 11 its reply, 12 a NAT detection request, 13 a report of the result, 14 its ack, 15 the pre-init and 16 its
// ack.
//
// A negotiation's state goes 0 (the pre-init sent), 1 (its ack received), 2 (the init packets sent), 3 (all of them
// acked: waiting for the partner), 4 (pinging the partner), then 7 (the report sent), 8 (its ack received), 5
// (finished) and 6 (canceled). Its result is 0 (success), 1 (the partner never came), 2 (the servers never answered),
// 3 (the pings timed out), 4 (an unknown error) or 5 (no result yet); the errors of a start are 0 (none), 1 (out of
// memory), 2 (no socket, or the backend is down) and 3 (the servers' names can't be resolved)

// The byte order of the network
#define NN_SWAP16(x) ((gsi_u16)((gsi_u8)((x) >> 8) | ((x) << 8 & 0xff00)))
#define NN_SWAP32(x)                                                                                                   \
    ((((gsi_u32)(x) >> 24) & 0xff) | (((gsi_u32)(x) >> 8) & 0xff00) | (((gsi_u32)(x) << 8) & 0xff0000) |               \
     (((gsi_u32)(x) << 24) & 0xff000000))

#define NATNEG_MAGIC_LEN 6

// The protocol's version; the packets' types; the states a pre-init ack reports; and the port the three servers
// listen on
#define NN_PROTVER 4
#define MATCHUP_PORT1 27901
#define MATCHUP_PORT2 27901
#define MATCHUP_PORT3 27901

#define NN_INIT 0
#define NN_INITACK 1
#define NN_ERTTEST 2
#define NN_ERTACK 3
#define NN_STATEUPDATE 4
#define NN_CONNECT 5
#define NN_CONNECT_ACK 6
#define NN_CONNECT_PING 7
#define NN_BACKUP_TEST 8
#define NN_BACKUP_ACK 9
#define NN_ADDRESS_CHECK 10
#define NN_ADDRESS_REPLY 11
#define NN_NATIFY_REQUEST 12
#define NN_REPORT 13
#define NN_REPORT_ACK 14
#define NN_PREINIT 15
#define NN_PREINIT_ACK 16

#define NN_PREINIT_WAITING_FOR_CLIENT 0
#define NN_PREINIT_WAITING_FOR_MATCHUP 1
#define NN_PREINIT_READY 2

// The packets' header is 12 bytes and its eighth byte is the type; each type adds its fields: 9 for an init packet
// (and the game's name after them), 8 for a connect packet or a ping, 61 for a report and 6 for a pre-init. The
// init packet's address follows its port type and flags, unaligned
#define BASEPACKET_SIZE 12
#define BASEPACKET_TYPE_OFFSET 7
#define INITPACKET_SIZE (BASEPACKET_SIZE + 9)
#define INITPACKET_ADDRESS_OFFSET (BASEPACKET_SIZE + 3)
#define CONNECTPACKET_SIZE (BASEPACKET_SIZE + 8)
#define REPORTPACKET_SIZE (BASEPACKET_SIZE + 61)
#define PREINITPACKET_SIZE (BASEPACKET_SIZE + 6)

// The init packet's port types: the game's socket, then the negotiation's to each of the three servers
#define NN_PT_GP 0
#define NN_PT_NN1 1
#define NN_PT_NN2 2
#define NN_PT_NN3 3

// The reason a connect packet gives for a negotiation that ended: 0 while it goes on, else 1 a deadbeat partner and 2
// the init packets' timeout
#define FINISHED_NOERROR 0
#define FINISHED_ERROR_DEADBEAT_PARTNER 1
#define FINISHED_ERROR_INIT_PACKETS_TIMEDOUT 2

// The retry times in milliseconds and counts of the SDK's state machine: the pre-init packet's first send and its
// acks, the init packets, the pings, the wait for the partner's pings and the report; and the size of a receive buffer
#define PREINIT_RETRY_TIME 500
#define PREINIT_RETRY_COUNT 10
#define PREINITACK_RETRY_TIME 10000
#define PREINITACK_RETRY_COUNT 12
#define INIT_RETRY_TIME 500
#define INIT_RETRY_COUNT 10
#define PING_RETRY_TIME 700
#define PING_RETRY_COUNT 7
#define PARTNER_WAIT_TIME 60000
#define REPORT_RETRY_TIME 500
#define REPORT_RETRY_COUNT 4
#define NNINBUF_LEN 512

typedef struct _InitPacket {
    unsigned char porttype; // NN_PT_GP, or NN_PT_NN1 to NN_PT_NN3
    unsigned char clientindex;
    unsigned char usegameport;
    unsigned int localip;
    unsigned short localport;
} InitPacket;

typedef struct _ReportPacket {
    unsigned char porttype;
    unsigned char clientindex;
    unsigned char negResult; // whether it succeeded
    NatType natType;
    NatMappingScheme natMappingScheme;
    char gamename[50];
} ReportPacket;

typedef struct _ConnectPacket {
    unsigned int remoteIP;
    unsigned short remotePort;
    unsigned char gotyourdata;
    unsigned char finished; // FINISHED_NOERROR, or the reason the negotiation failed
} ConnectPacket;

typedef struct _PreinitPacket {
    gsi_u8 clientindex;
    gsi_u8 state; // NN_PREINIT_WAITING_FOR_CLIENT, NN_PREINIT_WAITING_FOR_MATCHUP or NN_PREINIT_READY
    gsi_u32 clientID;
} PreinitPacket;

typedef struct _NatNegPacket {
    unsigned char magic[NATNEG_MAGIC_LEN];
    unsigned char version;
    unsigned char packettype;
    int cookie;
    union {
        InitPacket init;
        ConnectPacket connect;
        ReportPacket report;
        PreinitPacket preInit;
    } Packet;
} NatNegPacket;

typedef enum {
    ns_preinitsent,
    ns_preinitack,
    ns_initsent,
    ns_initack,
    ns_connectping,
    ns_finished,
    ns_canceled,
    ns_reportsent,
    ns_reportack
} NegotiateState;

typedef enum {
    nr_success,
    nr_deadbeatpartner,
    nr_inittimeout,
    nr_pingtimeout,
    nr_unknownerror,
    nr_noresult
} NegotiateResult;

typedef enum { ne_noerror, ne_allocerror, ne_socketerror, ne_dnserror } NegotiateError;

typedef void (*NegotiateProgressFunc)(NegotiateState state, void *userData);
typedef void (*NegotiateCompletedFunc)(NegotiateResult result, SOCKET gameSocket, SOCKADDR_IN *remoteAddr,
                                       void *userData);
typedef void (*NatDetectionResultsFunc)(gsi_bool success, NAT nat);

extern unsigned char NNMagicData[NATNEG_MAGIC_LEN];

void NNFreeNegotiateList(void);
// Starts a negotiation that shares the game's socket, or uses its own when it is -1; the game passes the packets
// that come in on its socket with the magic bytes to NNProcessData
NegotiateError NNBeginNegotiationWithSocket(SOCKET gameSocket, int cookie, int clientIndex,
                                            NegotiateProgressFunc progress, NegotiateCompletedFunc completed,
                                            void *userData);
void NNCancel(int cookie);
void NNThink(void);
void NNProcessData(char *data, int length, SOCKADDR_IN *from);

#endif // POKEBW2_DWC_NATNEG_H
