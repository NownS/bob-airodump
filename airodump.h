#pragma once
#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push,1)

struct RadiotapHdr final{
    uint8_t headerRevision_;
    uint8_t headerPad_;
    uint16_t hlen_;

    uint16_t hlen() {return hlen_;}
};
typedef RadiotapHdr *PRadiotabHdr;

struct Dot11FrameHdr {
    uint8_t version_:2;
    uint8_t type_:2;
    uint8_t subtype_:4;
    uint8_t flags_;
    uint16_t duration_;
    uint8_t destination_[6];
    uint8_t source_[6];
    uint8_t bssid_[6];
    uint16_t numbers;

    uint16_t duration() {return duration_;}
    Mac destination() {return Mac(destination_);}
    Mac source() {return Mac(source_);}
    Mac bssid() {return Mac(bssid_);}
};
typedef Dot11FrameHdr *PDot11FrameHdr;

struct Dot11WirelessMgntFixed {
    uint64_t timestamp_;
    uint16_t beaconInterval_;
    uint16_t capabilitiesInfo_;
};
typedef Dot11WirelessMgntFixed *PDot11WirelessMgntFixed;

struct Dot11WirelessMgntTaggedHdr {
    uint8_t eid_;
    uint8_t length_;
};
typedef Dot11WirelessMgntTaggedHdr *PDot11WirelessMgntTaggedHdr;

#pragma pack(pop)

struct BeaconInfo {
    int pwr = 0;
    int beacons = 0;
    int data = 0;
    std::string enc = "";
    std::string essid = "";
};


struct StationInfo {
    int pwr = 0;
    Mac bssid;
    int frame = 0;
    std::string prove = "";
};
