#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <thread>
#include <stdlib.h>
#include <unistd.h>
#include <map>
#include <set>
#include <algorithm>
#include <mutex>
#include "airodump.h"


void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
std::mutex channelmtx;
int channels[] = {1,7,13,2,8,3,14,9,4,10,5,11,6,12};
int i=0;

int channel_hop(char *interface){
    std::string cmd;
    cmd = cmd + "sudo iwconfig " + std::string(interface) + " channel ";
    std::string cmd_with_channels;
    while(1){
        channelmtx.lock();
        cmd_with_channels = cmd + std::to_string(channels[i]);
        system(cmd_with_channels.c_str());
        i++;
        if(i > (int)(sizeof(channels) / sizeof(int))) i=0;
        channelmtx.unlock();
        sleep(1);
    }
}

void print_beacon_info(std::pair<Mac, BeaconInfo> pair){
    printf("%s\t%d\t%d\t%s\n",std::string(pair.first).c_str(), pair.second.beacons, pair.second.data, pair.second.essid.c_str());
}
void print_station_info(std::pair<Mac, StationInfo> pair){
    if(pair.second.bssid == Mac::broadcastMac()){
        printf("%s\t", "(not associated)");
    } else{
        printf("%s\t", std::string(pair.second.bssid).c_str());
    }
    printf("%s\t%d\n", std::string(pair.first).c_str(), pair.second.frame);
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    std::thread t1(channel_hop, param.dev_);
    t1.detach();

    std::map<Mac, BeaconInfo> beacon_info;
    std::map<Mac, StationInfo> station_info;
    PRadiotabHdr radio;
    PDot11FrameHdr dot11;

    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
        }
        radio = (PRadiotabHdr)packet;
        packet += radio->hlen();
        dot11 = (PDot11FrameHdr)packet;
        BeaconInfo beaconinfo;
        StationInfo stationinfo;
        if(dot11->type_ == 0b00 && dot11->subtype_ == 0b1000){          //beacon frame
            if (beacon_info.find(dot11->bssid()) == beacon_info.end()){
                beacon_info.insert({dot11->bssid(), beaconinfo});
            }
            beaconinfo = beacon_info.find(dot11->bssid())->second;
            beaconinfo.beacons++;
            packet += sizeof(Dot11FrameHdr);
            packet += sizeof(Dot11WirelessMgntFixed);
            while(*(packet + 4) != 0){
                PDot11WirelessMgntTaggedHdr tagHdr = (PDot11WirelessMgntTaggedHdr) packet;
                if(tagHdr->eid_ == 0){
                    beaconinfo.essid = std::string(packet + sizeof(Dot11WirelessMgntTaggedHdr), packet + sizeof(Dot11WirelessMgntTaggedHdr) + tagHdr->length_);
                }
                packet += sizeof(Dot11WirelessMgntTaggedHdr) + tagHdr->length_;
            }
            beacon_info[dot11->bssid()] = beaconinfo;
        } else if(dot11->type_ == 0b10){                                //data frame
            if (beacon_info.find(dot11->bssid()) != beacon_info.end()){
                beaconinfo = beacon_info.find(dot11->bssid())->second;
                beaconinfo.data++;
                beacon_info[dot11->bssid()] = beaconinfo;
            }
        } else if(dot11->type_ == 0b00 && dot11->subtype_ == 0b0100){   //prove request
            if (station_info.find(dot11->source()) == station_info.end()){
                station_info.insert({dot11->source(), stationinfo});
            }
            stationinfo = station_info.find(dot11->source())->second;
            stationinfo.frame++;
            stationinfo.bssid = dot11->bssid();
            station_info[dot11->source()] = stationinfo;
        } else if(dot11->type_ == 0b00 && dot11->subtype_ == 0b0101){   //prove response
            if (station_info.find(dot11->destination()) == station_info.end()){
                station_info.insert({dot11->destination(), stationinfo});
            }
            stationinfo = station_info.find(dot11->destination())->second;
            stationinfo.frame++;
            stationinfo.bssid = dot11->bssid();
            station_info[dot11->destination()] = stationinfo;
        }
        system("clear");
        printf("Channel %d\n", channels[i]);
        printf("\nBSSID\t\t\tBeacons\t#Data\tESSID\n");
        std::for_each(beacon_info.begin(), beacon_info.end(), print_beacon_info);
        printf("\nBSSID\t\t\tStation\t\t\t#Frames\n");
        std::for_each(station_info.begin(), station_info.end(), print_station_info);
    }

	pcap_close(pcap);
}
