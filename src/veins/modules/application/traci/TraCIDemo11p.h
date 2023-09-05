//
// Copyright (C) 2006-2011 Christoph Sommer <christoph.sommer@uibk.ac.at>
//
// Documentation for these modules is at http://veins.car2x.org/
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#pragma once

#include "veins/modules/application/ieee80211p/DemoBaseApplLayer.h"
#include "malicious_message_m.h"

#define THRESHOLD_SPEED 50.0
#define THRESHOLD_POSITION 550.0
#define MAX_RECENT_MESSAGES 200
#define SIM_NORMAL_MESSAGES //allowing us to simulate normal messages

//#define SIM_1
//#define SIM_2
//#define SIM_3
//#define SIM_4
//#define SIM_5
//#define SIM_6
//#define SIM_7
//#define SIM_8
#define SIM_9






namespace veins {

/**
 * @brief
 * A tutorial demo for TraCI. When the car is stopped for longer than 10 seconds
 * it will send a message out to other cars containing the blocked road id.
 * Receiving cars will then trigger a reroute via TraCI.
 * When channel switching between SCH and CCH is enabled on the MAC, the message is
 * instead send out on a service channel following a Service Advertisement
 * on the CCH.
 *
 * @author Christoph Sommer : initial DemoApp
 * @author David Eckhoff : rewriting, moving functionality to DemoBaseApplLayer, adding WSA
 * @author Atans Joseph-Palmer : rewriting to allow for malicious message detection
 *
 */

struct MessageInfo {
    Coord position;
    double speed;
    simtime_t generationTime;
};

int messageCounter = 0;
std::map<int, MessageInfo> recentMessages;


class VEINS_API TraCIDemo11p : public DemoBaseApplLayer {
public:
    void initialize(int stage) override;
    void finish() override;

protected:
    simtime_t lastDroveAt;
    bool sentMessage;
    int currentSubscribedServiceId;
    double detectionThreshold;
    int maliciousMessagesDetected;
    int maliciousMessagesGenerated;
    bool isMalicious;
    double maliciousMessageInterval;
    std::vector<LAddress::L2Type>macHistory; //flagged mac addresses
    std::vector<std::string>MalContents;//vector of malicious content keywords

protected:
    void onWSM(BaseFrame1609_4* wsm) override;
    void onWSA(DemoServiceAdvertisment* wsa) override;

    void handleSelfMsg(cMessage* msg) override;
    void handlePositionUpdate(cObject* obj) override;

    double computeTrustValue(BaseFrame1609_4* frame) ;
    void handleMaliciousMessage(BaseFrame1609_4* frame);
    bool analyzeMessageContent(BaseFrame1609_4* frame);
    bool verifyMessageAddress(BaseFrame1609_4* frame) ;
};

} // namespace veins
