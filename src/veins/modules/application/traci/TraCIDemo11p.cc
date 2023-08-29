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

#include "veins/modules/application/traci/TraCIDemo11p.h"

#include "veins/modules/application/traci/TraCIDemo11pMessage_m.h"
//#include <string.h>
//#include <stdio.h>

using namespace veins;

Define_Module(veins::TraCIDemo11p);

void TraCIDemo11p::initialize(int stage)
{
    DemoBaseApplLayer::initialize(stage);
    if (stage == 0) {
        sentMessage = false;
        lastDroveAt = simTime();
        currentSubscribedServiceId = -1;
        macHistory = { 2000,35000,23000,11000};//initializing known malicious addresses
        MalContents = {"malicious","danger"};// adding content keywords
        //EV << "Initializing " << par("appName").stringValue() << std::endl;
        EV_DEBUG << "Initializing appl layer " << endl;
        detectionThreshold = 0.8; //we can always adjust this value
        maliciousMessagesDetected = 0; //initializing to 0

    }
    else if (stage == 1) {
        TraCIDemo11pMessage* wsm = new TraCIDemo11pMessage();
        TraCIDemo11pMessage* wsm2 = new TraCIDemo11pMessage();
        TraCIDemo11pMessage* wsm3 = new TraCIDemo11pMessage();
        isMalicious = (uniform(0,1) < 0.2); // 10% of cars are malicious
        maliciousMessageInterval = 5.0; // Malicious messages every 1 second
        // Initializing members that require initialized other modules goes here
        //send malicious payload here instead as module fails to send
        int numVehicles = par("numVehicles");//TODO: need to add this to params DONE
        int maliciousVehicleIndex = intuniform(0,numVehicles -1); // Choose a random vehicle to send the malicious message
        int maliciousValue = intuniform(1, 100); // Random value for the malicious field
        EV_TRACE << "scheduling malicious messages "  << std::endl;
        //schedule malicious message from knowKnown bad addresses
        //schedule also with know malicious keywords
#ifdef SIM_1
        wsm->setDemoData("maliciousmessage");
        wsm2->setDemoData("maliciousanswer");
        wsm3->setDemoData("dangermessage");
#endif

#ifdef SIM_2
        wsm->setSenderAddress(2000);
        wsm2->setSenderAddress(23000);
        wsm3->setSenderAddress(23000);
        send(wsm, "out");
        sendDelayed(wsm2,simTime() + maliciousMessageInterval, "out");
        sendDelayed(wsm3,simTime() + maliciousMessageInterval+maliciousMessageInterval, "out");
#endif

#ifdef SIM_3
#endif
        /*
        if(isMalicious) {
           // wsm->setSenderPos(traciVehicle->getPositionAt(simTime()+2.0)); // Fake position 2 seconds into the future
            scheduleAt(simTime() + maliciousMessageInterval, sendBeaconEvt); // Repeatedly send fake messages
            //sendwsm here instead
        } else {
            scheduleAt(simTime() + beaconInterval, sendBeaconEvt);
            //also same
        }
        */
        /*Simulation 1*/
#ifdef SIM_1
        send(wsm, "out");
        sendDelayed(wsm2,simTime() + maliciousMessageInterval, "out");
        sendDelayed(wsm3,simTime() + maliciousMessageInterval+maliciousMessageInterval, "out");
#endif
         // Get the pointer to the target module
         //cModule* targetModule = getParentModule()->getSubmodule("TraCiDemo11p"); // Replace "targetModule" with the actual name

         // Send the message to the target module's input gate
        //if(isMalicious)

        //schedule numerous malicious messages
         //lowerControlOut

    }
}
void TraCIDemo11p::finish()
{
    DemoBaseApplLayer::finish();
    EV_TRACE << "Malicious Messages detected : "<< maliciousMessagesDetected <<endl;
}

void TraCIDemo11p::onWSA(DemoServiceAdvertisment* wsa)
{
    //maliciousMessagesDetected++;
    if (currentSubscribedServiceId == -1) {
        mac->changeServiceChannel(static_cast<Channel>(wsa->getTargetChannel()));
        currentSubscribedServiceId = wsa->getPsid();
        if (currentOfferedServiceId != wsa->getPsid()) {
            stopService();
            startService(static_cast<Channel>(wsa->getTargetChannel()), wsa->getPsid(), "Mirrored Traffic Service");
        }
    }
}

void TraCIDemo11p::onWSM(BaseFrame1609_4* frame)
{
  //  bool isMalicious = false;
    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);

    int senderId = wsm->getSenderAddress();
     Coord reportedPosition = wsm->getSenderPos();
     simtime_t generationTime = wsm->getCreationTime();


    findHost()->getDisplayString().setTagArg("i", 1, "green");

    if(analyzeMessageContent(wsm)==true||verifyMessageAddress(wsm)==true)
    {
        maliciousMessagesDetected++;
        handleMaliciousMessage(frame);
        return;
    }
    // Create a profile from aggregated data
    Coord aggregatedPosition(0,0);
    double aggregatedSpeed = 0;
    int count = 0;

    for(auto &entry : recentMessages) {
        aggregatedPosition += entry.second.position;
        aggregatedSpeed += entry.second.speed;
        count++;
    }

    if(count > 0) {
        aggregatedPosition /= count; // Average position
        aggregatedSpeed /= count;    // Average speed

        double positionDeviation = reportedPosition.distance(aggregatedPosition);
        double speedDeviation = abs(wsm->getSenderSpeed() - aggregatedSpeed);

        if(positionDeviation > THRESHOLD_POSITION || speedDeviation > THRESHOLD_SPEED) {
            EV << "Potential malicious message detected from sender " << senderId << endl;
        }
    }
  //check malicious mac address
  //check malicious content



    if (mobility->getRoadId()[0] != ':') traciVehicle->changeRoute(wsm->getDemoData(), 9999);
    if (!sentMessage) {
        sentMessage = true;
        // repeat the received traffic update once in 2 seconds plus some random delay
        wsm->setSenderAddress(myId);
        wsm->setSerial(3);
        scheduleAt(simTime() + 2 + uniform(0.01, 0.2), wsm->dup());
    }
}

void TraCIDemo11p::handleSelfMsg(cMessage* msg)
{
   // maliciousMessagesDetected++;
    if (TraCIDemo11pMessage* wsm = dynamic_cast<TraCIDemo11pMessage*>(msg)) {
        // send this message on the service channel until the counter is 3 or higher.
        // this code only runs when channel switching is enabled
        sendDown(wsm->dup());
        wsm->setSerial(wsm->getSerial() + 1);
        if (wsm->getSerial() >= 3) {
            // stop service advertisements
            stopService();
            delete (wsm);
        }
        else {
            scheduleAt(simTime() + 1, wsm);
        }
    }
    else {
        DemoBaseApplLayer::handleSelfMsg(msg);
    }
}

void TraCIDemo11p::handlePositionUpdate(cObject* obj)
{
    DemoBaseApplLayer::handlePositionUpdate(obj);

    // stopped for for at least 10s?
    if (mobility->getSpeed() < 1) {
        if (simTime() - lastDroveAt >= 10 && sentMessage == false) {
            findHost()->getDisplayString().setTagArg("i", 1, "red");
            sentMessage = true;

            TraCIDemo11pMessage* wsm = new TraCIDemo11pMessage();
            populateWSM(wsm);
            wsm->setDemoData(mobility->getRoadId().c_str());

            // host is standing still due to crash
            if (dataOnSch) {
                startService(Channel::sch2, 42, "Traffic Information Service");
                // started service and server advertising, schedule message to self to send later
                scheduleAt(computeAsynchronousSendingTime(1, ChannelType::service), wsm);
            }
            else {
                // send right away on CCH, because channel switching is disabled
                sendDown(wsm);
            }
        }
    }
    else {
        lastDroveAt = simTime();
#ifdef SIM_3
#endif
        //send general position update hee

    }
}
bool TraCIDemo11p::analyzeMessageContent(BaseFrame1609_4* frame) {
    int vecSize= MalContents.size();
    char *is;
    size_t found;
    // Implement content analysis logic
    // Return true if the message content is considered normal, false otherwise
    //check lenghth of message
    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);
    const char* messageData= wsm->getDemoData();
    std::string messageDataStr(messageData);
    for (int i=0;i<vecSize;i++)
    {
      found= messageDataStr.find(MalContents[i]);
      if( found !=std::string::npos)
      {
          return true;
          break;
      }
    }

    //loop through the
    //need to change the logic here to check for those elements here.

    return false;
}



double TraCIDemo11p::computeTrustValue(BaseFrame1609_4* frame)
{
    // Implement trust computation logic
    //NEXXT steps, determine ho to caclculate a score here
    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);
    // Calculate a trust value based on the message and sender's behavior
    //create a list of sender addresss and assign them scores but how to do this with separate hreads running
}

bool TraCIDemo11p::verifyMessageAddress(BaseFrame1609_4* frame) {
    // Implement cryptographic verification logic
    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);

    LAddress::L2Type macAddress = wsm->getSenderAddress();
    int macFrequency = std::count(macHistory.begin(), macHistory.end(), macAddress);
    // Return true if the message address is valid, false otherwise

    if(macFrequency>0)return true;

    return false;
}
void TraCIDemo11p::handleMaliciousMessage(BaseFrame1609_4* frame) {

    TraCIDemo11pMessage* wsm = check_and_cast<TraCIDemo11pMessage*>(frame);
    EV_INFO << "Malicious message detected from vehicle " << wsm->getSenderAddress() << endl;
    // Implement response actions, e.g., logging, alerting, etc.
}
