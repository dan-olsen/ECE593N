# ECE 593N - Project 1 - Daniel Olsen

## Description of Parameters

| Scenario    | Simulation Area | Communication Range | Mobility Model | # Sinks/Sources |
| ----------- | --------------- | ------------------- | -------------- | --------------- |
| Base        | 300.0 x 1500.0  | 7.5                 | 20, 0          | 10              |
| AODV Better | 300.0 x 1500.0  | 7.5                 | 40, 5          | 10              |
| DSDV Better | 300.0 x 1500.0  | 7.5                 | 1, 0           | 10              |

## Figures
![Throughput Base]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart1-Base.png)
![Throughput AODV]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart1-AODV.png)
![Throughput DSDV]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart1-DSDV.png)
![Efficiency Base]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart2-Base.png)
![Efficiency AOV]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart2-AODV.png)
![Efficiency DSDV]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart2-DSDV.png)
![Overhead Base]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart3-Base.png)
![Overhead AODV]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart3-AODV.png)
![Overhead DSDV]
(https://raw.githubusercontent.com/dan-olsen/ECE593N/master/Chart3-DSDV.png)
## Script (Base Scenario AODV)
```c++
/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2011 University of Kansas
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Justin Rohrer <rohrej@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

/*
 * This example program allows one to run ns-3 DSDV, AODV, or OLSR under
 * a typical random waypoint mobility model.
 *
 * By default, the simulation runs for 200 simulated seconds, of which
 * the first 50 are used for start-up time.  The number of nodes is 50.
 * Nodes move according to RandomWaypointMobilityModel with a speed of
 * 20 m/s and no pause time within a 300x1500 m region.  The WiFi is
 * in ad hoc mode with a 2 Mb/s rate (802.11b) and a Friis loss model.
 * The transmit power is set to 7.5 dBm.
 *
 * It is possible to change the mobility and density of the network by
 * directly modifying the speed and the number of nodes.  It is also
 * possible to change the characteristics of the network by changing
 * the transmit power (as power increases, the impact of mobility
 * decreases and the effective density increases).
 *
 * By default, OLSR is used, but specifying a value of 2 for the protocol
 * will cause AODV to be used, and specifying a value of 3 will cause
 * DSDV to be used.
 *
 * By default, there are 10 source/sink data pairs sending UDP data
 * at an application rate of 2.048 Kb/s each.    This is typically done
 * at a rate of 4 64-byte packets per second.  Application data is
 * started at a random time between 50 and 51 seconds and continues
 * to the end of the simulation.
 *
 * The program outputs a few items:
 * - packet receptions are notified to stdout such as:
 *   <timestamp> <node-id> received one packet from <src-address>
 * - each second, the data reception statistics are tabulated and output
 *   to a comma-separated value (csv) file
 * - some tracing and flow monitor configuration that used to work is
 *   left commented inline in the program
 */

#include <fstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/aodv-module.h"
#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/applications-module.h"

using namespace ns3;
using namespace dsr;

NS_LOG_COMPONENT_DEFINE ("project1");

class RoutingExperiment
{
public:
  RoutingExperiment ();
  void Run (int nSinks, double txp, std::string CSVfileName);
  //static void SetMACParam (ns3::NetDeviceContainer & devices,
  //                                 int slotDistance);
  std::string CommandSetup (int argc, char **argv);

private:
  Ptr<Socket> SetupPacketReceive (Ipv4Address addr, Ptr<Node> node);
  void ReceivePacket (Ptr<Socket> socket);
  void CheckThroughput ();
  void PrintNumCommandPackets ();

  uint32_t port;
  uint32_t bytesTotal;
  uint32_t packetsReceived;

  std::string m_CSVfileName;
  int m_nSinks;
  std::string m_protocolName;
  double m_txp;
  bool m_traceMobility;
  uint32_t m_protocol;
};

RoutingExperiment::RoutingExperiment ()
  : port (9),
    bytesTotal (0),
    packetsReceived (0),
    m_CSVfileName ("./scratch/project1.output.csv"),
    m_traceMobility (false),
    m_protocol (2) // AODV
{
}

static inline std::string
PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet)
{
  SocketAddressTag tag;
  bool found;
  found = packet->PeekPacketTag (tag);
  std::ostringstream oss;

  oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode ()->GetId ();

  if (found)
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (tag.GetAddress ());
      oss << " received one packet from " << addr.GetIpv4 ();
    }
  else
    {
      oss << " received one packet!";
    }
  return oss.str ();
}

void
RoutingExperiment::ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  while ((packet = socket->Recv ()))
    {
      bytesTotal += packet->GetSize ();
      packetsReceived += 1;
      NS_LOG_UNCOND (PrintReceivedPacket (socket, packet));
    }
}

void
RoutingExperiment::CheckThroughput ()
{
  double kbs = (bytesTotal * 8.0) / 5000;
  bytesTotal = 0;

  std::ofstream out (m_CSVfileName.c_str (), std::ios::app);

  out << (Simulator::Now ()).GetSeconds () << ","
      << kbs << ","
      << packetsReceived << ","
      << m_nSinks << ","
      << m_protocolName << ","
      << m_txp << ""
      << std::endl;

  out.close ();
  packetsReceived = 0;
  Simulator::Schedule (Seconds (5.0), &RoutingExperiment::CheckThroughput, this);
}
void
RoutingExperiment::PrintNumCommandPackets ()
{
    std::cout << (Simulator::Now ()).GetSeconds () << ","
      << aodv::RoutingProtocol::CommandPacketCount
      << std::endl;
}

Ptr<Socket>
RoutingExperiment::SetupPacketReceive (Ipv4Address addr, Ptr<Node> node)
{
  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> sink = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (addr, port);
  sink->Bind (local);
  sink->SetRecvCallback (MakeCallback (&RoutingExperiment::ReceivePacket, this));

  return sink;
}

std::string
RoutingExperiment::CommandSetup (int argc, char **argv)
{
  CommandLine cmd;
  cmd.AddValue ("CSVfileName", "The name of the CSV output file name", m_CSVfileName);
  cmd.AddValue ("traceMobility", "Enable mobility tracing", m_traceMobility);
  cmd.AddValue ("protocol", "1=OLSR;2=AODV;3=DSDV;4=DSR", m_protocol);
  cmd.Parse (argc, argv);
  return m_CSVfileName;
}

int
main (int argc, char *argv[])
{
  RoutingExperiment experiment;
  std::string CSVfileName = experiment.CommandSetup (argc,argv);

  //blank out the last output file and write the column headers
  std::ofstream out (CSVfileName.c_str ());
  out << "SimulationSecond," <<
  "ReceiveRate," <<
  "PacketsReceived," <<
  "NumberOfSinks," <<
  "RoutingProtocol," <<
  "TransmissionPower" <<
  std::endl;
  out.close ();

  int nSinks = 10;
  double txp = 7.5;

  experiment.Run (nSinks, txp, CSVfileName);
}

void
RoutingExperiment::Run (int nSinks, double txp, std::string CSVfileName)
{
  Packet::EnablePrinting ();
  m_nSinks = nSinks;
  m_txp = txp;
  m_CSVfileName = CSVfileName;

  int nWifis = 50;

  double TotalTime = 200.0;
  std::string rate ("2048bps");
  std::string phyMode ("DsssRate11Mbps");
  std::string tr_name ("project1");
  int nodeSpeed = 20; //in m/s
  int nodePause = 0; //in s
  m_protocolName = "protocol";

  Config::SetDefault  ("ns3::OnOffApplication::PacketSize",StringValue ("64"));
  Config::SetDefault ("ns3::OnOffApplication::DataRate",  StringValue (rate));

  //Set Non-unicastMode rate to unicast mode
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",StringValue (phyMode));

  NodeContainer adhocNodes;
  adhocNodes.Create (nWifis);

  // setting up wifi phy and channel using helpers
  WifiHelper wifi;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a mac and disable rate control
  WifiMacHelper wifiMac;
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue (phyMode),
                                "ControlMode",StringValue (phyMode));

  wifiPhy.Set ("TxPowerStart",DoubleValue (txp));
  wifiPhy.Set ("TxPowerEnd", DoubleValue (txp));

  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer adhocDevices = wifi.Install (wifiPhy, wifiMac, adhocNodes);

  MobilityHelper mobilityAdhoc;
  int64_t streamIndex = 0; // used to get consistent mobility across scenarios

  ObjectFactory pos;
  pos.SetTypeId ("ns3::RandomRectanglePositionAllocator");
  pos.Set ("X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
  pos.Set ("Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1500.0]"));

  Ptr<PositionAllocator> taPositionAlloc = pos.Create ()->GetObject<PositionAllocator> ();
  streamIndex += taPositionAlloc->AssignStreams (streamIndex);

  std::stringstream ssSpeed;
  ssSpeed << "ns3::UniformRandomVariable[Min=0.0|Max=" << nodeSpeed << "]";
  std::stringstream ssPause;
  ssPause << "ns3::ConstantRandomVariable[Constant=" << nodePause << "]";
  mobilityAdhoc.SetMobilityModel ("ns3::RandomWaypointMobilityModel",
                                  "Speed", StringValue (ssSpeed.str ()),
                                  "Pause", StringValue (ssPause.str ()),
                                  "PositionAllocator", PointerValue (taPositionAlloc));
  mobilityAdhoc.SetPositionAllocator (taPositionAlloc);
  mobilityAdhoc.Install (adhocNodes);
  streamIndex += mobilityAdhoc.AssignStreams (adhocNodes, streamIndex);

  AodvHelper aodv;
  OlsrHelper olsr;
  DsdvHelper dsdv;
  DsrHelper dsr;
  DsrMainHelper dsrMain;
  Ipv4ListRoutingHelper list;
  InternetStackHelper internet;

  switch (m_protocol)
    {
    case 1:
      list.Add (olsr, 100);
      m_protocolName = "OLSR";
      break;
    case 2:
      list.Add (aodv, 100);
      m_protocolName = "AODV";
      break;
    case 3:
      list.Add (dsdv, 100);
      m_protocolName = "DSDV";
      break;
    case 4:
      m_protocolName = "DSR";
      break;
    default:
      NS_FATAL_ERROR ("No such protocol:" << m_protocol);
    }

  if (m_protocol < 4)
    {
      internet.SetRoutingHelper (list);
      internet.Install (adhocNodes);
    }
  else if (m_protocol == 4)
    {
      internet.Install (adhocNodes);
      dsrMain.Install (dsr, adhocNodes);
    }

  NS_LOG_INFO ("assigning ip address");

  Ipv4AddressHelper addressAdhoc;
  addressAdhoc.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer adhocInterfaces;
  adhocInterfaces = addressAdhoc.Assign (adhocDevices);

  OnOffHelper onoff1 ("ns3::UdpSocketFactory",Address ());
  onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));

  for (int i = 0; i < nSinks; i++)
    {
      Ptr<Socket> sink = SetupPacketReceive (adhocInterfaces.GetAddress (i), adhocNodes.Get (i));

      AddressValue remoteAddress (InetSocketAddress (adhocInterfaces.GetAddress (i), port));
      onoff1.SetAttribute ("Remote", remoteAddress);

      Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable> ();
      ApplicationContainer temp = onoff1.Install (adhocNodes.Get (i + nSinks));
      temp.Start (Seconds (var->GetValue (100.0,101.0)));
      temp.Stop (Seconds (TotalTime));
    }

  std::stringstream ss;
  ss << nWifis;
  std::string nodes = ss.str ();

  std::stringstream ss2;
  ss2 << nodeSpeed;
  std::string sNodeSpeed = ss2.str ();

  std::stringstream ss3;
  ss3 << nodePause;
  std::string sNodePause = ss3.str ();

  std::stringstream ss4;
  ss4 << rate;
  std::string sRate = ss4.str ();

  //NS_LOG_INFO ("Configure Tracing.");
  //tr_name = tr_name + "_" + m_protocolName +"_" + nodes + "nodes_" + sNodeSpeed + "speed_" + sNodePause + "pause_" + sRate + "rate";

  //AsciiTraceHelper ascii;
  //Ptr<OutputStreamWrapper> osw = ascii.CreateFileStream ( (tr_name + ".tr").c_str());
  //wifiPhy.EnableAsciiAll (osw);
  AsciiTraceHelper ascii;
  MobilityHelper::EnableAsciiAll (ascii.CreateFileStream ("./scratch/" + tr_name + ".mob"));

  //Ptr<FlowMonitor> flowmon;
  //FlowMonitorHelper flowmonHelper;
  //flowmon = flowmonHelper.InstallAll ();


  NS_LOG_INFO ("Run Simulation.");

  CheckThroughput ();
  
  Simulator::Schedule (Seconds (TotalTime - 1.0), &RoutingExperiment::PrintNumCommandPackets, this);

  Simulator::Stop (Seconds (TotalTime));
  Simulator::Run ();

  //flowmon->SerializeToXmlFile ((tr_name + ".flowmon").c_str(), false, false);

  Simulator::Destroy ();
}
```

## Modified Source Code

In both the AODV and DSDV routing protocols a static integer named CommandPacketCount was declared in the class and was defined to 0 in the source file. Within the RecvAodv and RecvDsdv methods the CommandPacketCount was incremented. This allows for direct access to the Counts without the need to sum them from every node because there is only one CommandPacketCount member that is shared between all the nodes.

### aodv-routing-protocol.cc
```c++
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Based on 
 *      NS-2 AODV model developed by the CMU/MONARCH group and optimized and
 *      tuned by Samir Das and Mahesh Marina, University of Cincinnati;
 * 
 *      AODV-UU implementation by Erik Nordström of Uppsala University
 *      http://core.it.uu.se/core/index.php/AODV-UU
 *
 * Authors: Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */
#define NS_LOG_APPEND_CONTEXT                                   \
  if (m_ipv4) { std::clog << "[node " << m_ipv4->GetObject<Node> ()->GetId () << "] "; } 

#include "aodv-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/wifi-net-device.h"
#include "ns3/adhoc-wifi-mac.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include <algorithm>
#include <limits>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE ("AodvRoutingProtocol");

namespace aodv
{

int RoutingProtocol::CommandPacketCount = 0;
NS_OBJECT_ENSURE_REGISTERED (RoutingProtocol);

/// UDP Port for AODV control traffic
const uint32_t RoutingProtocol::AODV_PORT = 654;

//-----------------------------------------------------------------------------
/// Tag used by AODV implementation

class DeferredRouteOutputTag : public Tag
{

public:
  DeferredRouteOutputTag (int32_t o = -1) : Tag (), m_oif (o) {}

  static TypeId GetTypeId ()
  {
    static TypeId tid = TypeId ("ns3::aodv::DeferredRouteOutputTag")
      .SetParent<Tag> ()
      .SetGroupName("Aodv")
      .AddConstructor<DeferredRouteOutputTag> ()
    ;
    return tid;
  }

  TypeId  GetInstanceTypeId () const 
  {
    return GetTypeId ();
  }

  int32_t GetInterface() const
  {
    return m_oif;
  }

  void SetInterface(int32_t oif)
  {
    m_oif = oif;
  }

  uint32_t GetSerializedSize () const
  {
    return sizeof(int32_t);
  }

  void  Serialize (TagBuffer i) const
  {
    i.WriteU32 (m_oif);
  }

  void  Deserialize (TagBuffer i)
  {
    m_oif = i.ReadU32 ();
  }

  void  Print (std::ostream &os) const
  {
    os << "DeferredRouteOutputTag: output interface = " << m_oif;
  }

private:
  /// Positive if output device is fixed in RouteOutput
  int32_t m_oif;
};

NS_OBJECT_ENSURE_REGISTERED (DeferredRouteOutputTag);


//-----------------------------------------------------------------------------
RoutingProtocol::RoutingProtocol () :
  RreqRetries (2),
  RreqRateLimit (10),
  RerrRateLimit (10),
  ActiveRouteTimeout (Seconds (3)),
  NetDiameter (35),
  NodeTraversalTime (MilliSeconds (40)),
  NetTraversalTime (Time ((2 * NetDiameter) * NodeTraversalTime)),
  PathDiscoveryTime ( Time (2 * NetTraversalTime)),
  MyRouteTimeout (Time (2 * std::max (PathDiscoveryTime, ActiveRouteTimeout))),
  HelloInterval (Seconds (1)),
  AllowedHelloLoss (2),
  DeletePeriod (Time (5 * std::max (ActiveRouteTimeout, HelloInterval))),
  NextHopWait (NodeTraversalTime + MilliSeconds (10)),
  BlackListTimeout (Time (RreqRetries * NetTraversalTime)),
  MaxQueueLen (64),
  MaxQueueTime (Seconds (30)),
  DestinationOnly (false),
  GratuitousReply (true),
  EnableHello (false),
  m_routingTable (DeletePeriod),
  m_queue (MaxQueueLen, MaxQueueTime),
  m_requestId (0),
  m_seqNo (0),
  m_rreqIdCache (PathDiscoveryTime),
  m_dpd (PathDiscoveryTime),
  m_nb (HelloInterval),
  m_rreqCount (0),
  m_rerrCount (0),
  m_htimer (Timer::CANCEL_ON_DESTROY),
  m_rreqRateLimitTimer (Timer::CANCEL_ON_DESTROY),
  m_rerrRateLimitTimer (Timer::CANCEL_ON_DESTROY),
  m_lastBcastTime (Seconds (0))
{
  m_nb.SetCallback (MakeCallback (&RoutingProtocol::SendRerrWhenBreaksLinkToNextHop, this));
}

TypeId
RoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::aodv::RoutingProtocol")
    .SetParent<Ipv4RoutingProtocol> ()
    .SetGroupName("Aodv")
    .AddConstructor<RoutingProtocol> ()
    .AddAttribute ("HelloInterval", "HELLO messages emission interval.",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&RoutingProtocol::HelloInterval),
                   MakeTimeChecker ())
    .AddAttribute ("RreqRetries", "Maximum number of retransmissions of RREQ to discover a route",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::RreqRetries),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RreqRateLimit", "Maximum number of RREQ per second.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&RoutingProtocol::RreqRateLimit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("RerrRateLimit", "Maximum number of RERR per second.",
                   UintegerValue (10),
                   MakeUintegerAccessor (&RoutingProtocol::RerrRateLimit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NodeTraversalTime", "Conservative estimate of the average one hop traversal time for packets and should include "
                   "queuing delays, interrupt processing times and transfer times.",
                   TimeValue (MilliSeconds (40)),
                   MakeTimeAccessor (&RoutingProtocol::NodeTraversalTime),
                   MakeTimeChecker ())
    .AddAttribute ("NextHopWait", "Period of our waiting for the neighbour's RREP_ACK = 10 ms + NodeTraversalTime",
                   TimeValue (MilliSeconds (50)),
                   MakeTimeAccessor (&RoutingProtocol::NextHopWait),
                   MakeTimeChecker ())
    .AddAttribute ("ActiveRouteTimeout", "Period of time during which the route is considered to be valid",
                   TimeValue (Seconds (3)),
                   MakeTimeAccessor (&RoutingProtocol::ActiveRouteTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("MyRouteTimeout", "Value of lifetime field in RREP generating by this node = 2 * max(ActiveRouteTimeout, PathDiscoveryTime)",
                   TimeValue (Seconds (11.2)),
                   MakeTimeAccessor (&RoutingProtocol::MyRouteTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("BlackListTimeout", "Time for which the node is put into the blacklist = RreqRetries * NetTraversalTime",
                   TimeValue (Seconds (5.6)),
                   MakeTimeAccessor (&RoutingProtocol::BlackListTimeout),
                   MakeTimeChecker ())
    .AddAttribute ("DeletePeriod", "DeletePeriod is intended to provide an upper bound on the time for which an upstream node A "
                   "can have a neighbor B as an active next hop for destination D, while B has invalidated the route to D."
                   " = 5 * max (HelloInterval, ActiveRouteTimeout)",
                   TimeValue (Seconds (15)),
                   MakeTimeAccessor (&RoutingProtocol::DeletePeriod),
                   MakeTimeChecker ())
    .AddAttribute ("NetDiameter", "Net diameter measures the maximum possible number of hops between two nodes in the network",
                   UintegerValue (35),
                   MakeUintegerAccessor (&RoutingProtocol::NetDiameter),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("NetTraversalTime", "Estimate of the average net traversal time = 2 * NodeTraversalTime * NetDiameter",
                   TimeValue (Seconds (2.8)),
                   MakeTimeAccessor (&RoutingProtocol::NetTraversalTime),
                   MakeTimeChecker ())
    .AddAttribute ("PathDiscoveryTime", "Estimate of maximum time needed to find route in network = 2 * NetTraversalTime",
                   TimeValue (Seconds (5.6)),
                   MakeTimeAccessor (&RoutingProtocol::PathDiscoveryTime),
                   MakeTimeChecker ())
    .AddAttribute ("MaxQueueLen", "Maximum number of packets that we allow a routing protocol to buffer.",
                   UintegerValue (64),
                   MakeUintegerAccessor (&RoutingProtocol::SetMaxQueueLen,
                                         &RoutingProtocol::GetMaxQueueLen),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxQueueTime", "Maximum time packets can be queued (in seconds)",
                   TimeValue (Seconds (30)),
                   MakeTimeAccessor (&RoutingProtocol::SetMaxQueueTime,
                                     &RoutingProtocol::GetMaxQueueTime),
                   MakeTimeChecker ())
    .AddAttribute ("AllowedHelloLoss", "Number of hello messages which may be loss for valid link.",
                   UintegerValue (2),
                   MakeUintegerAccessor (&RoutingProtocol::AllowedHelloLoss),
                   MakeUintegerChecker<uint16_t> ())
    .AddAttribute ("GratuitousReply", "Indicates whether a gratuitous RREP should be unicast to the node originated route discovery.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetGratuitousReplyFlag,
                                        &RoutingProtocol::GetGratuitousReplyFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("DestinationOnly", "Indicates only the destination may respond to this RREQ.",
                   BooleanValue (false),
                   MakeBooleanAccessor (&RoutingProtocol::SetDesinationOnlyFlag,
                                        &RoutingProtocol::GetDesinationOnlyFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("EnableHello", "Indicates whether a hello messages enable.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetHelloEnable,
                                        &RoutingProtocol::GetHelloEnable),
                   MakeBooleanChecker ())
    .AddAttribute ("EnableBroadcast", "Indicates whether a broadcast data packets forwarding enable.",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetBroadcastEnable,
                                        &RoutingProtocol::GetBroadcastEnable),
                   MakeBooleanChecker ())
    .AddAttribute ("UniformRv",
                   "Access to the underlying UniformRandomVariable",
                   StringValue ("ns3::UniformRandomVariable"),
                   MakePointerAccessor (&RoutingProtocol::m_uniformRandomVariable),
                   MakePointerChecker<UniformRandomVariable> ())
  ;
  return tid;
}

void
RoutingProtocol::SetMaxQueueLen (uint32_t len)
{
  MaxQueueLen = len;
  m_queue.SetMaxQueueLen (len);
}
void
RoutingProtocol::SetMaxQueueTime (Time t)
{
  MaxQueueTime = t;
  m_queue.SetQueueTimeout (t);
}

RoutingProtocol::~RoutingProtocol ()
{
}

void
RoutingProtocol::DoDispose ()
{
  m_ipv4 = 0;
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
         m_socketAddresses.begin (); iter != m_socketAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketAddresses.clear ();
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
         m_socketSubnetBroadcastAddresses.begin (); iter != m_socketSubnetBroadcastAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketSubnetBroadcastAddresses.clear ();
  Ipv4RoutingProtocol::DoDispose ();
}

void
RoutingProtocol::PrintRoutingTable (Ptr<OutputStreamWrapper> stream) const
{
  *stream->GetStream () << "Node: " << m_ipv4->GetObject<Node> ()->GetId ()
                        << "; Time: " << Now().As (Time::S)
                        << ", Local time: " << GetObject<Node> ()->GetLocalTime ().As (Time::S)
                        << ", AODV Routing table" << std::endl;

  m_routingTable.Print (stream);
  *stream->GetStream () << std::endl;
}

int64_t
RoutingProtocol::AssignStreams (int64_t stream)
{
  NS_LOG_FUNCTION (this << stream);
  m_uniformRandomVariable->SetStream (stream);
  return 1;
}

void
RoutingProtocol::Start ()
{
  NS_LOG_FUNCTION (this);
  if (EnableHello)
    {
      m_nb.ScheduleTimer ();
    }
  m_rreqRateLimitTimer.SetFunction (&RoutingProtocol::RreqRateLimitTimerExpire,
                                    this);
  m_rreqRateLimitTimer.Schedule (Seconds (1));

  m_rerrRateLimitTimer.SetFunction (&RoutingProtocol::RerrRateLimitTimerExpire,
                                    this);
  m_rerrRateLimitTimer.Schedule (Seconds (1));

}

Ptr<Ipv4Route>
RoutingProtocol::RouteOutput (Ptr<Packet> p, const Ipv4Header &header,
                              Ptr<NetDevice> oif, Socket::SocketErrno &sockerr)
{
  NS_LOG_FUNCTION (this << header << (oif ? oif->GetIfIndex () : 0));
  if (!p)
    {
      NS_LOG_DEBUG("Packet is == 0");
      return LoopbackRoute (header, oif); // later
    }
  if (m_socketAddresses.empty ())
    {
      sockerr = Socket::ERROR_NOROUTETOHOST;
      NS_LOG_LOGIC ("No aodv interfaces");
      Ptr<Ipv4Route> route;
      return route;
    }
  sockerr = Socket::ERROR_NOTERROR;
  Ptr<Ipv4Route> route;
  Ipv4Address dst = header.GetDestination ();
  RoutingTableEntry rt;
  if (m_routingTable.LookupValidRoute (dst, rt))
    {
      route = rt.GetRoute ();
      NS_ASSERT (route != 0);
      NS_LOG_DEBUG ("Exist route to " << route->GetDestination () << " from interface " << route->GetSource ());
      if (oif != 0 && route->GetOutputDevice () != oif)
        {
          NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
          sockerr = Socket::ERROR_NOROUTETOHOST;
          return Ptr<Ipv4Route> ();
        }
      UpdateRouteLifeTime (dst, ActiveRouteTimeout);
      UpdateRouteLifeTime (route->GetGateway (), ActiveRouteTimeout);
      return route;
    }

  // Valid route not found, in this case we return loopback. 
  // Actual route request will be deferred until packet will be fully formed, 
  // routed to loopback, received from loopback and passed to RouteInput (see below)
  uint32_t iif = (oif ? m_ipv4->GetInterfaceForDevice (oif) : -1);
  DeferredRouteOutputTag tag (iif);
  NS_LOG_DEBUG ("Valid Route not found");
  if (!p->PeekPacketTag (tag))
    {
      p->AddPacketTag (tag);
    }
  return LoopbackRoute (header, oif);
}

void
RoutingProtocol::DeferredRouteOutput (Ptr<const Packet> p, const Ipv4Header & header, 
                                      UnicastForwardCallback ucb, ErrorCallback ecb)
{
  NS_LOG_FUNCTION (this << p << header);
  NS_ASSERT (p != 0 && p != Ptr<Packet> ());

  QueueEntry newEntry (p, header, ucb, ecb);
  bool result = m_queue.Enqueue (newEntry);
  if (result)
    {
      NS_LOG_LOGIC ("Add packet " << p->GetUid () << " to queue. Protocol " << (uint16_t) header.GetProtocol ());
      RoutingTableEntry rt;
      bool result = m_routingTable.LookupRoute (header.GetDestination (), rt);
      if(!result || ((rt.GetFlag () != IN_SEARCH) && result))
        {
          NS_LOG_LOGIC ("Send new RREQ for outbound packet to " <<header.GetDestination ());
          SendRequest (header.GetDestination ());
        }
    }
}

bool
RoutingProtocol::RouteInput (Ptr<const Packet> p, const Ipv4Header &header,
                             Ptr<const NetDevice> idev, UnicastForwardCallback ucb,
                             MulticastForwardCallback mcb, LocalDeliverCallback lcb, ErrorCallback ecb)
{
  NS_LOG_FUNCTION (this << p->GetUid () << header.GetDestination () << idev->GetAddress ());
  if (m_socketAddresses.empty ())
    {
      NS_LOG_LOGIC ("No aodv interfaces");
      return false;
    }
  NS_ASSERT (m_ipv4 != 0);
  NS_ASSERT (p != 0);
  // Check if input device supports IP
  NS_ASSERT (m_ipv4->GetInterfaceForDevice (idev) >= 0);
  int32_t iif = m_ipv4->GetInterfaceForDevice (idev);

  Ipv4Address dst = header.GetDestination ();
  Ipv4Address origin = header.GetSource ();

  // Deferred route request
  if (idev == m_lo)
    {
      DeferredRouteOutputTag tag;
      if (p->PeekPacketTag (tag))
        {
          DeferredRouteOutput (p, header, ucb, ecb);
          return true;
        }
    }

  // Duplicate of own packet
  if (IsMyOwnAddress (origin))
    return true;

  // AODV is not a multicast routing protocol
  if (dst.IsMulticast ())
    {
      return false; 
    }

  // Broadcast local delivery/forwarding
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ipv4InterfaceAddress iface = j->second;
      if (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()) == iif)
        if (dst == iface.GetBroadcast () || dst.IsBroadcast ())
          {
            if (m_dpd.IsDuplicate (p, header))
              {
                NS_LOG_DEBUG ("Duplicated packet " << p->GetUid () << " from " << origin << ". Drop.");
                return true;
              }
            UpdateRouteLifeTime (origin, ActiveRouteTimeout);
            Ptr<Packet> packet = p->Copy ();
            if (lcb.IsNull () == false)
              {
                NS_LOG_LOGIC ("Broadcast local delivery to " << iface.GetLocal ());
                lcb (p, header, iif);
                // Fall through to additional processing
              }
            else
              {
                NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
                ecb (p, header, Socket::ERROR_NOROUTETOHOST);
              }
            if (!EnableBroadcast)
              {
                return true;
              }
            if (header.GetTtl () > 1)
              {
                NS_LOG_LOGIC ("Forward broadcast. TTL " << (uint16_t) header.GetTtl ());
                RoutingTableEntry toBroadcast;
                if (m_routingTable.LookupRoute (dst, toBroadcast))
                  {
                    Ptr<Ipv4Route> route = toBroadcast.GetRoute ();
                    ucb (route, packet, header);
                  }
                else
                  {
                    NS_LOG_DEBUG ("No route to forward broadcast. Drop packet " << p->GetUid ());
                  }
              }
            else
              {
                NS_LOG_DEBUG ("TTL exceeded. Drop packet " << p->GetUid ());
              }
            return true;
          }
    }

  // Unicast local delivery
  if (m_ipv4->IsDestinationAddress (dst, iif))
    {
      UpdateRouteLifeTime (origin, ActiveRouteTimeout);
      RoutingTableEntry toOrigin;
      if (m_routingTable.LookupValidRoute (origin, toOrigin))
        {
          UpdateRouteLifeTime (toOrigin.GetNextHop (), ActiveRouteTimeout);
          m_nb.Update (toOrigin.GetNextHop (), ActiveRouteTimeout);
        }
      if (lcb.IsNull () == false)
        {
          NS_LOG_LOGIC ("Unicast local delivery to " << dst);
          lcb (p, header, iif);
        }
      else
        {
          NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
          ecb (p, header, Socket::ERROR_NOROUTETOHOST);
        }
      return true;
    }

  // Forwarding
  return Forwarding (p, header, ucb, ecb);
}

bool
RoutingProtocol::Forwarding (Ptr<const Packet> p, const Ipv4Header & header,
                             UnicastForwardCallback ucb, ErrorCallback ecb)
{
  NS_LOG_FUNCTION (this);
  Ipv4Address dst = header.GetDestination ();
  Ipv4Address origin = header.GetSource ();
  m_routingTable.Purge ();
  RoutingTableEntry toDst;
  if (m_routingTable.LookupRoute (dst, toDst))
    {
      if (toDst.GetFlag () == VALID)
        {
          Ptr<Ipv4Route> route = toDst.GetRoute ();
          NS_LOG_LOGIC (route->GetSource ()<<" forwarding to " << dst << " from " << origin << " packet " << p->GetUid ());

          /*
           *  Each time a route is used to forward a data packet, its Active Route
           *  Lifetime field of the source, destination and the next hop on the
           *  path to the destination is updated to be no less than the current
           *  time plus ActiveRouteTimeout.
           */
          UpdateRouteLifeTime (origin, ActiveRouteTimeout);
          UpdateRouteLifeTime (dst, ActiveRouteTimeout);
          UpdateRouteLifeTime (route->GetGateway (), ActiveRouteTimeout);
          /*
           *  Since the route between each originator and destination pair is expected to be symmetric, the
           *  Active Route Lifetime for the previous hop, along the reverse path back to the IP source, is also updated
           *  to be no less than the current time plus ActiveRouteTimeout
           */
          RoutingTableEntry toOrigin;
          m_routingTable.LookupRoute (origin, toOrigin);
          UpdateRouteLifeTime (toOrigin.GetNextHop (), ActiveRouteTimeout);

          m_nb.Update (route->GetGateway (), ActiveRouteTimeout);
          m_nb.Update (toOrigin.GetNextHop (), ActiveRouteTimeout);

          ucb (route, p, header);
          return true;
        }
      else
        {
          if (toDst.GetValidSeqNo ())
            {
              SendRerrWhenNoRouteToForward (dst, toDst.GetSeqNo (), origin);
              NS_LOG_DEBUG ("Drop packet " << p->GetUid () << " because no route to forward it.");
              return false;
            }
        }
    }
  NS_LOG_LOGIC ("route not found to "<< dst << ". Send RERR message.");
  NS_LOG_DEBUG ("Drop packet " << p->GetUid () << " because no route to forward it.");
  SendRerrWhenNoRouteToForward (dst, 0, origin);
  return false;
}

void
RoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  NS_ASSERT (ipv4 != 0);
  NS_ASSERT (m_ipv4 == 0);

  m_ipv4 = ipv4;

  // Create lo route. It is asserted that the only one interface up for now is loopback
  NS_ASSERT (m_ipv4->GetNInterfaces () == 1 && m_ipv4->GetAddress (0, 0).GetLocal () == Ipv4Address ("127.0.0.1"));
  m_lo = m_ipv4->GetNetDevice (0);
  NS_ASSERT (m_lo != 0);
  // Remember lo route
  RoutingTableEntry rt (/*device=*/ m_lo, /*dst=*/ Ipv4Address::GetLoopback (), /*know seqno=*/ true, /*seqno=*/ 0,
                                    /*iface=*/ Ipv4InterfaceAddress (Ipv4Address::GetLoopback (), Ipv4Mask ("255.0.0.0")),
                                    /*hops=*/ 1, /*next hop=*/ Ipv4Address::GetLoopback (),
                                    /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  m_routingTable.AddRoute (rt);

  Simulator::ScheduleNow (&RoutingProtocol::Start, this);
}

void
RoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
  NS_LOG_FUNCTION (this << m_ipv4->GetAddress (i, 0).GetLocal ());
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  if (l3->GetNAddresses (i) > 1)
    {
      NS_LOG_WARN ("AODV does not work with more then one address per each interface.");
    }
  Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
  if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
    return;
 
  // Create a socket to listen only on this interface
  Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                             UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
  socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), AODV_PORT));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->SetAllowBroadcast (true);
  socket->SetAttribute ("IpTtl", UintegerValue (1));
  m_socketAddresses.insert (std::make_pair (socket, iface));

  // create also a subnet broadcast socket
  socket = Socket::CreateSocket (GetObject<Node> (),
                                 UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
  socket->Bind (InetSocketAddress (iface.GetBroadcast (), AODV_PORT));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->SetAllowBroadcast (true);
  socket->SetAttribute ("IpTtl", UintegerValue (1));
  m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

  // Add local broadcast record to the routing table
  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
  RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true, /*seqno=*/ 0, /*iface=*/ iface,
                                    /*hops=*/ 1, /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  m_routingTable.AddRoute (rt);

  if (l3->GetInterface (i)->GetArpCache ())
    {
      m_nb.AddArpCache (l3->GetInterface (i)->GetArpCache ());
    }

  // Allow neighbor manager use this interface for layer 2 feedback if possible
  Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice> ();
  if (wifi == 0)
    return;
  Ptr<WifiMac> mac = wifi->GetMac ();
  if (mac == 0)
    return;

  mac->TraceConnectWithoutContext ("TxErrHeader", m_nb.GetTxErrorCallback ());
}

void
RoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
  NS_LOG_FUNCTION (this << m_ipv4->GetAddress (i, 0).GetLocal ());

  // Disable layer 2 link state monitoring (if possible)
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  Ptr<NetDevice> dev = l3->GetNetDevice (i);
  Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice> ();
  if (wifi != 0)
    {
      Ptr<WifiMac> mac = wifi->GetMac ()->GetObject<AdhocWifiMac> ();
      if (mac != 0)
        {
          mac->TraceDisconnectWithoutContext ("TxErrHeader",
                                              m_nb.GetTxErrorCallback ());
          m_nb.DelArpCache (l3->GetInterface (i)->GetArpCache ());
        }
    }

  // Close socket 
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (m_ipv4->GetAddress (i, 0));
  NS_ASSERT (socket);
  socket->Close ();
  m_socketAddresses.erase (socket);

  // Close socket
  socket = FindSubnetBroadcastSocketWithInterfaceAddress (m_ipv4->GetAddress (i, 0));
  NS_ASSERT (socket);
  socket->Close ();
  m_socketSubnetBroadcastAddresses.erase (socket);

  if (m_socketAddresses.empty ())
    {
      NS_LOG_LOGIC ("No aodv interfaces");
      m_htimer.Cancel ();
      m_nb.Clear ();
      m_routingTable.Clear ();
      return;
    }
  m_routingTable.DeleteAllRoutesFromInterface (m_ipv4->GetAddress (i, 0));
}

void
RoutingProtocol::NotifyAddAddress (uint32_t i, Ipv4InterfaceAddress address)
{
  NS_LOG_FUNCTION (this << " interface " << i << " address " << address);
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  if (!l3->IsUp (i))
    return;
  if (l3->GetNAddresses (i) == 1)
    {
      Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (iface);
      if (!socket)
        {
          if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
            return;
          // Create a socket to listen only on this interface
          Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                                     UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv,this));
          socket->Bind (InetSocketAddress (iface.GetLocal (), AODV_PORT));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->SetAllowBroadcast (true);
          m_socketAddresses.insert (std::make_pair (socket, iface));

          // create also a subnet directed broadcast socket
          socket = Socket::CreateSocket (GetObject<Node> (),
                                                       UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
          socket->Bind (InetSocketAddress (iface.GetBroadcast (), AODV_PORT));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->SetAllowBroadcast (true);
          socket->SetAttribute ("IpTtl", UintegerValue (1));
          m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

          // Add local broadcast record to the routing table
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice (
              m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
          RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true,
                                            /*seqno=*/ 0, /*iface=*/ iface, /*hops=*/ 1,
                                            /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
          m_routingTable.AddRoute (rt);
        }
    }
  else
    {
      NS_LOG_LOGIC ("AODV does not work with more then one address per each interface. Ignore added address");
    }
}

void
RoutingProtocol::NotifyRemoveAddress (uint32_t i, Ipv4InterfaceAddress address)
{
  NS_LOG_FUNCTION (this);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (address);
  if (socket)
    {
      m_routingTable.DeleteAllRoutesFromInterface (address);
      socket->Close ();
      m_socketAddresses.erase (socket);

      Ptr<Socket> unicastSocket = FindSubnetBroadcastSocketWithInterfaceAddress (address);
      if (unicastSocket)
        {
          unicastSocket->Close ();
          m_socketAddresses.erase (unicastSocket);
        }

      Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
      if (l3->GetNAddresses (i))
        {
          Ipv4InterfaceAddress iface = l3->GetAddress (i, 0);
          // Create a socket to listen only on this interface
          Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),
                                                     UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
          // Bind to any IP address so that broadcasts can be received
          socket->Bind (InetSocketAddress (iface.GetLocal (), AODV_PORT));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->SetAllowBroadcast (true);
          socket->SetAttribute ("IpTtl", UintegerValue (1));
          m_socketAddresses.insert (std::make_pair (socket, iface));

          // create also a unicast socket
          socket = Socket::CreateSocket (GetObject<Node> (),
                                                       UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvAodv, this));
          socket->Bind (InetSocketAddress (iface.GetBroadcast (), AODV_PORT));
          socket->BindToNetDevice (l3->GetNetDevice (i));
          socket->SetAllowBroadcast (true);
          socket->SetAttribute ("IpTtl", UintegerValue (1));
          m_socketSubnetBroadcastAddresses.insert (std::make_pair (socket, iface));

          // Add local broadcast record to the routing table
          Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
          RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*know seqno=*/ true, /*seqno=*/ 0, /*iface=*/ iface,
                                            /*hops=*/ 1, /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
          m_routingTable.AddRoute (rt);
        }
      if (m_socketAddresses.empty ())
        {
          NS_LOG_LOGIC ("No aodv interfaces");
          m_htimer.Cancel ();
          m_nb.Clear ();
          m_routingTable.Clear ();
          return;
        }
    }
  else
    {
      NS_LOG_LOGIC ("Remove address not participating in AODV operation");
    }
}

bool
RoutingProtocol::IsMyOwnAddress (Ipv4Address src)
{
  NS_LOG_FUNCTION (this << src);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ipv4InterfaceAddress iface = j->second;
      if (src == iface.GetLocal ())
        {
          return true;
        }
    }
  return false;
}

Ptr<Ipv4Route> 
RoutingProtocol::LoopbackRoute (const Ipv4Header & hdr, Ptr<NetDevice> oif) const
{
  NS_LOG_FUNCTION (this << hdr);
  NS_ASSERT (m_lo != 0);
  Ptr<Ipv4Route> rt = Create<Ipv4Route> ();
  rt->SetDestination (hdr.GetDestination ());
  //
  // Source address selection here is tricky.  The loopback route is
  // returned when AODV does not have a route; this causes the packet
  // to be looped back and handled (cached) in RouteInput() method
  // while a route is found. However, connection-oriented protocols
  // like TCP need to create an endpoint four-tuple (src, src port,
  // dst, dst port) and create a pseudo-header for checksumming.  So,
  // AODV needs to guess correctly what the eventual source address
  // will be.
  //
  // For single interface, single address nodes, this is not a problem.
  // When there are possibly multiple outgoing interfaces, the policy
  // implemented here is to pick the first available AODV interface.
  // If RouteOutput() caller specified an outgoing interface, that 
  // further constrains the selection of source address
  //
  std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
  if (oif)
    {
      // Iterate to find an address on the oif device
      for (j = m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
        {
          Ipv4Address addr = j->second.GetLocal ();
          int32_t interface = m_ipv4->GetInterfaceForAddress (addr);
          if (oif == m_ipv4->GetNetDevice (static_cast<uint32_t> (interface)))
            {
              rt->SetSource (addr);
              break;
            }
        }
    }
  else
    {
      rt->SetSource (j->second.GetLocal ());
    }
  NS_ASSERT_MSG (rt->GetSource () != Ipv4Address (), "Valid AODV source address not found");
  rt->SetGateway (Ipv4Address ("127.0.0.1"));
  rt->SetOutputDevice (m_lo);
  return rt;
}

void
RoutingProtocol::SendRequest (Ipv4Address dst)
{
  NS_LOG_FUNCTION ( this << dst);
  // A node SHOULD NOT originate more than RREQ_RATELIMIT RREQ messages per second.
  if (m_rreqCount == RreqRateLimit)
    {
      Simulator::Schedule (m_rreqRateLimitTimer.GetDelayLeft () + MicroSeconds (100),
                           &RoutingProtocol::SendRequest, this, dst);
      return;
    }
  else
    m_rreqCount++;
  // Create RREQ header
  RreqHeader rreqHeader;
  rreqHeader.SetDst (dst);

  RoutingTableEntry rt;
  if (m_routingTable.LookupRoute (dst, rt))
    {
      rreqHeader.SetHopCount (rt.GetHop ());
      if (rt.GetValidSeqNo ())
        rreqHeader.SetDstSeqno (rt.GetSeqNo ());
      else
        rreqHeader.SetUnknownSeqno (true);
      rt.SetFlag (IN_SEARCH);
      m_routingTable.Update (rt);
    }
  else
    {
      rreqHeader.SetUnknownSeqno (true);
      Ptr<NetDevice> dev = 0;
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ dst, /*validSeqNo=*/ false, /*seqno=*/ 0,
                                              /*iface=*/ Ipv4InterfaceAddress (),/*hop=*/ 0,
                                              /*nextHop=*/ Ipv4Address (), /*lifeTime=*/ Seconds (0));
      newEntry.SetFlag (IN_SEARCH);
      m_routingTable.AddRoute (newEntry);
    }

  if (GratuitousReply)
    rreqHeader.SetGratiousRrep (true);
  if (DestinationOnly)
    rreqHeader.SetDestinationOnly (true);

  m_seqNo++;
  rreqHeader.SetOriginSeqno (m_seqNo);
  m_requestId++;
  rreqHeader.SetId (m_requestId);
  rreqHeader.SetHopCount (0);

  // Send RREQ as subnet directed broadcast from each interface used by aodv
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;

      rreqHeader.SetOrigin (iface.GetLocal ());
      m_rreqIdCache.IsDuplicate (iface.GetLocal (), m_requestId);

      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (rreqHeader);
      TypeHeader tHeader (AODVTYPE_RREQ);
      packet->AddHeader (tHeader);
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        { 
          destination = iface.GetBroadcast ();
        }
      NS_LOG_DEBUG ("Send RREQ with id " << rreqHeader.GetId () << " to socket");
      m_lastBcastTime = Simulator::Now ();
      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, destination); 
    }
  ScheduleRreqRetry (dst);
}

void
RoutingProtocol::SendTo (Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination)
{
    socket->SendTo (packet, 0, InetSocketAddress (destination, AODV_PORT));

}
void
RoutingProtocol::ScheduleRreqRetry (Ipv4Address dst)
{
  NS_LOG_FUNCTION (this << dst);
  if (m_addressReqTimer.find (dst) == m_addressReqTimer.end ())
    {
      Timer timer (Timer::CANCEL_ON_DESTROY);
      m_addressReqTimer[dst] = timer;
    }
  m_addressReqTimer[dst].SetFunction (&RoutingProtocol::RouteRequestTimerExpire, this);
  m_addressReqTimer[dst].Remove ();
  m_addressReqTimer[dst].SetArguments (dst);
  RoutingTableEntry rt;
  m_routingTable.LookupRoute (dst, rt);
  rt.IncrementRreqCnt ();
  m_routingTable.Update (rt);
  m_addressReqTimer[dst].Schedule (Time (rt.GetRreqCnt () * NetTraversalTime));
  NS_LOG_LOGIC ("Scheduled RREQ retry in " << Time (rt.GetRreqCnt () * NetTraversalTime).GetSeconds () << " seconds");
}

void
RoutingProtocol::RecvAodv (Ptr<Socket> socket)
{
  CommandPacketCount++;
  NS_LOG_FUNCTION (this << socket);
  Address sourceAddress;
  Ptr<Packet> packet = socket->RecvFrom (sourceAddress);
  InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom (sourceAddress);
  Ipv4Address sender = inetSourceAddr.GetIpv4 ();
  Ipv4Address receiver;

  if (m_socketAddresses.find (socket) != m_socketAddresses.end ())
    {
      receiver = m_socketAddresses[socket].GetLocal ();
    }
  else if(m_socketSubnetBroadcastAddresses.find (socket) != m_socketSubnetBroadcastAddresses.end ())
    {
      receiver = m_socketSubnetBroadcastAddresses[socket].GetLocal ();
    }
  else
    {
      NS_ASSERT_MSG (false, "Received a packet from an unknown socket");
    }
  NS_LOG_DEBUG ("AODV node " << this << " received a AODV packet from " << sender << " to " << receiver);

  UpdateRouteToNeighbor (sender, receiver);
  TypeHeader tHeader (AODVTYPE_RREQ);
  packet->RemoveHeader (tHeader);
  if (!tHeader.IsValid ())
    {
      NS_LOG_DEBUG ("AODV message " << packet->GetUid () << " with unknown type received: " << tHeader.Get () << ". Drop");
      return; // drop
    }
  switch (tHeader.Get ())
    {
    case AODVTYPE_RREQ:
      {
        RecvRequest (packet, receiver, sender);
        break;
      }
    case AODVTYPE_RREP:
      {
        RecvReply (packet, receiver, sender);
        break;
      }
    case AODVTYPE_RERR:
      {
        RecvError (packet, sender);
        break;
      }
    case AODVTYPE_RREP_ACK:
      {
        RecvReplyAck (sender);
        break;
      }
    }
}

bool
RoutingProtocol::UpdateRouteLifeTime (Ipv4Address addr, Time lifetime)
{
  NS_LOG_FUNCTION (this << addr << lifetime);
  RoutingTableEntry rt;
  if (m_routingTable.LookupRoute (addr, rt))
    {
      if (rt.GetFlag () == VALID)
        {
          NS_LOG_DEBUG ("Updating VALID route");
          rt.SetRreqCnt (0);
          rt.SetLifeTime (std::max (lifetime, rt.GetLifeTime ()));
          m_routingTable.Update (rt);
          return true;
        }
    }
  return false;
}

void
RoutingProtocol::UpdateRouteToNeighbor (Ipv4Address sender, Ipv4Address receiver)
{
  NS_LOG_FUNCTION (this << "sender " << sender << " receiver " << receiver);
  RoutingTableEntry toNeighbor;
  if (!m_routingTable.LookupRoute (sender, toNeighbor))
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ sender, /*know seqno=*/ false, /*seqno=*/ 0,
                                              /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                              /*hops=*/ 1, /*next hop=*/ sender, /*lifetime=*/ ActiveRouteTimeout);
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      if (toNeighbor.GetValidSeqNo () && (toNeighbor.GetHop () == 1) && (toNeighbor.GetOutputDevice () == dev))
        {
          toNeighbor.SetLifeTime (std::max (ActiveRouteTimeout, toNeighbor.GetLifeTime ()));
        }
      else
        {
          RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ sender, /*know seqno=*/ false, /*seqno=*/ 0,
                                                  /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                                  /*hops=*/ 1, /*next hop=*/ sender, /*lifetime=*/ std::max (ActiveRouteTimeout, toNeighbor.GetLifeTime ()));
          m_routingTable.Update (newEntry);
        }
    }

}

void
RoutingProtocol::RecvRequest (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src)
{
  NS_LOG_FUNCTION (this);
  RreqHeader rreqHeader;
  p->RemoveHeader (rreqHeader);

  // A node ignores all RREQs received from any node in its blacklist
  RoutingTableEntry toPrev;
  if (m_routingTable.LookupRoute (src, toPrev))
    {
      if (toPrev.IsUnidirectional ())
        {
          NS_LOG_DEBUG ("Ignoring RREQ from node in blacklist");
          return;
        }
    }

  uint32_t id = rreqHeader.GetId ();
  Ipv4Address origin = rreqHeader.GetOrigin ();

  /*
   *  Node checks to determine whether it has received a RREQ with the same Originator IP Address and RREQ ID.
   *  If such a RREQ has been received, the node silently discards the newly received RREQ.
   */
  if (m_rreqIdCache.IsDuplicate (origin, id))
    {
      NS_LOG_DEBUG ("Ignoring RREQ due to duplicate");
      return;
    }

  // Increment RREQ hop count
  uint8_t hop = rreqHeader.GetHopCount () + 1;
  rreqHeader.SetHopCount (hop);

  /*
   *  When the reverse route is created or updated, the following actions on the route are also carried out:
   *  1. the Originator Sequence Number from the RREQ is compared to the corresponding destination sequence number
   *     in the route table entry and copied if greater than the existing value there
   *  2. the valid sequence number field is set to true;
   *  3. the next hop in the routing table becomes the node from which the  RREQ was received
   *  4. the hop count is copied from the Hop Count in the RREQ message;
   *  5. the Lifetime is set to be the maximum of (ExistingLifetime, MinimalLifetime), where
   *     MinimalLifetime = current time + 2*NetTraversalTime - 2*HopCount*NodeTraversalTime
   */
  RoutingTableEntry toOrigin;
  if (!m_routingTable.LookupRoute (origin, toOrigin))
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ origin, /*validSeno=*/ true, /*seqNo=*/ rreqHeader.GetOriginSeqno (),
                                              /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0), /*hops=*/ hop,
                                              /*nextHop*/ src, /*timeLife=*/ Time ((2 * NetTraversalTime - 2 * hop * NodeTraversalTime)));
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      if (toOrigin.GetValidSeqNo ())
        {
          if (int32_t (rreqHeader.GetOriginSeqno ()) - int32_t (toOrigin.GetSeqNo ()) > 0)
            toOrigin.SetSeqNo (rreqHeader.GetOriginSeqno ());
        }
      else
        toOrigin.SetSeqNo (rreqHeader.GetOriginSeqno ());
      toOrigin.SetValidSeqNo (true);
      toOrigin.SetNextHop (src);
      toOrigin.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toOrigin.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toOrigin.SetHop (hop);
      toOrigin.SetLifeTime (std::max (Time (2 * NetTraversalTime - 2 * hop * NodeTraversalTime),
                                      toOrigin.GetLifeTime ()));
      m_routingTable.Update (toOrigin);
      //m_nb.Update (src, Time (AllowedHelloLoss * HelloInterval));
    }


  RoutingTableEntry toNeighbor;
  if (!m_routingTable.LookupRoute (src, toNeighbor))
    {
      NS_LOG_DEBUG ("Neighbor:" << src << " not found in routing table. Creating an entry"); 
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (dev, src, false, rreqHeader.GetOriginSeqno (),
                                              m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                              1, src, ActiveRouteTimeout);
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      toNeighbor.SetLifeTime (ActiveRouteTimeout);
      toNeighbor.SetValidSeqNo (false);
      toNeighbor.SetSeqNo (rreqHeader.GetOriginSeqno ()); 
      toNeighbor.SetFlag (VALID);
      toNeighbor.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toNeighbor.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toNeighbor.SetHop (1);
      toNeighbor.SetNextHop (src);
      m_routingTable.Update (toNeighbor);
    }
  m_nb.Update (src, Time (AllowedHelloLoss * HelloInterval));

  NS_LOG_LOGIC (receiver << " receive RREQ with hop count " << static_cast<uint32_t>(rreqHeader.GetHopCount ()) 
                         << " ID " << rreqHeader.GetId ()
                         << " to destination " << rreqHeader.GetDst ());

  //  A node generates a RREP if either:
  //  (i)  it is itself the destination,
  if (IsMyOwnAddress (rreqHeader.GetDst ()))
    {
      m_routingTable.LookupRoute (origin, toOrigin);
      NS_LOG_DEBUG ("Send reply since I am the destination");
      SendReply (rreqHeader, toOrigin);
      return;
    }
  /*
   * (ii) or it has an active route to the destination, the destination sequence number in the node's existing route table entry for the destination
   *      is valid and greater than or equal to the Destination Sequence Number of the RREQ, and the "destination only" flag is NOT set.
   */
  RoutingTableEntry toDst;
  Ipv4Address dst = rreqHeader.GetDst ();
  if (m_routingTable.LookupRoute (dst, toDst))
    {
      /*
       * Drop RREQ, This node RREP wil make a loop.
       */
      if (toDst.GetNextHop () == src)
        {
          NS_LOG_DEBUG ("Drop RREQ from " << src << ", dest next hop " << toDst.GetNextHop ());
          return;
        }
      /*
       * The Destination Sequence number for the requested destination is set to the maximum of the corresponding value
       * received in the RREQ message, and the destination sequence value currently maintained by the node for the requested destination.
       * However, the forwarding node MUST NOT modify its maintained value for the destination sequence number, even if the value
       * received in the incoming RREQ is larger than the value currently maintained by the forwarding node.
       */
      if ((rreqHeader.GetUnknownSeqno () || (int32_t (toDst.GetSeqNo ()) - int32_t (rreqHeader.GetDstSeqno ()) >= 0))
          && toDst.GetValidSeqNo () )
        {
          if (!rreqHeader.GetDestinationOnly () && toDst.GetFlag () == VALID)
            {
              m_routingTable.LookupRoute (origin, toOrigin);
              SendReplyByIntermediateNode (toDst, toOrigin, rreqHeader.GetGratiousRrep ());
              return;
            }
          rreqHeader.SetDstSeqno (toDst.GetSeqNo ());
          rreqHeader.SetUnknownSeqno (false);
        }
    }

  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (rreqHeader);
      TypeHeader tHeader (AODVTYPE_RREQ);
      packet->AddHeader (tHeader);
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        { 
          destination = iface.GetBroadcast ();
        }
      m_lastBcastTime = Simulator::Now ();
      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, destination); 

    }
}

void
RoutingProtocol::SendReply (RreqHeader const & rreqHeader, RoutingTableEntry const & toOrigin)
{
  NS_LOG_FUNCTION (this << toOrigin.GetDestination ());
  /*
   * Destination node MUST increment its own sequence number by one if the sequence number in the RREQ packet is equal to that
   * incremented value. Otherwise, the destination does not change its sequence number before generating the  RREP message.
   */
  if (!rreqHeader.GetUnknownSeqno () && (rreqHeader.GetDstSeqno () == m_seqNo + 1))
    m_seqNo++;
  RrepHeader rrepHeader ( /*prefixSize=*/ 0, /*hops=*/ 0, /*dst=*/ rreqHeader.GetDst (),
                                          /*dstSeqNo=*/ m_seqNo, /*origin=*/ toOrigin.GetDestination (), /*lifeTime=*/ MyRouteTimeout);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));
}

void
RoutingProtocol::SendReplyByIntermediateNode (RoutingTableEntry & toDst, RoutingTableEntry & toOrigin, bool gratRep)
{
  NS_LOG_FUNCTION (this);
  RrepHeader rrepHeader (/*prefix size=*/ 0, /*hops=*/ toDst.GetHop (), /*dst=*/ toDst.GetDestination (), /*dst seqno=*/ toDst.GetSeqNo (),
                                          /*origin=*/ toOrigin.GetDestination (), /*lifetime=*/ toDst.GetLifeTime ());
  /* If the node we received a RREQ for is a neighbor we are
   * probably facing a unidirectional link... Better request a RREP-ack
   */
  if (toDst.GetHop () == 1)
    {
      rrepHeader.SetAckRequired (true);
      RoutingTableEntry toNextHop;
      m_routingTable.LookupRoute (toOrigin.GetNextHop (), toNextHop);
      toNextHop.m_ackTimer.SetFunction (&RoutingProtocol::AckTimerExpire, this);
      toNextHop.m_ackTimer.SetArguments (toNextHop.GetDestination (), BlackListTimeout);
      toNextHop.m_ackTimer.SetDelay (NextHopWait);
    }
  toDst.InsertPrecursor (toOrigin.GetNextHop ());
  toOrigin.InsertPrecursor (toDst.GetNextHop ());
  m_routingTable.Update (toDst);
  m_routingTable.Update (toOrigin);

  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));

  // Generating gratuitous RREPs
  if (gratRep)
    {
      RrepHeader gratRepHeader (/*prefix size=*/ 0, /*hops=*/ toOrigin.GetHop (), /*dst=*/ toOrigin.GetDestination (),
                                                 /*dst seqno=*/ toOrigin.GetSeqNo (), /*origin=*/ toDst.GetDestination (),
                                                 /*lifetime=*/ toOrigin.GetLifeTime ());
      Ptr<Packet> packetToDst = Create<Packet> ();
      packetToDst->AddHeader (gratRepHeader);
      TypeHeader type (AODVTYPE_RREP);
      packetToDst->AddHeader (type);
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (toDst.GetInterface ());
      NS_ASSERT (socket);
      NS_LOG_LOGIC ("Send gratuitous RREP " << packet->GetUid ());
      socket->SendTo (packetToDst, 0, InetSocketAddress (toDst.GetNextHop (), AODV_PORT));
    }
}

void
RoutingProtocol::SendReplyAck (Ipv4Address neighbor)
{
  NS_LOG_FUNCTION (this << " to " << neighbor);
  RrepAckHeader h;
  TypeHeader typeHeader (AODVTYPE_RREP_ACK);
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (h);
  packet->AddHeader (typeHeader);
  RoutingTableEntry toNeighbor;
  m_routingTable.LookupRoute (neighbor, toNeighbor);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toNeighbor.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (neighbor, AODV_PORT));
}

void
RoutingProtocol::RecvReply (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address sender)
{
  NS_LOG_FUNCTION (this << " src " << sender);
  RrepHeader rrepHeader;
  p->RemoveHeader (rrepHeader);
  Ipv4Address dst = rrepHeader.GetDst ();
  NS_LOG_LOGIC ("RREP destination " << dst << " RREP origin " << rrepHeader.GetOrigin ());

  uint8_t hop = rrepHeader.GetHopCount () + 1;
  rrepHeader.SetHopCount (hop);

  // If RREP is Hello message
  if (dst == rrepHeader.GetOrigin ())
    {
      ProcessHello (rrepHeader, receiver);
      return;
    }

  /*
   * If the route table entry to the destination is created or updated, then the following actions occur:
   * -  the route is marked as active,
   * -  the destination sequence number is marked as valid,
   * -  the next hop in the route entry is assigned to be the node from which the RREP is received,
   *    which is indicated by the source IP address field in the IP header,
   * -  the hop count is set to the value of the hop count from RREP message + 1
   * -  the expiry time is set to the current time plus the value of the Lifetime in the RREP message,
   * -  and the destination sequence number is the Destination Sequence Number in the RREP message.
   */
  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
  RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ dst, /*validSeqNo=*/ true, /*seqno=*/ rrepHeader.GetDstSeqno (),
                                          /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),/*hop=*/ hop,
                                          /*nextHop=*/ sender, /*lifeTime=*/ rrepHeader.GetLifeTime ());
  RoutingTableEntry toDst;
  if (m_routingTable.LookupRoute (dst, toDst))
    {
      /*
       * The existing entry is updated only in the following circumstances:
       * (i) the sequence number in the routing table is marked as invalid in route table entry.
       */
      if (!toDst.GetValidSeqNo ())
        {
          m_routingTable.Update (newEntry);
        }
      // (ii)the Destination Sequence Number in the RREP is greater than the node's copy of the destination sequence number and the known value is valid,
      else if ((int32_t (rrepHeader.GetDstSeqno ()) - int32_t (toDst.GetSeqNo ())) > 0)
        {
          m_routingTable.Update (newEntry);
        }
      else
        {
          // (iii) the sequence numbers are the same, but the route is marked as inactive.
          if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (toDst.GetFlag () != VALID))
            {
              m_routingTable.Update (newEntry);
            }
          // (iv)  the sequence numbers are the same, and the New Hop Count is smaller than the hop count in route table entry.
          else if ((rrepHeader.GetDstSeqno () == toDst.GetSeqNo ()) && (hop < toDst.GetHop ()))
            {
              m_routingTable.Update (newEntry);
            }
        }
    }
  else
    {
      // The forward route for this destination is created if it does not already exist.
      NS_LOG_LOGIC ("add new route");
      m_routingTable.AddRoute (newEntry);
    }
  // Acknowledge receipt of the RREP by sending a RREP-ACK message back
  if (rrepHeader.GetAckRequired ())
    {
      SendReplyAck (sender);
      rrepHeader.SetAckRequired (false);
    }
  NS_LOG_LOGIC ("receiver " << receiver << " origin " << rrepHeader.GetOrigin ());
  if (IsMyOwnAddress (rrepHeader.GetOrigin ()))
    {
      if (toDst.GetFlag () == IN_SEARCH)
        {
          m_routingTable.Update (newEntry);
          m_addressReqTimer[dst].Remove ();
          m_addressReqTimer.erase (dst);
        }
      m_routingTable.LookupRoute (dst, toDst);
      SendPacketFromQueue (dst, toDst.GetRoute ());
      return;
    }

  RoutingTableEntry toOrigin;
  if (!m_routingTable.LookupRoute (rrepHeader.GetOrigin (), toOrigin) || toOrigin.GetFlag () == IN_SEARCH)
    {
      return; // Impossible! drop.
    }
  toOrigin.SetLifeTime (std::max (ActiveRouteTimeout, toOrigin.GetLifeTime ()));
  m_routingTable.Update (toOrigin);

  // Update information about precursors
  if (m_routingTable.LookupValidRoute (rrepHeader.GetDst (), toDst))
    {
      toDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTable.Update (toDst);

      RoutingTableEntry toNextHopToDst;
      m_routingTable.LookupRoute (toDst.GetNextHop (), toNextHopToDst);
      toNextHopToDst.InsertPrecursor (toOrigin.GetNextHop ());
      m_routingTable.Update (toNextHopToDst);

      toOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTable.Update (toOrigin);

      RoutingTableEntry toNextHopToOrigin;
      m_routingTable.LookupRoute (toOrigin.GetNextHop (), toNextHopToOrigin);
      toNextHopToOrigin.InsertPrecursor (toDst.GetNextHop ());
      m_routingTable.Update (toNextHopToOrigin);
    }

  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (rrepHeader);
  TypeHeader tHeader (AODVTYPE_RREP);
  packet->AddHeader (tHeader);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (toOrigin.GetInterface ());
  NS_ASSERT (socket);
  socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));
}

void
RoutingProtocol::RecvReplyAck (Ipv4Address neighbor)
{
  NS_LOG_FUNCTION (this);
  RoutingTableEntry rt;
  if(m_routingTable.LookupRoute (neighbor, rt))
    {
      rt.m_ackTimer.Cancel ();
      rt.SetFlag (VALID);
      m_routingTable.Update (rt);
    }
}

void
RoutingProtocol::ProcessHello (RrepHeader const & rrepHeader, Ipv4Address receiver )
{
  NS_LOG_FUNCTION (this << "from " << rrepHeader.GetDst ());
  /*
   *  Whenever a node receives a Hello message from a neighbor, the node
   * SHOULD make sure that it has an active route to the neighbor, and
   * create one if necessary.
   */
  RoutingTableEntry toNeighbor;
  if (!m_routingTable.LookupRoute (rrepHeader.GetDst (), toNeighbor))
    {
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
      RoutingTableEntry newEntry (/*device=*/ dev, /*dst=*/ rrepHeader.GetDst (), /*validSeqNo=*/ true, /*seqno=*/ rrepHeader.GetDstSeqno (),
                                              /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                                              /*hop=*/ 1, /*nextHop=*/ rrepHeader.GetDst (), /*lifeTime=*/ rrepHeader.GetLifeTime ());
      m_routingTable.AddRoute (newEntry);
    }
  else
    {
      toNeighbor.SetLifeTime (std::max (Time (AllowedHelloLoss * HelloInterval), toNeighbor.GetLifeTime ()));
      toNeighbor.SetSeqNo (rrepHeader.GetDstSeqno ());
      toNeighbor.SetValidSeqNo (true);
      toNeighbor.SetFlag (VALID);
      toNeighbor.SetOutputDevice (m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver)));
      toNeighbor.SetInterface (m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0));
      toNeighbor.SetHop (1);
      toNeighbor.SetNextHop (rrepHeader.GetDst ());
      m_routingTable.Update (toNeighbor);
    }
  if (EnableHello)
    {
      m_nb.Update (rrepHeader.GetDst (), Time (AllowedHelloLoss * HelloInterval));
    }
}

void
RoutingProtocol::RecvError (Ptr<Packet> p, Ipv4Address src )
{
  NS_LOG_FUNCTION (this << " from " << src);
  RerrHeader rerrHeader;
  p->RemoveHeader (rerrHeader);
  std::map<Ipv4Address, uint32_t> dstWithNextHopSrc;
  std::map<Ipv4Address, uint32_t> unreachable;
  m_routingTable.GetListOfDestinationWithNextHop (src, dstWithNextHopSrc);
  std::pair<Ipv4Address, uint32_t> un;
  while (rerrHeader.RemoveUnDestination (un))
    {
      for (std::map<Ipv4Address, uint32_t>::const_iterator i =
           dstWithNextHopSrc.begin (); i != dstWithNextHopSrc.end (); ++i)
      {
        if (i->first == un.first)
          {
            unreachable.insert (un);
          }
      }
    }

  std::vector<Ipv4Address> precursors;
  for (std::map<Ipv4Address, uint32_t>::const_iterator i = unreachable.begin ();
       i != unreachable.end ();)
    {
      if (!rerrHeader.AddUnDestination (i->first, i->second))
        {
          TypeHeader typeHeader (AODVTYPE_RERR);
          Ptr<Packet> packet = Create<Packet> ();
          packet->AddHeader (rerrHeader);
          packet->AddHeader (typeHeader);
          SendRerrMessage (packet, precursors);
          rerrHeader.Clear ();
        }
      else
        {
          RoutingTableEntry toDst;
          m_routingTable.LookupRoute (i->first, toDst);
          toDst.GetPrecursors (precursors);
          ++i;
        }
    }
  if (rerrHeader.GetDestCount () != 0)
    {
      TypeHeader typeHeader (AODVTYPE_RERR);
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (rerrHeader);
      packet->AddHeader (typeHeader);
      SendRerrMessage (packet, precursors);
    }
  m_routingTable.InvalidateRoutesWithDst (unreachable);
}

void
RoutingProtocol::RouteRequestTimerExpire (Ipv4Address dst)
{
  NS_LOG_LOGIC (this);
  RoutingTableEntry toDst;
  if (m_routingTable.LookupValidRoute (dst, toDst))
    {
      SendPacketFromQueue (dst, toDst.GetRoute ());
      NS_LOG_LOGIC ("route to " << dst << " found");
      return;
    }
  /*
   *  If a route discovery has been attempted RreqRetries times at the maximum TTL without
   *  receiving any RREP, all data packets destined for the corresponding destination SHOULD be
   *  dropped from the buffer and a Destination Unreachable message SHOULD be delivered to the application.
   */
  if (toDst.GetRreqCnt () == RreqRetries)
    {
      NS_LOG_LOGIC ("route discovery to " << dst << " has been attempted RreqRetries (" << RreqRetries << ") times");
      m_addressReqTimer.erase (dst);
      m_routingTable.DeleteRoute (dst);
      NS_LOG_DEBUG ("Route not found. Drop all packets with dst " << dst);
      m_queue.DropPacketWithDst (dst);
      return;
    }

  if (toDst.GetFlag () == IN_SEARCH)
    {
      NS_LOG_LOGIC ("Resend RREQ to " << dst << " ttl " << NetDiameter);
      SendRequest (dst);
    }
  else
    {
      NS_LOG_DEBUG ("Route down. Stop search. Drop packet with destination " << dst);
      m_addressReqTimer.erase (dst);
      m_routingTable.DeleteRoute (dst);
      m_queue.DropPacketWithDst (dst);
    }
}

void
RoutingProtocol::HelloTimerExpire ()
{
  NS_LOG_FUNCTION (this);
  Time offset = Time (Seconds (0));
  if (m_lastBcastTime > Time (Seconds (0)))
    {
      offset = Simulator::Now () - m_lastBcastTime;
      NS_LOG_DEBUG ("Hello deferred due to last bcast at:" << m_lastBcastTime);
    }
  else
    {
      SendHello ();
    }
  m_htimer.Cancel ();
  Time diff = HelloInterval - offset;
  m_htimer.Schedule (std::max (Time (Seconds (0)), diff));
  m_lastBcastTime = Time (Seconds (0));
}

void
RoutingProtocol::RreqRateLimitTimerExpire ()
{
  NS_LOG_FUNCTION (this);
  m_rreqCount = 0;
  m_rreqRateLimitTimer.Schedule (Seconds (1));
}

void
RoutingProtocol::RerrRateLimitTimerExpire ()
{
  NS_LOG_FUNCTION (this);
  m_rerrCount = 0;
  m_rerrRateLimitTimer.Schedule (Seconds (1));
}

void
RoutingProtocol::AckTimerExpire (Ipv4Address neighbor, Time blacklistTimeout)
{
  NS_LOG_FUNCTION (this);
  m_routingTable.MarkLinkAsUnidirectional (neighbor, blacklistTimeout);
}

void
RoutingProtocol::SendHello ()
{
  NS_LOG_FUNCTION (this);
  /* Broadcast a RREP with TTL = 1 with the RREP message fields set as follows:
   *   Destination IP Address         The node's IP address.
   *   Destination Sequence Number    The node's latest sequence number.
   *   Hop Count                      0
   *   Lifetime                       AllowedHelloLoss * HelloInterval
   */
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      RrepHeader helloHeader (/*prefix size=*/ 0, /*hops=*/ 0, /*dst=*/ iface.GetLocal (), /*dst seqno=*/ m_seqNo,
                                               /*origin=*/ iface.GetLocal (),/*lifetime=*/ Time (AllowedHelloLoss * HelloInterval));
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (helloHeader);
      TypeHeader tHeader (AODVTYPE_RREP);
      packet->AddHeader (tHeader);
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        { 
          destination = iface.GetBroadcast ();
        }
      Time jitter = Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10)));
      Simulator::Schedule (jitter, &RoutingProtocol::SendTo, this , socket, packet, destination);
    }
}

void
RoutingProtocol::SendPacketFromQueue (Ipv4Address dst, Ptr<Ipv4Route> route)
{
  NS_LOG_FUNCTION (this);
  QueueEntry queueEntry;
  while (m_queue.Dequeue (dst, queueEntry))
    {
      DeferredRouteOutputTag tag;
      Ptr<Packet> p = ConstCast<Packet> (queueEntry.GetPacket ());
      if (p->RemovePacketTag (tag) && 
          tag.GetInterface() != -1 &&
          tag.GetInterface() != m_ipv4->GetInterfaceForDevice (route->GetOutputDevice ()))
        {
          NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
          return;
        }
      UnicastForwardCallback ucb = queueEntry.GetUnicastForwardCallback ();
      Ipv4Header header = queueEntry.GetIpv4Header ();
      header.SetSource (route->GetSource ());
      header.SetTtl (header.GetTtl () + 1); // compensate extra TTL decrement by fake loopback routing
      ucb (route, p, header);
    }
}

void
RoutingProtocol::SendRerrWhenBreaksLinkToNextHop (Ipv4Address nextHop)
{
  NS_LOG_FUNCTION (this << nextHop);
  RerrHeader rerrHeader;
  std::vector<Ipv4Address> precursors;
  std::map<Ipv4Address, uint32_t> unreachable;

  RoutingTableEntry toNextHop;
  if (!m_routingTable.LookupRoute (nextHop, toNextHop))
    return;
  toNextHop.GetPrecursors (precursors);
  rerrHeader.AddUnDestination (nextHop, toNextHop.GetSeqNo ());
  m_routingTable.GetListOfDestinationWithNextHop (nextHop, unreachable);
  for (std::map<Ipv4Address, uint32_t>::const_iterator i = unreachable.begin (); i
       != unreachable.end ();)
    {
      if (!rerrHeader.AddUnDestination (i->first, i->second))
        {
          NS_LOG_LOGIC ("Send RERR message with maximum size.");
          TypeHeader typeHeader (AODVTYPE_RERR);
          Ptr<Packet> packet = Create<Packet> ();
          packet->AddHeader (rerrHeader);
          packet->AddHeader (typeHeader);
          SendRerrMessage (packet, precursors);
          rerrHeader.Clear ();
        }
      else
        {
          RoutingTableEntry toDst;
          m_routingTable.LookupRoute (i->first, toDst);
          toDst.GetPrecursors (precursors);
          ++i;
        }
    }
  if (rerrHeader.GetDestCount () != 0)
    {
      TypeHeader typeHeader (AODVTYPE_RERR);
      Ptr<Packet> packet = Create<Packet> ();
      packet->AddHeader (rerrHeader);
      packet->AddHeader (typeHeader);
      SendRerrMessage (packet, precursors);
    }
  unreachable.insert (std::make_pair (nextHop, toNextHop.GetSeqNo ()));
  m_routingTable.InvalidateRoutesWithDst (unreachable);
}

void
RoutingProtocol::SendRerrWhenNoRouteToForward (Ipv4Address dst,
                                               uint32_t dstSeqNo, Ipv4Address origin)
{
  NS_LOG_FUNCTION (this);
  // A node SHOULD NOT originate more than RERR_RATELIMIT RERR messages per second.
  if (m_rerrCount == RerrRateLimit)
    {
      // Just make sure that the RerrRateLimit timer is running and will expire
      NS_ASSERT (m_rerrRateLimitTimer.IsRunning ());
      // discard the packet and return
      NS_LOG_LOGIC ("RerrRateLimit reached at " << Simulator::Now ().GetSeconds () << " with timer delay left " 
                                                << m_rerrRateLimitTimer.GetDelayLeft ().GetSeconds ()
                                                << "; suppressing RERR");
      return;
    }
  RerrHeader rerrHeader;
  rerrHeader.AddUnDestination (dst, dstSeqNo);
  RoutingTableEntry toOrigin;
  Ptr<Packet> packet = Create<Packet> ();
  packet->AddHeader (rerrHeader);
  packet->AddHeader (TypeHeader (AODVTYPE_RERR));
  if (m_routingTable.LookupValidRoute (origin, toOrigin))
    {
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (
          toOrigin.GetInterface ());
      NS_ASSERT (socket);
      NS_LOG_LOGIC ("Unicast RERR to the source of the data transmission");
      socket->SendTo (packet, 0, InetSocketAddress (toOrigin.GetNextHop (), AODV_PORT));
    }
  else
    {
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator i =
             m_socketAddresses.begin (); i != m_socketAddresses.end (); ++i)
        {
          Ptr<Socket> socket = i->first;
          Ipv4InterfaceAddress iface = i->second;
          NS_ASSERT (socket);
          NS_LOG_LOGIC ("Broadcast RERR message from interface " << iface.GetLocal ());
          // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
          Ipv4Address destination;
          if (iface.GetMask () == Ipv4Mask::GetOnes ())
            {
              destination = Ipv4Address ("255.255.255.255");
            }
          else
            { 
              destination = iface.GetBroadcast ();
            }
          socket->SendTo (packet->Copy (), 0, InetSocketAddress (destination, AODV_PORT));
        }
    }
}

void
RoutingProtocol::SendRerrMessage (Ptr<Packet> packet, std::vector<Ipv4Address> precursors)
{
  NS_LOG_FUNCTION (this);

  if (precursors.empty ())
    {
      NS_LOG_LOGIC ("No precursors");
      return;
    }
  // A node SHOULD NOT originate more than RERR_RATELIMIT RERR messages per second.
  if (m_rerrCount == RerrRateLimit)
    {
      // Just make sure that the RerrRateLimit timer is running and will expire
      NS_ASSERT (m_rerrRateLimitTimer.IsRunning ());
      // discard the packet and return
      NS_LOG_LOGIC ("RerrRateLimit reached at " << Simulator::Now ().GetSeconds () << " with timer delay left " 
                                                << m_rerrRateLimitTimer.GetDelayLeft ().GetSeconds ()
                                                << "; suppressing RERR");
      return;
    }
  // If there is only one precursor, RERR SHOULD be unicast toward that precursor
  if (precursors.size () == 1)
    {
      RoutingTableEntry toPrecursor;
      if (m_routingTable.LookupValidRoute (precursors.front (), toPrecursor))
        {
          Ptr<Socket> socket = FindSocketWithInterfaceAddress (toPrecursor.GetInterface ());
          NS_ASSERT (socket);
          NS_LOG_LOGIC ("one precursor => unicast RERR to " << toPrecursor.GetDestination () << " from " << toPrecursor.GetInterface ().GetLocal ());
          Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, packet, precursors.front ());
          m_rerrCount++;
        }
      return;
    }

  //  Should only transmit RERR on those interfaces which have precursor nodes for the broken route
  std::vector<Ipv4InterfaceAddress> ifaces;
  RoutingTableEntry toPrecursor;
  for (std::vector<Ipv4Address>::const_iterator i = precursors.begin (); i != precursors.end (); ++i)
    {
      if (m_routingTable.LookupValidRoute (*i, toPrecursor) && 
          std::find (ifaces.begin (), ifaces.end (), toPrecursor.GetInterface ()) == ifaces.end ())
        {
          ifaces.push_back (toPrecursor.GetInterface ());
        }
    }

  for (std::vector<Ipv4InterfaceAddress>::const_iterator i = ifaces.begin (); i != ifaces.end (); ++i)
    {
      Ptr<Socket> socket = FindSocketWithInterfaceAddress (*i);
      NS_ASSERT (socket);
      NS_LOG_LOGIC ("Broadcast RERR message from interface " << i->GetLocal ());
      // std::cout << "Broadcast RERR message from interface " << i->GetLocal () << std::endl;
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ptr<Packet> p = packet->Copy ();
      Ipv4Address destination;
      if (i->GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        { 
          destination = i->GetBroadcast ();
        }
      Simulator::Schedule (Time (MilliSeconds (m_uniformRandomVariable->GetInteger (0, 10))), &RoutingProtocol::SendTo, this, socket, p, destination);
    }
}

Ptr<Socket>
RoutingProtocol::FindSocketWithInterfaceAddress (Ipv4InterfaceAddress addr ) const
{
  NS_LOG_FUNCTION (this << addr);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      if (iface == addr)
        return socket;
    }
  Ptr<Socket> socket;
  return socket;
}

Ptr<Socket>
RoutingProtocol::FindSubnetBroadcastSocketWithInterfaceAddress (Ipv4InterfaceAddress addr ) const
{
  NS_LOG_FUNCTION (this << addr);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketSubnetBroadcastAddresses.begin (); j != m_socketSubnetBroadcastAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      if (iface == addr)
        return socket;
    }
  Ptr<Socket> socket;
  return socket;
}

void
RoutingProtocol::DoInitialize (void)
{
  NS_LOG_FUNCTION (this);
  uint32_t startTime;
  if (EnableHello)
    {
      m_htimer.SetFunction (&RoutingProtocol::HelloTimerExpire, this);
      startTime = m_uniformRandomVariable->GetInteger (0, 100);
      NS_LOG_DEBUG ("Starting at time " << startTime << "ms");
      m_htimer.Schedule (MilliSeconds (startTime));
    }
  Ipv4RoutingProtocol::DoInitialize ();
}

} //namespace aodv
} //namespace ns3
```
### aodv-routing-protocol.h
```c++
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Based on 
 *      NS-2 AODV model developed by the CMU/MONARCH group and optimized and
 *      tuned by Samir Das and Mahesh Marina, University of Cincinnati;
 * 
 *      AODV-UU implementation by Erik Nordström of Uppsala University
 *      http://core.it.uu.se/core/index.php/AODV-UU
 *
 * Authors: Elena Buchatskaia <borovkovaes@iitp.ru>
 *          Pavel Boyko <boyko@iitp.ru>
 */
#ifndef AODVROUTINGPROTOCOL_H
#define AODVROUTINGPROTOCOL_H

#include "aodv-rtable.h"
#include "aodv-rqueue.h"
#include "aodv-packet.h"
#include "aodv-neighbor.h"
#include "aodv-dpd.h"
#include "ns3/node.h"
#include "ns3/random-variable-stream.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/ipv4-l3-protocol.h"
#include <map>

namespace ns3
{
namespace aodv
{
/**
 * \ingroup aodv
 * 
 * \brief AODV routing protocol
 */
class RoutingProtocol : public Ipv4RoutingProtocol
{
public:
  static TypeId GetTypeId (void);
  static const uint32_t AODV_PORT;
  static int CommandPacketCount;

  /// c-tor
  RoutingProtocol ();
  virtual ~RoutingProtocol();
  virtual void DoDispose ();

  // Inherited from Ipv4RoutingProtocol
  Ptr<Ipv4Route> RouteOutput (Ptr<Packet> p, const Ipv4Header &header, Ptr<NetDevice> oif, Socket::SocketErrno &sockerr);
  bool RouteInput (Ptr<const Packet> p, const Ipv4Header &header, Ptr<const NetDevice> idev,
                   UnicastForwardCallback ucb, MulticastForwardCallback mcb,
                   LocalDeliverCallback lcb, ErrorCallback ecb);
  virtual void NotifyInterfaceUp (uint32_t interface);
  virtual void NotifyInterfaceDown (uint32_t interface);
  virtual void NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address);
  virtual void NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address);
  virtual void SetIpv4 (Ptr<Ipv4> ipv4);
  virtual void PrintRoutingTable (Ptr<OutputStreamWrapper> stream) const;

  // Handle protocol parameters
  Time GetMaxQueueTime () const { return MaxQueueTime; }
  void SetMaxQueueTime (Time t);
  uint32_t GetMaxQueueLen () const { return MaxQueueLen; }
  void SetMaxQueueLen (uint32_t len);
  bool GetDesinationOnlyFlag () const { return DestinationOnly; }
  void SetDesinationOnlyFlag (bool f) { DestinationOnly = f; }
  bool GetGratuitousReplyFlag () const { return GratuitousReply; }
  void SetGratuitousReplyFlag (bool f) { GratuitousReply = f; }
  void SetHelloEnable (bool f) { EnableHello = f; }
  bool GetHelloEnable () const { return EnableHello; }
  void SetBroadcastEnable (bool f) { EnableBroadcast = f; }
  bool GetBroadcastEnable () const { return EnableBroadcast; }

 /**
  * Assign a fixed random variable stream number to the random variables
  * used by this model.  Return the number of streams (possibly zero) that
  * have been assigned.
  *
  * \param stream first stream index to use
  * \return the number of stream indices assigned by this model
  */
  int64_t AssignStreams (int64_t stream);

protected:
  virtual void DoInitialize (void);
private:
  
  // Protocol parameters.
  uint32_t RreqRetries;             ///< Maximum number of retransmissions of RREQ with TTL = NetDiameter to discover a route
  uint16_t RreqRateLimit;           ///< Maximum number of RREQ per second.
  uint16_t RerrRateLimit;           ///< Maximum number of REER per second.
  Time ActiveRouteTimeout;          ///< Period of time during which the route is considered to be valid.
  uint32_t NetDiameter;             ///< Net diameter measures the maximum possible number of hops between two nodes in the network
  /**
   *  NodeTraversalTime is a conservative estimate of the average one hop traversal time for packets
   *  and should include queuing delays, interrupt processing times and transfer times.
   */
  Time NodeTraversalTime;
  Time NetTraversalTime;             ///< Estimate of the average net traversal time.
  Time PathDiscoveryTime;            ///< Estimate of maximum time needed to find route in network.
  Time MyRouteTimeout;               ///< Value of lifetime field in RREP generating by this node.
  /**
   * Every HelloInterval the node checks whether it has sent a broadcast  within the last HelloInterval.
   * If it has not, it MAY broadcast a  Hello message
   */
  Time HelloInterval;
  uint32_t AllowedHelloLoss;         ///< Number of hello messages which may be loss for valid link
  /**
   * DeletePeriod is intended to provide an upper bound on the time for which an upstream node A
   * can have a neighbor B as an active next hop for destination D, while B has invalidated the route to D.
   */
  Time DeletePeriod;
  Time NextHopWait;                  ///< Period of our waiting for the neighbour's RREP_ACK
  Time BlackListTimeout;             ///< Time for which the node is put into the blacklist
  uint32_t MaxQueueLen;              ///< The maximum number of packets that we allow a routing protocol to buffer.
  Time MaxQueueTime;                 ///< The maximum period of time that a routing protocol is allowed to buffer a packet for.
  bool DestinationOnly;              ///< Indicates only the destination may respond to this RREQ.
  bool GratuitousReply;              ///< Indicates whether a gratuitous RREP should be unicast to the node originated route discovery.
  bool EnableHello;                  ///< Indicates whether a hello messages enable
  bool EnableBroadcast;              ///< Indicates whether a a broadcast data packets forwarding enable
  //\}

  /// IP protocol
  Ptr<Ipv4> m_ipv4;
  /// Raw unicast socket per each IP interface, map socket -> iface address (IP + mask)
  std::map< Ptr<Socket>, Ipv4InterfaceAddress > m_socketAddresses;
  /// Raw subnet directed broadcast socket per each IP interface, map socket -> iface address (IP + mask)
  std::map< Ptr<Socket>, Ipv4InterfaceAddress > m_socketSubnetBroadcastAddresses;
  /// Loopback device used to defer RREQ until packet will be fully formed
  Ptr<NetDevice> m_lo; 

  /// Routing table
  RoutingTable m_routingTable;
  /// A "drop-front" queue used by the routing layer to buffer packets to which it does not have a route.
  RequestQueue m_queue;
  /// Broadcast ID
  uint32_t m_requestId;
  /// Request sequence number
  uint32_t m_seqNo;
  /// Handle duplicated RREQ
  IdCache m_rreqIdCache;
  /// Handle duplicated broadcast/multicast packets
  DuplicatePacketDetection m_dpd;
  /// Handle neighbors
  Neighbors m_nb;
  /// Number of RREQs used for RREQ rate control
  uint16_t m_rreqCount;
  /// Number of RERRs used for RERR rate control
  uint16_t m_rerrCount;

private:
  /// Start protocol operation
  void Start ();
  /// Queue packet and send route request
  void DeferredRouteOutput (Ptr<const Packet> p, const Ipv4Header & header, UnicastForwardCallback ucb, ErrorCallback ecb);
  /// If route exists and valid, forward packet.
  bool Forwarding (Ptr<const Packet> p, const Ipv4Header & header, UnicastForwardCallback ucb, ErrorCallback ecb);
  /**
  * To reduce congestion in a network, repeated attempts by a source node at route discovery
  * for a single destination MUST utilize a binary exponential backoff.
  */
  void ScheduleRreqRetry (Ipv4Address dst);
  /**
   * Set lifetime field in routing table entry to the maximum of existing lifetime and lt, if the entry exists
   * \param addr - destination address
   * \param lt - proposed time for lifetime field in routing table entry for destination with address addr.
   * \return true if route to destination address addr exist
   */
  bool UpdateRouteLifeTime (Ipv4Address addr, Time lt);
  /**
   * Update neighbor record.
   * \param receiver is supposed to be my interface
   * \param sender is supposed to be IP address of my neighbor.
   */
  void UpdateRouteToNeighbor (Ipv4Address sender, Ipv4Address receiver);
  /// Check that packet is send from own interface
  bool IsMyOwnAddress (Ipv4Address src);
  /// Find unicast socket with local interface address iface
  Ptr<Socket> FindSocketWithInterfaceAddress (Ipv4InterfaceAddress iface) const;
  /// Find subnet directed broadcast socket with local interface address iface
  Ptr<Socket> FindSubnetBroadcastSocketWithInterfaceAddress (Ipv4InterfaceAddress iface) const;
  /// Process hello message
  void ProcessHello (RrepHeader const & rrepHeader, Ipv4Address receiverIfaceAddr);
  /// Create loopback route for given header
  Ptr<Ipv4Route> LoopbackRoute (const Ipv4Header & header, Ptr<NetDevice> oif) const;

  ///\name Receive control packets
  //\{
  /// Receive and process control packet
  void RecvAodv (Ptr<Socket> socket);
  /// Receive RREQ
  void RecvRequest (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address src);
  /// Receive RREP
  void RecvReply (Ptr<Packet> p, Ipv4Address my,Ipv4Address src);
  /// Receive RREP_ACK
  void RecvReplyAck (Ipv4Address neighbor);
  /// Receive RERR from node with address src
  void RecvError (Ptr<Packet> p, Ipv4Address src);
  //\}

  ///\name Send
  //\{
  /// Forward packet from route request queue
  void SendPacketFromQueue (Ipv4Address dst, Ptr<Ipv4Route> route);
  /// Send hello
  void SendHello ();
  /// Send RREQ
  void SendRequest (Ipv4Address dst);
  /// Send RREP
  void SendReply (RreqHeader const & rreqHeader, RoutingTableEntry const & toOrigin);
  /** Send RREP by intermediate node
   * \param toDst routing table entry to destination
   * \param toOrigin routing table entry to originator
   * \param gratRep indicates whether a gratuitous RREP should be unicast to destination
   */
  void SendReplyByIntermediateNode (RoutingTableEntry & toDst, RoutingTableEntry & toOrigin, bool gratRep);
  /// Send RREP_ACK
  void SendReplyAck (Ipv4Address neighbor);
  /// Initiate RERR
  void SendRerrWhenBreaksLinkToNextHop (Ipv4Address nextHop);
  /// Forward RERR
  void SendRerrMessage (Ptr<Packet> packet,  std::vector<Ipv4Address> precursors);
  /**
   * Send RERR message when no route to forward input packet. Unicast if there is reverse route to originating node, broadcast otherwise.
   * \param dst - destination node IP address
   * \param dstSeqNo - destination node sequence number
   * \param origin - originating node IP address
   */
  void SendRerrWhenNoRouteToForward (Ipv4Address dst, uint32_t dstSeqNo, Ipv4Address origin);
  /// @}

  void SendTo (Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination);

  /// Hello timer
  Timer m_htimer;
  /// Schedule next send of hello message
  void HelloTimerExpire ();
  /// RREQ rate limit timer
  Timer m_rreqRateLimitTimer;
  /// Reset RREQ count and schedule RREQ rate limit timer with delay 1 sec.
  void RreqRateLimitTimerExpire ();
  /// RERR rate limit timer
  Timer m_rerrRateLimitTimer;
  /// Reset RERR count and schedule RERR rate limit timer with delay 1 sec.
  void RerrRateLimitTimerExpire ();
  /// Map IP address + RREQ timer.
  std::map<Ipv4Address, Timer> m_addressReqTimer;
  /// Handle route discovery process
  void RouteRequestTimerExpire (Ipv4Address dst);
  /// Mark link to neighbor node as unidirectional for blacklistTimeout
  void AckTimerExpire (Ipv4Address neighbor,  Time blacklistTimeout);

  /// Provides uniform random variables.
  Ptr<UniformRandomVariable> m_uniformRandomVariable;  
  /// Keep track of the last bcast time
  Time m_lastBcastTime;
};

}
}
#endif /* AODVROUTINGPROTOCOL_H */
```

### dsdv-routing-protocol.cc
```c++
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 Hemanth Narra, Yufei Cheng
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Hemanth Narra <hemanth@ittc.ku.com>
 * Author: Yufei Cheng   <yfcheng@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

#include "dsdv-routing-protocol.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/wifi-net-device.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("DsdvRoutingProtocol");
  
namespace dsdv {

int RoutingProtocol::CommandPacketCount = 0;
NS_OBJECT_ENSURE_REGISTERED (RoutingProtocol);

/// UDP Port for DSDV control traffic
const uint32_t RoutingProtocol::DSDV_PORT = 269;

/// Tag used by DSDV implementation
struct DeferredRouteOutputTag : public Tag
{
  /// Positive if output device is fixed in RouteOutput
  int32_t oif;

  DeferredRouteOutputTag (int32_t o = -1)
    : Tag (),
      oif (o)
  {
  }

  static TypeId
  GetTypeId ()
  {
    static TypeId tid = TypeId ("ns3::dsdv::DeferredRouteOutputTag")
      .SetParent<Tag> ()
      .SetGroupName ("Dsdv")
      .AddConstructor<DeferredRouteOutputTag> ()
      ;
    return tid;
  }

  TypeId
  GetInstanceTypeId () const
  {
    return GetTypeId ();
  }

  uint32_t
  GetSerializedSize () const
  {
    return sizeof(int32_t);
  }

  void
  Serialize (TagBuffer i) const
  {
    i.WriteU32 (oif);
  }

  void
  Deserialize (TagBuffer i)
  {
    oif = i.ReadU32 ();
  }

  void
  Print (std::ostream &os) const
  {
    os << "DeferredRouteOutputTag: output interface = " << oif;
  }
};

TypeId
RoutingProtocol::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::dsdv::RoutingProtocol")
    .SetParent<Ipv4RoutingProtocol> ()
    .SetGroupName ("Dsdv")
    .AddConstructor<RoutingProtocol> ()
    .AddAttribute ("PeriodicUpdateInterval","Periodic interval between exchange of full routing tables among nodes. ",
                   TimeValue (Seconds (15)),
                   MakeTimeAccessor (&RoutingProtocol::m_periodicUpdateInterval),
                   MakeTimeChecker ())
    .AddAttribute ("SettlingTime", "Minimum time an update is to be stored in adv table before sending out"
                   "in case of change in metric (in seconds)",
                   TimeValue (Seconds (5)),
                   MakeTimeAccessor (&RoutingProtocol::m_settlingTime),
                   MakeTimeChecker ())
    .AddAttribute ("MaxQueueLen", "Maximum number of packets that we allow a routing protocol to buffer.",
                   UintegerValue (500 /*assuming maximum nodes in simulation is 100*/),
                   MakeUintegerAccessor (&RoutingProtocol::m_maxQueueLen),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxQueuedPacketsPerDst", "Maximum number of packets that we allow per destination to buffer.",
                   UintegerValue (5),
                   MakeUintegerAccessor (&RoutingProtocol::m_maxQueuedPacketsPerDst),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxQueueTime","Maximum time packets can be queued (in seconds)",
                   TimeValue (Seconds (30)),
                   MakeTimeAccessor (&RoutingProtocol::m_maxQueueTime),
                   MakeTimeChecker ())
    .AddAttribute ("EnableBuffering","Enables buffering of data packets if no route to destination is available",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetEnableBufferFlag,
                                        &RoutingProtocol::GetEnableBufferFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("EnableWST","Enables Weighted Settling Time for the updates before advertising",
                   BooleanValue (true),
                   MakeBooleanAccessor (&RoutingProtocol::SetWSTFlag,
                                        &RoutingProtocol::GetWSTFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("Holdtimes","Times the forwarding Interval to purge the route.",
                   UintegerValue (3),
                   MakeUintegerAccessor (&RoutingProtocol::Holdtimes),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("WeightedFactor","WeightedFactor for the settling time if Weighted Settling Time is enabled",
                   DoubleValue (0.875),
                   MakeDoubleAccessor (&RoutingProtocol::m_weightedFactor),
                   MakeDoubleChecker<double> ())
    .AddAttribute ("EnableRouteAggregation","Enables Weighted Settling Time for the updates before advertising",
                   BooleanValue (false),
                   MakeBooleanAccessor (&RoutingProtocol::SetEnableRAFlag,
                                        &RoutingProtocol::GetEnableRAFlag),
                   MakeBooleanChecker ())
    .AddAttribute ("RouteAggregationTime","Time to aggregate updates before sending them out (in seconds)",
                   TimeValue (Seconds (1)),
                   MakeTimeAccessor (&RoutingProtocol::m_routeAggregationTime),
                   MakeTimeChecker ());
  return tid;
}

void
RoutingProtocol::SetEnableBufferFlag (bool f)
{
  EnableBuffering = f;
}
bool
RoutingProtocol::GetEnableBufferFlag () const
{
  return EnableBuffering;
}
void
RoutingProtocol::SetWSTFlag (bool f)
{
  EnableWST = f;
}
bool
RoutingProtocol::GetWSTFlag () const
{
  return EnableWST;
}
void
RoutingProtocol::SetEnableRAFlag (bool f)
{
  EnableRouteAggregation = f;
}
bool
RoutingProtocol::GetEnableRAFlag () const
{
  return EnableRouteAggregation;
}

int64_t
RoutingProtocol::AssignStreams (int64_t stream)
{
  NS_LOG_FUNCTION (this << stream);
  m_uniformRandomVariable->SetStream (stream);
  return 1;
}

RoutingProtocol::RoutingProtocol ()
  : m_routingTable (),
    m_advRoutingTable (),
    m_queue (),
    m_periodicUpdateTimer (Timer::CANCEL_ON_DESTROY)
{
  m_uniformRandomVariable = CreateObject<UniformRandomVariable> ();
}

RoutingProtocol::~RoutingProtocol ()
{
}

void
RoutingProtocol::DoDispose ()
{
  m_ipv4 = 0;
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin (); iter
       != m_socketAddresses.end (); iter++)
    {
      iter->first->Close ();
    }
  m_socketAddresses.clear ();
  Ipv4RoutingProtocol::DoDispose ();
}

void
RoutingProtocol::PrintRoutingTable (Ptr<OutputStreamWrapper> stream) const
{
  *stream->GetStream () << "Node: " << m_ipv4->GetObject<Node> ()->GetId ()
                        << ", Time: " << Now().As (Time::S)
                        << ", Local time: " << GetObject<Node> ()->GetLocalTime ().As (Time::S)
                        << ", DSDV Routing table" << std::endl;

  m_routingTable.Print (stream);
  *stream->GetStream () << std::endl;
}

void
RoutingProtocol::Start ()
{
  m_queue.SetMaxPacketsPerDst (m_maxQueuedPacketsPerDst);
  m_queue.SetMaxQueueLen (m_maxQueueLen);
  m_queue.SetQueueTimeout (m_maxQueueTime);
  m_routingTable.Setholddowntime (Time (Holdtimes * m_periodicUpdateInterval));
  m_advRoutingTable.Setholddowntime (Time (Holdtimes * m_periodicUpdateInterval));
  m_scb = MakeCallback (&RoutingProtocol::Send,this);
  m_ecb = MakeCallback (&RoutingProtocol::Drop,this);
  m_periodicUpdateTimer.SetFunction (&RoutingProtocol::SendPeriodicUpdate,this);
  m_periodicUpdateTimer.Schedule (MicroSeconds (m_uniformRandomVariable->GetInteger (0,1000)));
}

Ptr<Ipv4Route>
RoutingProtocol::RouteOutput (Ptr<Packet> p,
                              const Ipv4Header &header,
                              Ptr<NetDevice> oif,
                              Socket::SocketErrno &sockerr)
{
  NS_LOG_FUNCTION (this << header << (oif ? oif->GetIfIndex () : 0));

  if (!p)
    {
      return LoopbackRoute (header,oif);
    }
  if (m_socketAddresses.empty ())
    {
      sockerr = Socket::ERROR_NOROUTETOHOST;
      NS_LOG_LOGIC ("No dsdv interfaces");
      Ptr<Ipv4Route> route;
      return route;
    }
  std::map<Ipv4Address, RoutingTableEntry> removedAddresses;
  sockerr = Socket::ERROR_NOTERROR;
  Ptr<Ipv4Route> route;
  Ipv4Address dst = header.GetDestination ();
  NS_LOG_DEBUG ("Packet Size: " << p->GetSize ()
                                << ", Packet id: " << p->GetUid () << ", Destination address in Packet: " << dst);
  RoutingTableEntry rt;
  m_routingTable.Purge (removedAddresses);
  for (std::map<Ipv4Address, RoutingTableEntry>::iterator rmItr = removedAddresses.begin ();
       rmItr != removedAddresses.end (); ++rmItr)
    {
      rmItr->second.SetEntriesChanged (true);
      rmItr->second.SetSeqNo (rmItr->second.GetSeqNo () + 1);
      m_advRoutingTable.AddRoute (rmItr->second);
    }
  if (!removedAddresses.empty ())
    {
      Simulator::Schedule (MicroSeconds (m_uniformRandomVariable->GetInteger (0,1000)),&RoutingProtocol::SendTriggeredUpdate,this);
    }
  if (m_routingTable.LookupRoute (dst,rt))
    {
      if (EnableBuffering)
        {
          LookForQueuedPackets ();
        }
      if (rt.GetHop () == 1)
        {
          route = rt.GetRoute ();
          NS_ASSERT (route != 0);
          NS_LOG_DEBUG ("A route exists from " << route->GetSource ()
                                               << " to neighboring destination "
                                               << route->GetDestination ());
          if (oif != 0 && route->GetOutputDevice () != oif)
            {
              NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
              sockerr = Socket::ERROR_NOROUTETOHOST;
              return Ptr<Ipv4Route> ();
            }
          return route;
        }
      else
        {
          RoutingTableEntry newrt;
          if (m_routingTable.LookupRoute (rt.GetNextHop (),newrt))
            {
              route = newrt.GetRoute ();
              NS_ASSERT (route != 0);
              NS_LOG_DEBUG ("A route exists from " << route->GetSource ()
                                                   << " to destination " << dst << " via "
                                                   << rt.GetNextHop ());
              if (oif != 0 && route->GetOutputDevice () != oif)
                {
                  NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
                  sockerr = Socket::ERROR_NOROUTETOHOST;
                  return Ptr<Ipv4Route> ();
                }
              return route;
            }
        }
    }

  if (EnableBuffering)
    {
      uint32_t iif = (oif ? m_ipv4->GetInterfaceForDevice (oif) : -1);
      DeferredRouteOutputTag tag (iif);
      if (!p->PeekPacketTag (tag))
        {
          p->AddPacketTag (tag);
        }
    }
  return LoopbackRoute (header,oif);
}

void
RoutingProtocol::DeferredRouteOutput (Ptr<const Packet> p,
                                      const Ipv4Header & header,
                                      UnicastForwardCallback ucb,
                                      ErrorCallback ecb)
{
  NS_LOG_FUNCTION (this << p << header);
  NS_ASSERT (p != 0 && p != Ptr<Packet> ());
  QueueEntry newEntry (p,header,ucb,ecb);
  bool result = m_queue.Enqueue (newEntry);
  if (result)
    {
      NS_LOG_DEBUG ("Added packet " << p->GetUid () << " to queue.");
    }
}

bool
RoutingProtocol::RouteInput (Ptr<const Packet> p,
                             const Ipv4Header &header,
                             Ptr<const NetDevice> idev,
                             UnicastForwardCallback ucb,
                             MulticastForwardCallback mcb,
                             LocalDeliverCallback lcb,
                             ErrorCallback ecb)
{
  NS_LOG_FUNCTION (m_mainAddress << " received packet " << p->GetUid ()
                                 << " from " << header.GetSource ()
                                 << " on interface " << idev->GetAddress ()
                                 << " to destination " << header.GetDestination ());
  if (m_socketAddresses.empty ())
    {
      NS_LOG_DEBUG ("No dsdv interfaces");
      return false;
    }
  NS_ASSERT (m_ipv4 != 0);
  // Check if input device supports IP
  NS_ASSERT (m_ipv4->GetInterfaceForDevice (idev) >= 0);
  int32_t iif = m_ipv4->GetInterfaceForDevice (idev);

  Ipv4Address dst = header.GetDestination ();
  Ipv4Address origin = header.GetSource ();

  // DSDV is not a multicast routing protocol
  if (dst.IsMulticast ())
    {
      return false;
    }

  // Deferred route request
  if (EnableBuffering == true && idev == m_lo)
    {
      DeferredRouteOutputTag tag;
      if (p->PeekPacketTag (tag))
        {
          DeferredRouteOutput (p,header,ucb,ecb);
          return true;
        }
    }
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
         m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
    {
      Ipv4InterfaceAddress iface = j->second;
      if (origin == iface.GetLocal ())
        {
          return true;
        }
    }
  // LOCAL DELIVARY TO DSDV INTERFACES
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j
       != m_socketAddresses.end (); ++j)
    {
      Ipv4InterfaceAddress iface = j->second;
      if (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()) == iif)
        {
          if (dst == iface.GetBroadcast () || dst.IsBroadcast ())
            {
              Ptr<Packet> packet = p->Copy ();
              if (lcb.IsNull () == false)
                {
                  NS_LOG_LOGIC ("Broadcast local delivery to " << iface.GetLocal ());
                  lcb (p, header, iif);
                  // Fall through to additional processing
                }
              else
                {
                  NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
                  ecb (p, header, Socket::ERROR_NOROUTETOHOST);
                }
              if (header.GetTtl () > 1)
                {
                  NS_LOG_LOGIC ("Forward broadcast. TTL " << (uint16_t) header.GetTtl ());
                  RoutingTableEntry toBroadcast;
                  if (m_routingTable.LookupRoute (dst,toBroadcast,true))
                    {
                      Ptr<Ipv4Route> route = toBroadcast.GetRoute ();
                      ucb (route,packet,header);
                    }
                  else
                    {
                      NS_LOG_DEBUG ("No route to forward. Drop packet " << p->GetUid ());
                    }
                }
              return true;
            }
        }
    }

  if (m_ipv4->IsDestinationAddress (dst, iif))
    {
      if (lcb.IsNull () == false)
        {
          NS_LOG_LOGIC ("Unicast local delivery to " << dst);
          lcb (p, header, iif);
        }
      else
        {
          NS_LOG_ERROR ("Unable to deliver packet locally due to null callback " << p->GetUid () << " from " << origin);
          ecb (p, header, Socket::ERROR_NOROUTETOHOST);
        }
      return true;
    }
  RoutingTableEntry toDst;
  if (m_routingTable.LookupRoute (dst,toDst))
    {
      RoutingTableEntry ne;
      if (m_routingTable.LookupRoute (toDst.GetNextHop (),ne))
        {
          Ptr<Ipv4Route> route = ne.GetRoute ();
          NS_LOG_LOGIC (m_mainAddress << " is forwarding packet " << p->GetUid ()
                                      << " to " << dst
                                      << " from " << header.GetSource ()
                                      << " via nexthop neighbor " << toDst.GetNextHop ());
          ucb (route,p,header);
          return true;
        }
    }
  NS_LOG_LOGIC ("Drop packet " << p->GetUid ()
                               << " as there is no route to forward it.");
  return false;
}

Ptr<Ipv4Route>
RoutingProtocol::LoopbackRoute (const Ipv4Header & hdr, Ptr<NetDevice> oif) const
{
  NS_ASSERT (m_lo != 0);
  Ptr<Ipv4Route> rt = Create<Ipv4Route> ();
  rt->SetDestination (hdr.GetDestination ());
  // rt->SetSource (hdr.GetSource ());
  //
  // Source address selection here is tricky.  The loopback route is
  // returned when DSDV does not have a route; this causes the packet
  // to be looped back and handled (cached) in RouteInput() method
  // while a route is found. However, connection-oriented protocols
  // like TCP need to create an endpoint four-tuple (src, src port,
  // dst, dst port) and create a pseudo-header for checksumming.  So,
  // DSDV needs to guess correctly what the eventual source address
  // will be.
  //
  // For single interface, single address nodes, this is not a problem.
  // When there are possibly multiple outgoing interfaces, the policy
  // implemented here is to pick the first available DSDV interface.
  // If RouteOutput() caller specified an outgoing interface, that
  // further constrains the selection of source address
  //
  std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin ();
  if (oif)
    {
      // Iterate to find an address on the oif device
      for (j = m_socketAddresses.begin (); j != m_socketAddresses.end (); ++j)
        {
          Ipv4Address addr = j->second.GetLocal ();
          int32_t interface = m_ipv4->GetInterfaceForAddress (addr);
          if (oif == m_ipv4->GetNetDevice (static_cast<uint32_t> (interface)))
            {
              rt->SetSource (addr);
              break;
            }
        }
    }
  else
    {
      rt->SetSource (j->second.GetLocal ());
    }
  NS_ASSERT_MSG (rt->GetSource () != Ipv4Address (), "Valid DSDV source address not found");
  rt->SetGateway (Ipv4Address ("127.0.0.1"));
  rt->SetOutputDevice (m_lo);
  return rt;
}

void
RoutingProtocol::RecvDsdv (Ptr<Socket> socket)
{
  CommandPacketCount++;
  Address sourceAddress;
  Ptr<Packet> advpacket = Create<Packet> ();
  Ptr<Packet> packet = socket->RecvFrom (sourceAddress);
  InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom (sourceAddress);
  Ipv4Address sender = inetSourceAddr.GetIpv4 ();
  Ipv4Address receiver = m_socketAddresses[socket].GetLocal ();
  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (receiver));
  uint32_t packetSize = packet->GetSize ();
  NS_LOG_FUNCTION (m_mainAddress << " received dsdv packet of size: " << packetSize
                                 << " and packet id: " << packet->GetUid ());
  uint32_t count = 0;
  for (; packetSize > 0; packetSize = packetSize - 12)
    {
      count = 0;
      DsdvHeader dsdvHeader, tempDsdvHeader;
      packet->RemoveHeader (dsdvHeader);
      NS_LOG_DEBUG ("Processing new update for " << dsdvHeader.GetDst ());
      /*Verifying if the packets sent by me were returned back to me. If yes, discarding them!*/
      for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j
           != m_socketAddresses.end (); ++j)
        {
          Ipv4InterfaceAddress interface = j->second;
          if (dsdvHeader.GetDst () == interface.GetLocal ())
            {
              if (dsdvHeader.GetDstSeqno () % 2 == 1)
                {
                  NS_LOG_DEBUG ("Sent Dsdv update back to the same Destination, "
                                "with infinite metric. Time left to send fwd update: "
                                << m_periodicUpdateTimer.GetDelayLeft ());
                  count++;
                }
              else
                {
                  NS_LOG_DEBUG ("Received update for my address. Discarding this.");
                  count++;
                }
            }
        }
      if (count > 0)
        {
          continue;
        }
      NS_LOG_DEBUG ("Received a DSDV packet from "
                    << sender << " to " << receiver << ". Details are: Destination: " << dsdvHeader.GetDst () << ", Seq No: "
                    << dsdvHeader.GetDstSeqno () << ", HopCount: " << dsdvHeader.GetHopCount ());
      RoutingTableEntry fwdTableEntry, advTableEntry;
      EventId event;
      bool permanentTableVerifier = m_routingTable.LookupRoute (dsdvHeader.GetDst (),fwdTableEntry);
      if (permanentTableVerifier == false)
        {
          if (dsdvHeader.GetDstSeqno () % 2 != 1)
            {
              NS_LOG_DEBUG ("Received New Route!");
              RoutingTableEntry newEntry (
                /*device=*/ dev, /*dst=*/
                dsdvHeader.GetDst (), /*seqno=*/
                dsdvHeader.GetDstSeqno (),
                /*iface=*/ m_ipv4->GetAddress (m_ipv4->GetInterfaceForAddress (receiver), 0),
                /*hops=*/ dsdvHeader.GetHopCount (), /*next hop=*/
                sender, /*lifetime=*/
                Simulator::Now (), /*settlingTime*/
                m_settlingTime, /*entries changed*/
                true);
              newEntry.SetFlag (VALID);
              m_routingTable.AddRoute (newEntry);
              NS_LOG_DEBUG ("New Route added to both tables");
              m_advRoutingTable.AddRoute (newEntry);
            }
          else
            {
              // received update not present in main routing table and also with infinite metric
              NS_LOG_DEBUG ("Discarding this update as this route is not present in "
                            "main routing table and received with infinite metric");
            }
        }
      else
        {
          if (!m_advRoutingTable.LookupRoute (dsdvHeader.GetDst (),advTableEntry))
            {
              RoutingTableEntry tr;
              std::map<Ipv4Address, RoutingTableEntry> allRoutes;
              m_advRoutingTable.GetListOfAllRoutes (allRoutes);
              for (std::map<Ipv4Address, RoutingTableEntry>::const_iterator i = allRoutes.begin (); i != allRoutes.end (); ++i)
                {
                  NS_LOG_DEBUG ("ADV table routes are:" << i->second.GetDestination ());
                }
              // present in fwd table and not in advtable
              m_advRoutingTable.AddRoute (fwdTableEntry);
              m_advRoutingTable.LookupRoute (dsdvHeader.GetDst (),advTableEntry);
            }
          if (dsdvHeader.GetDstSeqno () % 2 != 1)
            {
              if (dsdvHeader.GetDstSeqno () > advTableEntry.GetSeqNo ())
                {
                  // Received update with better seq number. Clear any old events that are running
                  if (m_advRoutingTable.ForceDeleteIpv4Event (dsdvHeader.GetDst ()))
                    {
                      NS_LOG_DEBUG ("Canceling the timer to update route with better seq number");
                    }
                  // if its a changed metric *nomatter* where the update came from, wait  for WST
                  if (dsdvHeader.GetHopCount () != advTableEntry.GetHop ())
                    {
                      advTableEntry.SetSeqNo (dsdvHeader.GetDstSeqno ());
                      advTableEntry.SetLifeTime (Simulator::Now ());
                      advTableEntry.SetFlag (VALID);
                      advTableEntry.SetEntriesChanged (true);
                      advTableEntry.SetNextHop (sender);
                      advTableEntry.SetHop (dsdvHeader.GetHopCount ());
                      NS_LOG_DEBUG ("Received update with better sequence number and changed metric.Waiting for WST");
                      Time tempSettlingtime = GetSettlingTime (dsdvHeader.GetDst ());
                      advTableEntry.SetSettlingTime (tempSettlingtime);
                      NS_LOG_DEBUG ("Added Settling Time:" << tempSettlingtime.GetSeconds ()
                                                           << "s as there is no event running for this route");
                      event = Simulator::Schedule (tempSettlingtime,&RoutingProtocol::SendTriggeredUpdate,this);
                      m_advRoutingTable.AddIpv4Event (dsdvHeader.GetDst (),event);
                      NS_LOG_DEBUG ("EventCreated EventUID: " << event.GetUid ());
                      // if received changed metric, use it but adv it only after wst
                      m_routingTable.Update (advTableEntry);
                      m_advRoutingTable.Update (advTableEntry);
                    }
                  else
                    {
                      // Received update with better seq number and same metric.
                      advTableEntry.SetSeqNo (dsdvHeader.GetDstSeqno ());
                      advTableEntry.SetLifeTime (Simulator::Now ());
                      advTableEntry.SetFlag (VALID);
                      advTableEntry.SetEntriesChanged (true);
                      advTableEntry.SetNextHop (sender);
                      advTableEntry.SetHop (dsdvHeader.GetHopCount ());
                      m_advRoutingTable.Update (advTableEntry);
                      NS_LOG_DEBUG ("Route with better sequence number and same metric received. Advertised without WST");
                    }
                }
              else if (dsdvHeader.GetDstSeqno () == advTableEntry.GetSeqNo ())
                {
                  if (dsdvHeader.GetHopCount () < advTableEntry.GetHop ())
                    {
                      /*Received update with same seq number and better hop count.
                       * As the metric is changed, we will have to wait for WST before sending out this update.
                       */
                      NS_LOG_DEBUG ("Canceling any existing timer to update route with same sequence number "
                                    "and better hop count");
                      m_advRoutingTable.ForceDeleteIpv4Event (dsdvHeader.GetDst ());
                      advTableEntry.SetSeqNo (dsdvHeader.GetDstSeqno ());
                      advTableEntry.SetLifeTime (Simulator::Now ());
                      advTableEntry.SetFlag (VALID);
                      advTableEntry.SetEntriesChanged (true);
                      advTableEntry.SetNextHop (sender);
                      advTableEntry.SetHop (dsdvHeader.GetHopCount ());
                      Time tempSettlingtime = GetSettlingTime (dsdvHeader.GetDst ());
                      advTableEntry.SetSettlingTime (tempSettlingtime);
                      NS_LOG_DEBUG ("Added Settling Time," << tempSettlingtime.GetSeconds ()
                                                           << " as there is no current event running for this route");
                      event = Simulator::Schedule (tempSettlingtime,&RoutingProtocol::SendTriggeredUpdate,this);
                      m_advRoutingTable.AddIpv4Event (dsdvHeader.GetDst (),event);
                      NS_LOG_DEBUG ("EventCreated EventUID: " << event.GetUid ());
                      // if received changed metric, use it but adv it only after wst
                      m_routingTable.Update (advTableEntry);
                      m_advRoutingTable.Update (advTableEntry);
                    }
                  else
                    {
                      /*Received update with same seq number but with same or greater hop count.
                       * Discard that update.
                       */
                      if (!m_advRoutingTable.AnyRunningEvent (dsdvHeader.GetDst ()))
                        {
                          /*update the timer only if nexthop address matches thus discarding
                           * updates to that destination from other nodes.
                           */
                          if (advTableEntry.GetNextHop () == sender)
                            {
                              advTableEntry.SetLifeTime (Simulator::Now ());
                              m_routingTable.Update (advTableEntry);
                            }
                          m_advRoutingTable.DeleteRoute (
                            dsdvHeader.GetDst ());
                        }
                      NS_LOG_DEBUG ("Received update with same seq number and "
                                    "same/worst metric for, " << dsdvHeader.GetDst () << ". Discarding the update.");
                    }
                }
              else
                {
                  // Received update with an old sequence number. Discard the update
                  if (!m_advRoutingTable.AnyRunningEvent (dsdvHeader.GetDst ()))
                    {
                      m_advRoutingTable.DeleteRoute (dsdvHeader.GetDst ());
                    }
                  NS_LOG_DEBUG (dsdvHeader.GetDst () << " : Received update with old seq number. Discarding the update.");
                }
            }
          else
            {
              NS_LOG_DEBUG ("Route with infinite metric received for "
                            << dsdvHeader.GetDst () << " from " << sender);
              // Delete route only if update was received from my nexthop neighbor
              if (sender == advTableEntry.GetNextHop ())
                {
                  NS_LOG_DEBUG ("Triggering an update for this unreachable route:");
                  std::map<Ipv4Address, RoutingTableEntry> dstsWithNextHopSrc;
                  m_routingTable.GetListOfDestinationWithNextHop (dsdvHeader.GetDst (),dstsWithNextHopSrc);
                  m_routingTable.DeleteRoute (dsdvHeader.GetDst ());
                  advTableEntry.SetSeqNo (dsdvHeader.GetDstSeqno ());
                  advTableEntry.SetEntriesChanged (true);
                  m_advRoutingTable.Update (advTableEntry);
                  for (std::map<Ipv4Address, RoutingTableEntry>::iterator i = dstsWithNextHopSrc.begin (); i
                       != dstsWithNextHopSrc.end (); ++i)
                    {
                      i->second.SetSeqNo (i->second.GetSeqNo () + 1);
                      i->second.SetEntriesChanged (true);
                      m_advRoutingTable.AddRoute (i->second);
                      m_routingTable.DeleteRoute (i->second.GetDestination ());
                    }
                }
              else
                {
                  if (!m_advRoutingTable.AnyRunningEvent (dsdvHeader.GetDst ()))
                    {
                      m_advRoutingTable.DeleteRoute (dsdvHeader.GetDst ());
                    }
                  NS_LOG_DEBUG (dsdvHeader.GetDst () <<
                                " : Discard this link break update as it was received from a different neighbor "
                                "and I can reach the destination");
                }
            }
        }
    }
  std::map<Ipv4Address, RoutingTableEntry> allRoutes;
  m_advRoutingTable.GetListOfAllRoutes (allRoutes);
  if (EnableRouteAggregation && allRoutes.size () > 0)
    {
      Simulator::Schedule (m_routeAggregationTime,&RoutingProtocol::SendTriggeredUpdate,this);
    }
  else
    {
      Simulator::Schedule (MicroSeconds (m_uniformRandomVariable->GetInteger (0,1000)),&RoutingProtocol::SendTriggeredUpdate,this);
    }
}


void
RoutingProtocol::SendTriggeredUpdate ()
{
  NS_LOG_FUNCTION (m_mainAddress << " is sending a triggered update");
  std::map<Ipv4Address, RoutingTableEntry> allRoutes;
  m_advRoutingTable.GetListOfAllRoutes (allRoutes);
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j
       != m_socketAddresses.end (); ++j)
    {
      DsdvHeader dsdvHeader;
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();
      for (std::map<Ipv4Address, RoutingTableEntry>::const_iterator i = allRoutes.begin (); i != allRoutes.end (); ++i)
        {
          NS_LOG_LOGIC ("Destination: " << i->second.GetDestination ()
                                        << " SeqNo:" << i->second.GetSeqNo () << " HopCount:"
                                        << i->second.GetHop () + 1);
          RoutingTableEntry temp = i->second;
          if ((i->second.GetEntriesChanged () == true) && (!m_advRoutingTable.AnyRunningEvent (temp.GetDestination ())))
            {
              dsdvHeader.SetDst (i->second.GetDestination ());
              dsdvHeader.SetDstSeqno (i->second.GetSeqNo ());
              dsdvHeader.SetHopCount (i->second.GetHop () + 1);
              temp.SetFlag (VALID);
              temp.SetEntriesChanged (false);
              m_advRoutingTable.DeleteIpv4Event (temp.GetDestination ());
              if (!(temp.GetSeqNo () % 2))
                {
                  m_routingTable.Update (temp);
                }
              packet->AddHeader (dsdvHeader);
              m_advRoutingTable.DeleteRoute (temp.GetDestination ());
              NS_LOG_DEBUG ("Deleted this route from the advertised table");
            }
          else
            {
              EventId event = m_advRoutingTable.GetEventId (temp.GetDestination ());
              NS_ASSERT (event.GetUid () != 0);
              NS_LOG_DEBUG ("EventID " << event.GetUid () << " associated with "
                                       << temp.GetDestination () << " has not expired, waiting in adv table");
            }
        }
      if (packet->GetSize () >= 12)
        {
          RoutingTableEntry temp2;
          m_routingTable.LookupRoute (m_ipv4->GetAddress (1, 0).GetBroadcast (), temp2);
          dsdvHeader.SetDst (m_ipv4->GetAddress (1, 0).GetLocal ());
          dsdvHeader.SetDstSeqno (temp2.GetSeqNo ());
          dsdvHeader.SetHopCount (temp2.GetHop () + 1);
          NS_LOG_DEBUG ("Adding my update as well to the packet");
          packet->AddHeader (dsdvHeader);
          // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
          Ipv4Address destination;
          if (iface.GetMask () == Ipv4Mask::GetOnes ())
            {
              destination = Ipv4Address ("255.255.255.255");
            }
          else
            {
              destination = iface.GetBroadcast ();
            }
          socket->SendTo (packet, 0, InetSocketAddress (destination, DSDV_PORT));
          NS_LOG_FUNCTION ("Sent Triggered Update from "
                           << dsdvHeader.GetDst ()
                           << " with packet id : " << packet->GetUid () << " and packet Size: " << packet->GetSize ());
        }
      else
        {
          NS_LOG_FUNCTION ("Update not sent as there are no updates to be triggered");
        }
    }
}

void
RoutingProtocol::SendPeriodicUpdate ()
{
  std::map<Ipv4Address, RoutingTableEntry> removedAddresses, allRoutes;
  m_routingTable.Purge (removedAddresses);
  MergeTriggerPeriodicUpdates ();
  m_routingTable.GetListOfAllRoutes (allRoutes);
  if (allRoutes.empty ())
    {
      return;
    }
  NS_LOG_FUNCTION (m_mainAddress << " is sending out its periodic update");
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j
       != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      Ptr<Packet> packet = Create<Packet> ();
      for (std::map<Ipv4Address, RoutingTableEntry>::const_iterator i = allRoutes.begin (); i != allRoutes.end (); ++i)
        {
          DsdvHeader dsdvHeader;
          if (i->second.GetHop () == 0)
            {
              RoutingTableEntry ownEntry;
              dsdvHeader.SetDst (m_ipv4->GetAddress (1,0).GetLocal ());
              dsdvHeader.SetDstSeqno (i->second.GetSeqNo () + 2);
              dsdvHeader.SetHopCount (i->second.GetHop () + 1);
              m_routingTable.LookupRoute (m_ipv4->GetAddress (1,0).GetBroadcast (),ownEntry);
              ownEntry.SetSeqNo (dsdvHeader.GetDstSeqno ());
              m_routingTable.Update (ownEntry);
              packet->AddHeader (dsdvHeader);
            }
          else
            {
              dsdvHeader.SetDst (i->second.GetDestination ());
              dsdvHeader.SetDstSeqno ((i->second.GetSeqNo ()));
              dsdvHeader.SetHopCount (i->second.GetHop () + 1);
              packet->AddHeader (dsdvHeader);
            }
          NS_LOG_DEBUG ("Forwarding the update for " << i->first);
          NS_LOG_DEBUG ("Forwarding details are, Destination: " << dsdvHeader.GetDst ()
                                                                << ", SeqNo:" << dsdvHeader.GetDstSeqno ()
                                                                << ", HopCount:" << dsdvHeader.GetHopCount ()
                                                                << ", LifeTime: " << i->second.GetLifeTime ().GetSeconds ());
        }
      for (std::map<Ipv4Address, RoutingTableEntry>::const_iterator rmItr = removedAddresses.begin (); rmItr
           != removedAddresses.end (); ++rmItr)
        {
          DsdvHeader removedHeader;
          removedHeader.SetDst (rmItr->second.GetDestination ());
          removedHeader.SetDstSeqno (rmItr->second.GetSeqNo () + 1);
          removedHeader.SetHopCount (rmItr->second.GetHop () + 1);
          packet->AddHeader (removedHeader);
          NS_LOG_DEBUG ("Update for removed record is: Destination: " << removedHeader.GetDst ()
                                                                      << " SeqNo:" << removedHeader.GetDstSeqno ()
                                                                      << " HopCount:" << removedHeader.GetHopCount ());
        }
      socket->Send (packet);
      // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
      Ipv4Address destination;
      if (iface.GetMask () == Ipv4Mask::GetOnes ())
        {
          destination = Ipv4Address ("255.255.255.255");
        }
      else
        {
          destination = iface.GetBroadcast ();
        }
      socket->SendTo (packet, 0, InetSocketAddress (destination, DSDV_PORT));
      NS_LOG_FUNCTION ("PeriodicUpdate Packet UID is : " << packet->GetUid ());
    }
  m_periodicUpdateTimer.Schedule (m_periodicUpdateInterval + MicroSeconds (25 * m_uniformRandomVariable->GetInteger (0,1000)));
}

void
RoutingProtocol::SetIpv4 (Ptr<Ipv4> ipv4)
{
  NS_ASSERT (ipv4 != 0);
  NS_ASSERT (m_ipv4 == 0);
  m_ipv4 = ipv4;
  // Create lo route. It is asserted that the only one interface up for now is loopback
  NS_ASSERT (m_ipv4->GetNInterfaces () == 1 && m_ipv4->GetAddress (0, 0).GetLocal () == Ipv4Address ("127.0.0.1"));
  m_lo = m_ipv4->GetNetDevice (0);
  NS_ASSERT (m_lo != 0);
  // Remember lo route
  RoutingTableEntry rt (
    /*device=*/ m_lo,  /*dst=*/
    Ipv4Address::GetLoopback (), /*seqno=*/
    0,
    /*iface=*/ Ipv4InterfaceAddress (Ipv4Address::GetLoopback (),Ipv4Mask ("255.0.0.0")),
    /*hops=*/ 0,  /*next hop=*/
    Ipv4Address::GetLoopback (),
    /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  rt.SetFlag (INVALID);
  rt.SetEntriesChanged (false);
  m_routingTable.AddRoute (rt);
  Simulator::ScheduleNow (&RoutingProtocol::Start,this);
}

void
RoutingProtocol::NotifyInterfaceUp (uint32_t i)
{
  NS_LOG_FUNCTION (this << m_ipv4->GetAddress (i, 0).GetLocal ()
                        << " interface is up");
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  Ipv4InterfaceAddress iface = l3->GetAddress (i,0);
  if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
    {
      return;
    }
  // Create a socket to listen only on this interface
  Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),UdpSocketFactory::GetTypeId ());
  NS_ASSERT (socket != 0);
  socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvDsdv,this));
  socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), DSDV_PORT));
  socket->BindToNetDevice (l3->GetNetDevice (i));
  socket->SetAllowBroadcast (true);
  socket->SetAttribute ("IpTtl",UintegerValue (1));
  m_socketAddresses.insert (std::make_pair (socket,iface));
  // Add local broadcast record to the routing table
  Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
  RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (), /*seqno=*/ 0,/*iface=*/ iface,/*hops=*/ 0,
                                    /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
  m_routingTable.AddRoute (rt);
  if (m_mainAddress == Ipv4Address ())
    {
      m_mainAddress = iface.GetLocal ();
    }
  NS_ASSERT (m_mainAddress != Ipv4Address ());
}

void
RoutingProtocol::NotifyInterfaceDown (uint32_t i)
{
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  Ptr<NetDevice> dev = l3->GetNetDevice (i);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (m_ipv4->GetAddress (i,0));
  NS_ASSERT (socket);
  socket->Close ();
  m_socketAddresses.erase (socket);
  if (m_socketAddresses.empty ())
    {
      NS_LOG_LOGIC ("No dsdv interfaces");
      m_routingTable.Clear ();
      return;
    }
  m_routingTable.DeleteAllRoutesFromInterface (m_ipv4->GetAddress (i,0));
  m_advRoutingTable.DeleteAllRoutesFromInterface (m_ipv4->GetAddress (i,0));
}

void
RoutingProtocol::NotifyAddAddress (uint32_t i,
                                   Ipv4InterfaceAddress address)
{
  NS_LOG_FUNCTION (this << " interface " << i << " address " << address);
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  if (!l3->IsUp (i))
    {
      return;
    }
  Ipv4InterfaceAddress iface = l3->GetAddress (i,0);
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (iface);
  if (!socket)
    {
      if (iface.GetLocal () == Ipv4Address ("127.0.0.1"))
        {
          return;
        }
      Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),UdpSocketFactory::GetTypeId ());
      NS_ASSERT (socket != 0);
      socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvDsdv,this));
      // Bind to any IP address so that broadcasts can be received
      socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), DSDV_PORT));
      socket->BindToNetDevice (l3->GetNetDevice (i));
      socket->SetAllowBroadcast (true);
      m_socketAddresses.insert (std::make_pair (socket,iface));
      Ptr<NetDevice> dev = m_ipv4->GetNetDevice (m_ipv4->GetInterfaceForAddress (iface.GetLocal ()));
      RoutingTableEntry rt (/*device=*/ dev, /*dst=*/ iface.GetBroadcast (),/*seqno=*/ 0, /*iface=*/ iface,/*hops=*/ 0,
                                        /*next hop=*/ iface.GetBroadcast (), /*lifetime=*/ Simulator::GetMaximumSimulationTime ());
      m_routingTable.AddRoute (rt);
    }
}

void
RoutingProtocol::NotifyRemoveAddress (uint32_t i,
                                      Ipv4InterfaceAddress address)
{
  Ptr<Socket> socket = FindSocketWithInterfaceAddress (address);
  if (socket)
    {
      m_socketAddresses.erase (socket);
      Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
      if (l3->GetNAddresses (i))
        {
          Ipv4InterfaceAddress iface = l3->GetAddress (i,0);
          // Create a socket to listen only on this interface
          Ptr<Socket> socket = Socket::CreateSocket (GetObject<Node> (),UdpSocketFactory::GetTypeId ());
          NS_ASSERT (socket != 0);
          socket->SetRecvCallback (MakeCallback (&RoutingProtocol::RecvDsdv,this));
          // Bind to any IP address so that broadcasts can be received
          socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), DSDV_PORT));
          socket->SetAllowBroadcast (true);
          m_socketAddresses.insert (std::make_pair (socket,iface));
        }
    }
}

Ptr<Socket>
RoutingProtocol::FindSocketWithInterfaceAddress (Ipv4InterfaceAddress addr) const
{
  for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin (); j
       != m_socketAddresses.end (); ++j)
    {
      Ptr<Socket> socket = j->first;
      Ipv4InterfaceAddress iface = j->second;
      if (iface == addr)
        {
          return socket;
        }
    }
  Ptr<Socket> socket;
  return socket;
}

void
RoutingProtocol::Send (Ptr<Ipv4Route> route,
                       Ptr<const Packet> packet,
                       const Ipv4Header & header)
{
  Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol> ();
  NS_ASSERT (l3 != 0);
  Ptr<Packet> p = packet->Copy ();
  l3->Send (p,route->GetSource (),header.GetDestination (),header.GetProtocol (),route);
}

void
RoutingProtocol::Drop (Ptr<const Packet> packet,
                       const Ipv4Header & header,
                       Socket::SocketErrno err)
{
  NS_LOG_DEBUG (m_mainAddress << " drop packet " << packet->GetUid () << " to "
                              << header.GetDestination () << " from queue. Error " << err);
}

void
RoutingProtocol::LookForQueuedPackets ()
{
  NS_LOG_FUNCTION (this);
  Ptr<Ipv4Route> route;
  std::map<Ipv4Address, RoutingTableEntry> allRoutes;
  m_routingTable.GetListOfAllRoutes (allRoutes);
  for (std::map<Ipv4Address, RoutingTableEntry>::const_iterator i = allRoutes.begin (); i != allRoutes.end (); ++i)
    {
      RoutingTableEntry rt;
      rt = i->second;
      if (m_queue.Find (rt.GetDestination ()))
        {
          if (rt.GetHop () == 1)
            {
              route = rt.GetRoute ();
              NS_LOG_LOGIC ("A route exists from " << route->GetSource ()
                                                   << " to neighboring destination "
                                                   << route->GetDestination ());
              NS_ASSERT (route != 0);
            }
          else
            {
              RoutingTableEntry newrt;
              m_routingTable.LookupRoute (rt.GetNextHop (),newrt);
              route = newrt.GetRoute ();
              NS_LOG_LOGIC ("A route exists from " << route->GetSource ()
                                                   << " to destination " << route->GetDestination () << " via "
                                                   << rt.GetNextHop ());
              NS_ASSERT (route != 0);
            }
          SendPacketFromQueue (rt.GetDestination (),route);
        }
    }
}

void
RoutingProtocol::SendPacketFromQueue (Ipv4Address dst,
                                      Ptr<Ipv4Route> route)
{
  NS_LOG_DEBUG (m_mainAddress << " is sending a queued packet to destination " << dst);
  QueueEntry queueEntry;
  if (m_queue.Dequeue (dst,queueEntry))
    {
      DeferredRouteOutputTag tag;
      Ptr<Packet> p = ConstCast<Packet> (queueEntry.GetPacket ());
      if (p->RemovePacketTag (tag))
        {
          if (tag.oif != -1 && tag.oif != m_ipv4->GetInterfaceForDevice (route->GetOutputDevice ()))
            {
              NS_LOG_DEBUG ("Output device doesn't match. Dropped.");
              return;
            }
        }
      UnicastForwardCallback ucb = queueEntry.GetUnicastForwardCallback ();
      Ipv4Header header = queueEntry.GetIpv4Header ();
      header.SetSource (route->GetSource ());
      header.SetTtl (header.GetTtl () + 1); // compensate extra TTL decrement by fake loopback routing
      ucb (route,p,header);
      if (m_queue.GetSize () != 0 && m_queue.Find (dst))
        {
          Simulator::Schedule (MilliSeconds (m_uniformRandomVariable->GetInteger (0,100)),
                               &RoutingProtocol::SendPacketFromQueue,this,dst,route);
        }
    }
}

Time
RoutingProtocol::GetSettlingTime (Ipv4Address address)
{
  NS_LOG_FUNCTION ("Calculating the settling time for " << address);
  RoutingTableEntry mainrt;
  Time weightedTime;
  m_routingTable.LookupRoute (address,mainrt);
  if (EnableWST)
    {
      if (mainrt.GetSettlingTime () == Seconds (0))
        {
          return Seconds (0);
        }
      else
        {
          NS_LOG_DEBUG ("Route SettlingTime: " << mainrt.GetSettlingTime ().GetSeconds ()
                                               << " and LifeTime:" << mainrt.GetLifeTime ().GetSeconds ());
          weightedTime = Time (m_weightedFactor * mainrt.GetSettlingTime ().GetSeconds () + (1.0 - m_weightedFactor)
                               * mainrt.GetLifeTime ().GetSeconds ());
          NS_LOG_DEBUG ("Calculated weightedTime:" << weightedTime.GetSeconds ());
          return weightedTime;
        }
    }
  return mainrt.GetSettlingTime ();
}

void
RoutingProtocol::MergeTriggerPeriodicUpdates ()
{
  NS_LOG_FUNCTION ("Merging advertised table changes with main table before sending out periodic update");
  std::map<Ipv4Address, RoutingTableEntry> allRoutes;
  m_advRoutingTable.GetListOfAllRoutes (allRoutes);
  if (allRoutes.size () > 0)
    {
      for (std::map<Ipv4Address, RoutingTableEntry>::const_iterator i = allRoutes.begin (); i != allRoutes.end (); ++i)
        {
          RoutingTableEntry advEntry = i->second;
          if ((advEntry.GetEntriesChanged () == true) && (!m_advRoutingTable.AnyRunningEvent (advEntry.GetDestination ())))
            {
              if (!(advEntry.GetSeqNo () % 2))
                {
                  advEntry.SetFlag (VALID);
                  advEntry.SetEntriesChanged (false);
                  m_routingTable.Update (advEntry);
                  NS_LOG_DEBUG ("Merged update for " << advEntry.GetDestination () << " with main routing Table");
                }
              m_advRoutingTable.DeleteRoute (advEntry.GetDestination ());
            }
          else
            {
              NS_LOG_DEBUG ("Event currently running. Cannot Merge Routing Tables");
            }
        }
    }
}
}
}
```
### dsdv-routing-protocol.h
```c++
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2010 Hemanth Narra, Yufei Cheng
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Hemanth Narra <hemanth@ittc.ku.com>
 * Author: Yufei Cheng   <yfcheng@ittc.ku.edu>
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  http://wiki.ittc.ku.edu/resilinets
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

#ifndef DSDV_ROUTING_PROTOCOL_H
#define DSDV_ROUTING_PROTOCOL_H

#include "dsdv-rtable.h"
#include "dsdv-packet-queue.h"
#include "dsdv-packet.h"
#include "ns3/node.h"
#include "ns3/random-variable-stream.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/output-stream-wrapper.h"

namespace ns3 {
namespace dsdv {

/**
 * \ingroup dsdv
 * \brief DSDV routing protocol.
 */
class RoutingProtocol : public Ipv4RoutingProtocol
{
public:
  static TypeId
  GetTypeId (void);
  static const uint32_t DSDV_PORT;
  static int CommandPacketCount;

  /// c-tor
  RoutingProtocol ();
  virtual
  ~RoutingProtocol ();
  virtual void
  DoDispose ();

  // From Ipv4RoutingProtocol
  Ptr<Ipv4Route> RouteOutput (Ptr<Packet> p, const Ipv4Header &header, Ptr<NetDevice> oif, Socket::SocketErrno &sockerr);
  bool RouteInput (Ptr<const Packet> p, const Ipv4Header &header, Ptr<const NetDevice> idev, UnicastForwardCallback ucb,
                   MulticastForwardCallback mcb, LocalDeliverCallback lcb, ErrorCallback ecb);
  virtual void PrintRoutingTable (Ptr<OutputStreamWrapper> stream) const;
  virtual void NotifyInterfaceUp (uint32_t interface);
  virtual void NotifyInterfaceDown (uint32_t interface);
  virtual void NotifyAddAddress (uint32_t interface, Ipv4InterfaceAddress address);
  virtual void NotifyRemoveAddress (uint32_t interface, Ipv4InterfaceAddress address);
  virtual void SetIpv4 (Ptr<Ipv4> ipv4);

  // Methods to handle protocol parameters
  void SetEnableBufferFlag (bool f);
  bool GetEnableBufferFlag () const;
  void SetWSTFlag (bool f);
  bool GetWSTFlag () const;
  void SetEnableRAFlag (bool f);
  bool GetEnableRAFlag () const;

 /**
  * Assign a fixed random variable stream number to the random variables
  * used by this model.  Return the number of streams (possibly zero) that
  * have been assigned.
  *
  * \param stream first stream index to use
  * \return the number of stream indices assigned by this model
  */
  int64_t AssignStreams (int64_t stream);

private:
  
  // Protocol parameters.
  /// Holdtimes is the multiplicative factor of PeriodicUpdateInterval for which the node waits since the last update
  /// before flushing a route from the routing table. If PeriodicUpdateInterval is 8s and Holdtimes is 3, the node
  /// waits for 24s since the last update to flush this route from its routing table.
  uint32_t Holdtimes;
  /// PeriodicUpdateInterval specifies the periodic time interval between which the a node broadcasts
  /// its entire routing table.
  Time m_periodicUpdateInterval;
  /// SettlingTime specifies the time for which a node waits before propagating an update.
  /// It waits for this time interval in hope of receiving an update with a better metric.
  Time m_settlingTime;
  /// Nodes IP address
  Ipv4Address m_mainAddress;
  /// IP protocol
  Ptr<Ipv4> m_ipv4;
  /// Raw socket per each IP interface, map socket -> iface address (IP + mask)
  std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_socketAddresses;
  /// Loopback device used to defer route requests until a route is found
  Ptr<NetDevice> m_lo;
  /// Main Routing table for the node
  RoutingTable m_routingTable;
  /// Advertised Routing table for the node
  RoutingTable m_advRoutingTable;
  /// The maximum number of packets that we allow a routing protocol to buffer.
  uint32_t m_maxQueueLen;
  /// The maximum number of packets that we allow per destination to buffer.
  uint32_t m_maxQueuedPacketsPerDst;
  /// The maximum period of time that a routing protocol is allowed to buffer a packet for.
  Time m_maxQueueTime;
  /// A "drop front on full" queue used by the routing layer to buffer packets to which it does not have a route.
  PacketQueue m_queue;
  /// Flag that is used to enable or disable buffering
  bool EnableBuffering;
  /// Flag that is used to enable or disable Weighted Settling Time
  bool EnableWST;
  /// This is the wighted factor to determine the weighted settling time
  double m_weightedFactor;
  /// This is a flag to enable route aggregation. Route aggregation will aggregate all routes for
  /// 'RouteAggregationTime' from the time an update is received by a node and sends them as a single update .
  bool EnableRouteAggregation;
  /// Parameter that holds the route aggregation time interval
  Time m_routeAggregationTime;
  /// Unicast callback for own packets
  UnicastForwardCallback m_scb;
  /// Error callback for own packets
  ErrorCallback m_ecb;

private:
  
  /// Start protocol operation
  void
  Start ();
  /// Queue packet untill we find a route
  void
  DeferredRouteOutput (Ptr<const Packet> p, const Ipv4Header & header, UnicastForwardCallback ucb, ErrorCallback ecb);
  /// Look for any queued packets to send them out
  void
  LookForQueuedPackets (void);
  /**
   * Send packet from queue
   * \param dst - destination address to which we are sending the packet to
   * \param route - route identified for this packet
   */
  void
  SendPacketFromQueue (Ipv4Address dst, Ptr<Ipv4Route> route);
  /// Find socket with local interface address iface
  Ptr<Socket>
  FindSocketWithInterfaceAddress (Ipv4InterfaceAddress iface) const;
  
  // Receive dsdv control packets
  /// Receive and process dsdv control packet
  void
  RecvDsdv (Ptr<Socket> socket);

  void
  Send (Ptr<Ipv4Route>, Ptr<const Packet>, const Ipv4Header &);
  /// Create loopback route for given header
  Ptr<Ipv4Route>
  LoopbackRoute (const Ipv4Header & header, Ptr<NetDevice> oif) const;
  /**
   * Get settlingTime for a destination
   * \param dst - destination address
   * \return settlingTime for the destination if found
   */
  Time
  GetSettlingTime (Ipv4Address dst);
  /// Sends trigger update from a node
  void
  SendTriggeredUpdate ();
  /// Broadcasts the entire routing table for every PeriodicUpdateInterval
  void
  SendPeriodicUpdate ();
  void
  MergeTriggerPeriodicUpdates ();
  /// Notify that packet is dropped for some reason
  void
  Drop (Ptr<const Packet>, const Ipv4Header &, Socket::SocketErrno);
  /// Timer to trigger periodic updates from a node
  Timer m_periodicUpdateTimer;
  /// Timer used by the trigger updates in case of Weighted Settling Time is used
  Timer m_triggeredExpireTimer;

  /// Provides uniform random variables.
  Ptr<UniformRandomVariable> m_uniformRandomVariable;  
};

}
}

#endif /* DSDV_ROUTING_PROTOCOL_H */
```
