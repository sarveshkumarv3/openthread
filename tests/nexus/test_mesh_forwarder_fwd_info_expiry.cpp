/*
 *  Copyright (c) 2026, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>

#include <openthread/platform/radio.h>

#include "net/checksum.hpp"
#include "net/ip6_headers.hpp"
#include "platform/nexus_core.hpp"
#include "platform/nexus_node.hpp"
#include "thread/mesh_forwarder.hpp"
#include "thread/message_framer.hpp"

namespace ot {

/**
 * Provides test access to the `MeshForwarder` forwarded-frame info list.
 */
class UnitTester
{
public:
    static uint16_t GetFwdFrameInfoCount(Nexus::Node &aNode)
    {
        return aNode.Get<MeshForwarder>().mFwdFrameInfoArray.GetLength();
    }

    static uint16_t GetFwdFrameInfoCapacity(Nexus::Node &aNode)
    {
        return aNode.Get<MeshForwarder>().mFwdFrameInfoArray.GetMaxSize();
    }
};

namespace Nexus {

static constexpr uint16_t kPayloadLength = 250; // Large enough for the datagram to need several fragments.

static Message *BuildIpMessage(Node &aOwner, const Ip6::Address &aSource, const Ip6::Address &aDestination)
{
    Message *message = aOwner.Get<MessagePool>().Allocate(Message::kTypeIp6);

    VerifyOrQuit(message != nullptr);

    Ip6::Header ip6Header;
    ip6Header.InitVersionTrafficClassFlow();
    ip6Header.SetPayloadLength(static_cast<uint16_t>(sizeof(Ip6::UdpHeader) + kPayloadLength));
    ip6Header.SetNextHeader(Ip6::kProtoUdp);
    ip6Header.SetHopLimit(Ip6::kDefaultHopLimit);
    ip6Header.SetSource(aSource);
    ip6Header.SetDestination(aDestination);

    Ip6::UdpHeader udpHeader;
    udpHeader.Clear();
    udpHeader.SetSourcePort(12345);
    udpHeader.SetDestinationPort(12345);
    udpHeader.SetLength(static_cast<uint16_t>(sizeof(Ip6::UdpHeader) + kPayloadLength));
    udpHeader.SetChecksum(0);

    SuccessOrQuit(message->Append(ip6Header));
    SuccessOrQuit(message->Append(udpHeader));

    for (uint16_t i = 0; i < kPayloadLength; i++)
    {
        SuccessOrQuit(message->Append<uint8_t>(static_cast<uint8_t>(i)));
    }

    message->SetOffset(sizeof(Ip6::Header));
    Checksum::UpdateMessageChecksum(*message, aSource, aDestination, Ip6::kProtoUdp);
    message->SetOffset(0);
    message->SetLinkSecurityEnabled(true);

    return message;
}

// Frames the next fragment of `aMessage` as a mesh-header frame sent by `aRelay` to `aForwarder`, delivers it
// to `aForwarder`, and returns the offset of the following fragment.
static uint16_t DeliverNextFragment(Node                 &aRelay,
                                    Node                 &aForwarder,
                                    Message              &aMessage,
                                    const Mac::Addresses &aMacAddresses,
                                    uint16_t              aMeshSource,
                                    uint16_t              aMeshDestination)
{
    Radio::Frame frame;
    uint16_t     nextOffset =
        aRelay.Get<MessageFramer>().PrepareFrame(frame, aMessage, aMacAddresses, true, aMeshSource, aMeshDestination);

    VerifyOrQuit(nextOffset > aMessage.GetOffset());
    SuccessOrQuit(otMacFrameProcessTxSfd(&frame, Core::Get().GetNowMicro64(), &aRelay.mRadio.mRadioContext));
    frame.UpdateFcs();

    Radio::Frame rxFrame(frame);
    rxFrame.mInfo.mRxInfo.mTimestamp = Core::Get().GetNowMicro64();
    rxFrame.mInfo.mRxInfo.mRssi      = -20;
    rxFrame.mInfo.mRxInfo.mLqi       = 255;
    otPlatRadioReceiveDone(&aForwarder.GetInstance(), &rxFrame, kErrorNone);

    return nextOffset;
}

struct Topology
{
    Node *mForwarder; // The router under test, it forwards the injected fragments.
    Node *mRelay;     // The neighbor that appears to hand fragments to `mForwarder`.
    Node *mOrigin;    // Mesh source of the injected fragments.
    Node *mTarget;    // Mesh destination of the injected fragments.
};

static void InitializeTopology(Core &aNexus, Topology &aTopology)
{
    aTopology.mForwarder = &aNexus.CreateNode();
    aTopology.mRelay     = &aNexus.CreateNode();
    aTopology.mOrigin    = &aNexus.CreateNode();
    aTopology.mTarget    = &aNexus.CreateNode();

    aTopology.mForwarder->Get<Mle::Mle>().SetRouterSelectionJitter(1);
    aTopology.mRelay->Get<Mle::Mle>().SetRouterSelectionJitter(1);
    aTopology.mOrigin->Get<Mle::Mle>().SetRouterSelectionJitter(1);
    aTopology.mTarget->Get<Mle::Mle>().SetRouterSelectionJitter(1);

    aTopology.mForwarder->Form();
    aNexus.AdvanceTime(15 * 1000);
    aTopology.mRelay->Join(*aTopology.mForwarder, Node::kAsFtd);
    aTopology.mOrigin->Join(*aTopology.mForwarder, Node::kAsFtd);
    aTopology.mTarget->Join(*aTopology.mForwarder, Node::kAsFtd);
    aNexus.AdvanceTime(120 * 1000);

    VerifyOrQuit(aTopology.mForwarder->Get<Mle::Mle>().IsRouterOrLeader());
    VerifyOrQuit(aTopology.mRelay->Get<Mle::Mle>().IsRouter());
    VerifyOrQuit(aTopology.mOrigin->Get<Mle::Mle>().IsRouter());
    VerifyOrQuit(aTopology.mTarget->Get<Mle::Mle>().IsRouter());
}

// Creates a new datagram (it gets its own fragmentation tag).
static Message *NewDatagram(Topology &aTopology)
{
    return BuildIpMessage(*aTopology.mRelay, aTopology.mOrigin->Get<Mle::Mle>().GetMeshLocalRloc(),
                          aTopology.mTarget->Get<Mle::Mle>().GetMeshLocalRloc());
}

// Delivers the next fragment of `aMessage` to the forwarder. Returns `true` if more fragments remain.
static bool DeliverNextFragmentOfDatagram(Topology &aTopology, Message &aMessage)
{
    Mac::Addresses addresses;

    addresses.mSource.SetShort(aTopology.mRelay->Get<Mac::Mac>().GetShortAddress());
    addresses.mDestination.SetShort(aTopology.mForwarder->Get<Mac::Mac>().GetShortAddress());

    uint16_t meshSource      = aTopology.mOrigin->Get<Mac::Mac>().GetShortAddress();
    uint16_t meshDestination = aTopology.mTarget->Get<Mac::Mac>().GetShortAddress();
    uint16_t nextOffset =
        DeliverNextFragment(*aTopology.mRelay, *aTopology.mForwarder, aMessage, addresses, meshSource, meshDestination);

    aMessage.SetOffset(nextOffset);

    return aMessage.GetOffset() < aMessage.GetLength();
}

// Creates a new datagram, and delivers either only its first fragment or all of its fragments to the forwarder.
static void InjectDatagram(Topology &aTopology, bool aFirstFragmentOnly)
{
    OwnedPtr<Message> message(NewDatagram(aTopology));
    bool              hasMore;

    do
    {
        hasMore = DeliverNextFragmentOfDatagram(aTopology, *message);
    } while (hasMore && !aFirstFragmentOnly);

    VerifyOrQuit(hasMore == aFirstFragmentOnly); // A first-fragment-only datagram has more fragments, never sent.
}

void TestIncompleteDatagramsAreNotHeldForever(void)
{
    Core     nexus;
    Topology topology;

    Log("---------------------------------------------------------------------------------------");
    Log("TestIncompleteDatagramsAreNotHeldForever");

    InitializeTopology(nexus, topology);

    Node    &forwarder = *topology.mForwarder;
    uint16_t capacity  = UnitTester::GetFwdFrameInfoCapacity(forwarder);

    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == 0);

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    Log("Forward first fragments of more datagrams than the list can track, their last fragments never arrive");

    for (uint16_t i = 0; i < capacity + 4; i++)
    {
        InjectDatagram(topology, /* aFirstFragmentOnly */ true);
        nexus.AdvanceTime(50);
    }

    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == capacity);

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    Log("Entries of incomplete datagrams are kept for a while");

    nexus.AdvanceTime(500);
    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == capacity);

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    Log("Entries of incomplete datagrams are released well before 4 minutes (tens of seconds is long enough)");

    nexus.AdvanceTime(30 * 1000);
    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == 0);

    // - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    Log("A new datagram can be tracked again");

    InjectDatagram(topology, /* aFirstFragmentOnly */ true);
    nexus.AdvanceTime(50);
    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == 1);
}

void TestCompleteDatagramReleasesEntry(void)
{
    Core     nexus;
    Topology topology;

    Log("---------------------------------------------------------------------------------------");
    Log("TestCompleteDatagramReleasesEntry");

    InitializeTopology(nexus, topology);

    Node &forwarder = *topology.mForwarder;

    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == 0);

    InjectDatagram(topology, /* aFirstFragmentOnly */ false);
    nexus.AdvanceTime(1000);

    // The entry is removed as soon as the last fragment is prepared for tx.
    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == 0);
}

void TestEntryIsRefreshedByEachFragment(void)
{
    static constexpr uint32_t kGapBetweenFragments = 2000; // Shorter than the retain time, but a few gaps exceed it.

    Core     nexus;
    Topology topology;

    Log("---------------------------------------------------------------------------------------");
    Log("TestEntryIsRefreshedByEachFragment");

    InitializeTopology(nexus, topology);

    Node             &forwarder = *topology.mForwarder;
    OwnedPtr<Message> message(NewDatagram(topology));
    uint16_t          fragmentCount = 0;
    bool              hasMore;

    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == 0);

    do
    {
        hasMore = DeliverNextFragmentOfDatagram(topology, *message);
        fragmentCount++;

        if (hasMore)
        {
            nexus.AdvanceTime(kGapBetweenFragments);

            // The entry must still be there, even though more than the retain time has passed since the first
            // fragment, because each fragment restarts the retain time.
            VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == 1);
        }
    } while (hasMore);

    // The datagram was spread over more than the retain time (reassembly timeout + 1 second).
    VerifyOrQuit(fragmentCount >= 3);
    VerifyOrQuit((fragmentCount - 1) * kGapBetweenFragments > 3 * 1000);

    nexus.AdvanceTime(1000);
    VerifyOrQuit(UnitTester::GetFwdFrameInfoCount(forwarder) == 0);
}

} // namespace Nexus
} // namespace ot

int main(void)
{
    ot::Nexus::TestCompleteDatagramReleasesEntry();
    ot::Nexus::TestEntryIsRefreshedByEachFragment();
    ot::Nexus::TestIncompleteDatagramsAreNotHeldForever();
    printf("All tests passed\n");
    return 0;
}
