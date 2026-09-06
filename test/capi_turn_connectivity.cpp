/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "test.hpp"
#include <rtc/rtc.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif

#define BUFFER_SIZE 4096

namespace {

typedef struct {
	rtcState state;
	rtcIceState iceState;
	int pc;
	int dc;
	bool connected;
} Peer;

Peer *peer1 = nullptr;
Peer *peer2 = nullptr;

void RTC_API descriptionCallback(int pc, const char *sdp, const char *type, void *ptr) {
	Peer *peer = (Peer *)ptr;
	Peer *other = peer == peer1 ? peer2 : peer1;
	rtcSetRemoteDescription(other->pc, sdp, type);
}

void RTC_API candidateCallback(int pc, const char *cand, const char *mid, void *ptr) {
	Peer *peer = (Peer *)ptr;
	Peer *other = peer == peer1 ? peer2 : peer1;
	rtcAddRemoteCandidate(other->pc, cand, mid);
}

void RTC_API stateChangeCallback(int pc, rtcState state, void *ptr) {
	Peer *peer = (Peer *)ptr;
	peer->state = state;
	printf("State %d: %d\n", peer == peer1 ? 1 : 2, (int)state);
}

void RTC_API iceStateChangeCallback(int pc, rtcIceState state, void *ptr) {
	Peer *peer = (Peer *)ptr;
	peer->iceState = state;
	printf("ICE state %d: %d\n", peer == peer1 ? 1 : 2, (int)state);
}

void RTC_API openCallback(int id, void *ptr) {
	Peer *peer = (Peer *)ptr;
	peer->connected = true;
	printf("DataChannel %d: Open\n", peer == peer1 ? 1 : 2);
	rtcSendMessage(peer->dc, "Hello over relay", -1);
}

void RTC_API dataChannelCallback(int pc, int dc, void *ptr) {
	Peer *peer = (Peer *)ptr;
	rtcSetOpenCallback(dc, openCallback);
	peer->dc = dc;
}

Peer *createPeer(const rtcConfiguration *config) {
	Peer *peer = (Peer *)malloc(sizeof(Peer));
	if (!peer)
		return nullptr;
	memset(peer, 0, sizeof(Peer));

	peer->pc = rtcCreatePeerConnection(config);
	rtcSetUserPointer(peer->pc, peer);
	rtcSetDataChannelCallback(peer->pc, dataChannelCallback);
	rtcSetLocalDescriptionCallback(peer->pc, descriptionCallback);
	rtcSetLocalCandidateCallback(peer->pc, candidateCallback);
	rtcSetStateChangeCallback(peer->pc, stateChangeCallback);
	rtcSetIceStateChangeCallback(peer->pc, iceStateChangeCallback);

	return peer;
}

void deletePeer(Peer *peer) {
	if (peer) {
		if (peer->dc)
			rtcDeleteDataChannel(peer->dc);
		if (peer->pc)
			rtcDeletePeerConnection(peer->pc);
		free(peer);
	}
}

// Forces both peers to gather relay-only candidates on the given TURN server, connects them
// through it, and checks that the negotiated relay transport matches expectations.
int runTurnRelayConnectivityMain(const char *url, rtcRelayTransport expectedRelayTransport) {
	const char *iceServers[1] = {url};

	rtcConfiguration config1;
	memset(&config1, 0, sizeof(config1));
	config1.iceServers = iceServers;
	config1.iceServersCount = 1;
	config1.iceTransportPolicy = RTC_TRANSPORT_POLICY_RELAY;

	rtcConfiguration config2;
	memset(&config2, 0, sizeof(config2));
	config2.iceServers = iceServers;
	config2.iceServersCount = 1;
	config2.iceTransportPolicy = RTC_TRANSPORT_POLICY_RELAY;

	peer1 = createPeer(&config1);
	peer2 = createPeer(&config2);
	if (!peer1 || !peer2)
		goto error;

	peer1->dc = rtcCreateDataChannel(peer1->pc, "test");
	rtcSetOpenCallback(peer1->dc, openCallback);

	{
		// Same budget as the C++ TURN test in turn_connectivity.cpp: allocating a relay over
		// TCP or TLS can take appreciably longer than over UDP
		int attempts = 20;
		while ((!peer1->connected || !peer2->connected) && attempts--)
			sleep(1);
	}

	if (peer1->state != RTC_CONNECTED || peer2->state != RTC_CONNECTED) {
		fprintf(stderr, "PeerConnection is not connected\n");
		goto error;
	}

	if (!peer1->connected || !peer2->connected) {
		fprintf(stderr, "DataChannel is not connected\n");
		goto error;
	}

	{
		char local[BUFFER_SIZE], remote[BUFFER_SIZE];
		if (rtcGetSelectedCandidatePair(peer1->pc, local, BUFFER_SIZE, remote, BUFFER_SIZE) < 0) {
			fprintf(stderr, "rtcGetSelectedCandidatePair failed\n");
			goto error;
		}
		printf("Local candidate 1: %s\n", local);
		if (!strstr(local, "typ relay")) {
			fprintf(stderr, "Connection is not relayed as expected\n");
			goto error;
		}
	}

	{
		int relayTransport = rtcGetSelectedRelayTransport(peer1->pc);
		if (relayTransport < 0) {
			fprintf(stderr, "rtcGetSelectedRelayTransport failed\n");
			goto error;
		}
		if (relayTransport != (int)expectedRelayTransport) {
			fprintf(stderr, "Unexpected relay transport was negotiated: %d\n", relayTransport);
			goto error;
		}
	}

	sleep(1); // let the "Hello over relay" message be exchanged

	deletePeer(peer1);
	sleep(1);
	deletePeer(peer2);
	sleep(1);

	printf("Success\n");
	return 0;

error:
	deletePeer(peer1);
	deletePeer(peer2);
	return -1;
}

} // namespace

// Requires a TURN server reachable over UDP, same env vars as deps/libjuice/test/turn2.c and
// turn_connectivity.cpp: TURN_HOST, TURN_PORT, TURN_USERNAME, TURN_PASSWORD.
// Skips (reports success) if unset.
TestResult test_capi_turn_connectivity() {
	rtcInitLogger(RTC_LOG_DEBUG, nullptr);

	const char *host = getenv("TURN_HOST");
	const char *port = getenv("TURN_PORT");
	const char *username = getenv("TURN_USERNAME");
	const char *password = getenv("TURN_PASSWORD");
	if (!host || !port || !username || !password) {
		printf("Skipping: TURN_HOST, TURN_PORT, TURN_USERNAME, and TURN_PASSWORD must all be "
		       "set\n");
		return TestResult(true);
	}

	std::string url = std::string("turn:") + username + ":" + password + "@" + host + ":" + port;

	if (runTurnRelayConnectivityMain(url.c_str(), RTC_RELAY_TRANSPORT_UDP))
		return TestResult(false, "Connection failed");
	return TestResult(true);
}

// Requires a TURN server reachable over TCP, same env vars as deps/libjuice/test/turn2.c and
// turn_connectivity.cpp: TURN_HOST, TURN_PORT, TURN_USERNAME, TURN_PASSWORD.
// Skips (reports success) if unset.
TestResult test_capi_turn_tcp_connectivity() {
	rtcInitLogger(RTC_LOG_DEBUG, nullptr);

	const char *host = getenv("TURN_HOST");
	const char *port = getenv("TURN_PORT");
	const char *username = getenv("TURN_USERNAME");
	const char *password = getenv("TURN_PASSWORD");
	if (!host || !port || !username || !password) {
		printf("Skipping: TURN_HOST, TURN_PORT, TURN_USERNAME, and TURN_PASSWORD must all be "
		       "set\n");
		return TestResult(true);
	}

	std::string url =
	    std::string("turn:") + username + ":" + password + "@" + host + ":" + port + "?transport=tcp";

	if (runTurnRelayConnectivityMain(url.c_str(), RTC_RELAY_TRANSPORT_TCP))
		return TestResult(false, "Connection failed");
	return TestResult(true);
}

// Requires a TURN server reachable over TLS (TURNS), same env vars as
// deps/libjuice/test/turn2.c and turn_connectivity.cpp: TURNS_HOST, TURNS_PORT,
// TURNS_USERNAME, TURNS_PASSWORD. Skips (reports success) if unset.
TestResult test_capi_turn_tls_connectivity() {
	rtcInitLogger(RTC_LOG_DEBUG, nullptr);

	const char *host = getenv("TURNS_HOST");
	const char *port = getenv("TURNS_PORT");
	const char *username = getenv("TURNS_USERNAME");
	const char *password = getenv("TURNS_PASSWORD");
	if (!host || !port || !username || !password) {
		printf("Skipping: TURNS_HOST, TURNS_PORT, TURNS_USERNAME, and TURNS_PASSWORD must all be "
		       "set\n");
		return TestResult(true);
	}

	std::string url = std::string("turns:") + username + ":" + password + "@" + host + ":" + port;

	if (runTurnRelayConnectivityMain(url.c_str(), RTC_RELAY_TRANSPORT_TLS))
		return TestResult(false, "Connection failed");
	return TestResult(true);
}
