/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "rtc/rtc.hpp"
#include "test.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <thread>

using namespace rtc;
using namespace std;

namespace {

// Requires a real TURN server, which isn't available in a default dev environment or CI, so these
// tests are opt-in via environment variables (same names as deps/libjuice/test/turn2.c:
// TURN_HOST/TURN_PORT/TURN_USERNAME/TURN_PASSWORD for UDP/TCP, TURNS_HOST/... for TLS) and skip
// (reported as success) rather than fail when unconfigured.
optional<IceServer> turnServerFromEnv(const char *hostVar, const char *portVar,
                                      const char *userVar, const char *passVar,
                                      IceServer::RelayType relayType) {
	const char *host = getenv(hostVar);
	const char *portStr = getenv(portVar);
	const char *username = getenv(userVar);
	const char *password = getenv(passVar);
	if (!host || !portStr || !username || !password) {
		cout << "Skipping: " << hostVar << ", " << portVar << ", " << userVar << ", and "
		     << passVar << " must all be set" << endl;
		return nullopt;
	}

	uint16_t port = uint16_t(stoul(portStr));
	return IceServer(string(host), port, string(username), string(password), relayType);
}

// Forces both peers to gather relay-only candidates on the given TURN server, connects them to
// each other through it, and checks that the negotiated relay transport matches expectations.
// Topology: PeerConnection 1 <--relay transport--> TURN server <--relay transport--> PeerConnection 2
TestResult runTurnRelayConnectivityTest(const IceServer &server,
                                        IceServer::RelayType expectedRelayType) {
	InitLogger(LogLevel::Debug);

	Configuration config1;
	config1.iceTransportPolicy = TransportPolicy::Relay;
	config1.iceServers.push_back(server);

	Configuration config2;
	config2.iceTransportPolicy = TransportPolicy::Relay;
	config2.iceServers.push_back(server);

	PeerConnection pc1(config1);
	PeerConnection pc2(config2);

	pc1.onLocalDescription([&pc2](Description sdp) { pc2.setRemoteDescription(std::move(sdp)); });
	pc1.onLocalCandidate(
	    [&pc2](Candidate candidate) { pc2.addRemoteCandidate(std::move(candidate)); });
	pc1.onStateChange([](PeerConnection::State state) { cout << "State 1: " << state << endl; });
	pc1.onIceStateChange(
	    [](PeerConnection::IceState state) { cout << "ICE state 1: " << state << endl; });

	pc2.onLocalDescription([&pc1](Description sdp) { pc1.setRemoteDescription(std::move(sdp)); });
	pc2.onLocalCandidate(
	    [&pc1](Candidate candidate) { pc1.addRemoteCandidate(std::move(candidate)); });
	pc2.onStateChange([](PeerConnection::State state) { cout << "State 2: " << state << endl; });
	pc2.onIceStateChange(
	    [](PeerConnection::IceState state) { cout << "ICE state 2: " << state << endl; });

	shared_ptr<DataChannel> dc2;
	pc2.onDataChannel([&dc2](shared_ptr<DataChannel> dc) { std::atomic_store(&dc2, dc); });

	auto dc1 = pc1.createDataChannel("test");

	int attempts = 20;
	shared_ptr<DataChannel> adc2;
	while ((!(adc2 = std::atomic_load(&dc2)) || !adc2->isOpen() || !dc1->isOpen()) && attempts--)
		this_thread::sleep_for(chrono::seconds(1));

	if (pc1.state() != PeerConnection::State::Connected ||
	    pc2.state() != PeerConnection::State::Connected)
		return TestResult(false, "PeerConnection is not connected");

	if (!adc2 || !adc2->isOpen() || !dc1->isOpen())
		return TestResult(false, "DataChannel is not open");

	Candidate local, remote;
	if (!pc1.getSelectedCandidatePair(&local, &remote))
		return TestResult(false, "getSelectedCandidatePair failed");

	cout << "Local candidate 1:  " << local << endl;
	cout << "Remote candidate 1: " << remote << endl;

	if (local.type() != Candidate::Type::Relayed)
		return TestResult(false, "Connection is not relayed as expected");

	auto relayType = pc1.selectedRelayType();
	if (!relayType)
		return TestResult(false, "selectedRelayType() returned no value");
	if (*relayType != expectedRelayType)
		return TestResult(false, "Unexpected relay transport was negotiated");

	std::atomic<bool> received = false;
	adc2->onMessage([&received](variant<binary, string> message) {
		if (holds_alternative<string>(message))
			received = true;
	});
	dc1->send("Hello over relay");

	attempts = 5;
	while (!received && attempts--)
		this_thread::sleep_for(chrono::seconds(1));

	if (!received)
		return TestResult(false, "Message was not received over the relay");

	pc1.close();
	this_thread::sleep_for(chrono::seconds(1));
	pc2.close();
	this_thread::sleep_for(chrono::seconds(1));

	return TestResult(true);
}

} // namespace

// Requires a TURN server reachable over UDP, same env vars as deps/libjuice/test/turn2.c:
// TURN_HOST, TURN_PORT, TURN_USERNAME, TURN_PASSWORD. Skips (reports success) if unset.
TestResult test_turn_connectivity() {
	auto server = turnServerFromEnv("TURN_HOST", "TURN_PORT", "TURN_USERNAME", "TURN_PASSWORD",
	                                IceServer::RelayType::TurnUdp);
	if (!server)
		return TestResult(true);

	return runTurnRelayConnectivityTest(*server, IceServer::RelayType::TurnUdp);
}

// Requires a TURN server reachable over TCP, same env vars as deps/libjuice/test/turn2.c:
// TURN_HOST, TURN_PORT, TURN_USERNAME, TURN_PASSWORD. Skips (reports success) if unset.
TestResult test_turn_tcp_connectivity() {
	auto server = turnServerFromEnv("TURN_HOST", "TURN_PORT", "TURN_USERNAME", "TURN_PASSWORD",
	                                IceServer::RelayType::TurnTcp);
	if (!server)
		return TestResult(true);

	return runTurnRelayConnectivityTest(*server, IceServer::RelayType::TurnTcp);
}

// Requires a TURN server reachable over TLS (TURNS), same env vars as
// deps/libjuice/test/turn2.c: TURNS_HOST, TURNS_PORT, TURNS_USERNAME, TURNS_PASSWORD.
// Skips (reports success) if unset.
TestResult test_turn_tls_connectivity() {
	auto server = turnServerFromEnv("TURNS_HOST", "TURNS_PORT", "TURNS_USERNAME",
	                                "TURNS_PASSWORD", IceServer::RelayType::TurnTls);
	if (!server)
		return TestResult(true);

	return runTurnRelayConnectivityTest(*server, IceServer::RelayType::TurnTls);
}
