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
#include <iostream>
#include <memory>
#include <thread>

using namespace rtc;
using namespace std;

// Sends a message large enough to be fragmented into full-size SCTP packets. Every other test
// sends a short string, which fits in a single undersized record and therefore still arrives when
// the DTLS layer is configured with an MTU smaller than the packets SCTP produces and refuses
// every full-size one. That is exactly how such a misconfiguration stays invisible to the suite.
TestResult test_large_message() {
	InitLogger(LogLevel::Debug);

	Configuration config1;
	config1.disableAutoNegotiation = true;
	PeerConnection pc1(config1);

	Configuration config2;
	config2.disableAutoNegotiation = true;
	PeerConnection pc2(config2);

	pc1.onLocalDescription([&pc2](Description sdp) {
		pc2.setRemoteDescription(string(sdp));
		pc2.setLocalDescription(); // Make the answer
	});

	pc1.onLocalCandidate(
	    [&pc2](Candidate candidate) { pc2.addRemoteCandidate(string(candidate)); });

	pc2.onLocalDescription([&pc1](Description sdp) { pc1.setRemoteDescription(string(sdp)); });

	pc2.onLocalCandidate(
	    [&pc1](Candidate candidate) { pc1.addRemoteCandidate(string(candidate)); });

	DataChannelInit init;
	init.negotiated = true;
	init.id = 1;
	auto dc1 = pc1.createDataChannel("large", init);
	auto dc2 = pc2.createDataChannel("large", init);

	// Make the offer
	pc1.setLocalDescription();

	// Wait a bit
	int attempts = 10;
	while ((!dc1->isOpen() || !dc2->isOpen()) && attempts--)
		this_thread::sleep_for(1s);

	if (pc1.state() != PeerConnection::State::Connected ||
	    pc2.state() != PeerConnection::State::Connected)
		return TestResult(false, "PeerConnection is not connected");

	if (!dc1->isOpen() || !dc2->isOpen())
		return TestResult(false, "DataChannel is not open");

	const size_t messageSize = 64 * 1024;
	binary sent(messageSize);
	for (size_t i = 0; i < messageSize; ++i)
		sent[i] = byte(i % 251); // Prime stride, so truncation or reordering does not go unnoticed

	std::atomic<bool> received = false;
	binary got;
	dc2->onMessage([&received, &got](const variant<binary, string> &message) {
		if (holds_alternative<binary>(message)) {
			got = get<binary>(message);
			received = true;
		}
	});

	dc1->send(sent);

	// Wait a bit
	attempts = 10;
	while (!received && attempts--)
		this_thread::sleep_for(1s);

	if (!received)
		return TestResult(false, "Large message was not received");

	if (got.size() != sent.size())
		return TestResult(false, "Large message has wrong size: got " + to_string(got.size()) +
		                             ", expected " + to_string(sent.size()));

	if (got != sent)
		return TestResult(false, "Large message content does not match");

	cout << "Received large message of " << got.size() << " bytes" << endl;

	// Delay close of peer 2 to check closing works properly
	pc1.close();
	this_thread::sleep_for(1s);
	pc2.close();
	this_thread::sleep_for(1s);

	return TestResult(true);
}
