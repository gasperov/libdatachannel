/**
 * Copyright (c) 2019 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "rtc/rtc.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

using namespace rtc;
using namespace std;
using namespace chrono_literals;

using chrono::duration_cast;
using chrono::milliseconds;
using chrono::steady_clock;

template <class T> weak_ptr<T> make_weak_ptr(shared_ptr<T> ptr) { return ptr; }

namespace {

struct BenchResult {
	string name;
	bool connected = false;
	size_t goodput = 0; // bytes/s
};

// Measures DataChannel goodput between two local PeerConnections. If server is set, both peers
// are forced to relay through it (see test/turn_connectivity.cpp for the equivalent correctness
// test); otherwise they connect directly over host candidates.
BenchResult runBenchmark(const string &name, milliseconds duration,
                         optional<IceServer> server = nullopt) {
	cout << endl << "=== " << name << " ===" << endl;

	Configuration config1, config2;
	if (server) {
		config1.iceTransportPolicy = TransportPolicy::Relay;
		config2.iceTransportPolicy = TransportPolicy::Relay;
		config1.iceServers.push_back(*server);
		config2.iceServers.push_back(*server);
	}

	PeerConnection pc1(config1);
	PeerConnection pc2(config2);

	pc1.onLocalDescription([&pc2](Description sdp) { pc2.setRemoteDescription(std::move(sdp)); });
	pc1.onLocalCandidate(
	    [&pc2](Candidate candidate) { pc2.addRemoteCandidate(std::move(candidate)); });
	pc1.onStateChange([](PeerConnection::State state) { cout << "State 1: " << state << endl; });

	pc2.onLocalDescription([&pc1](Description sdp) { pc1.setRemoteDescription(std::move(sdp)); });
	pc2.onLocalCandidate(
	    [&pc1](Candidate candidate) { pc1.addRemoteCandidate(std::move(candidate)); });
	pc2.onStateChange([](PeerConnection::State state) { cout << "State 2: " << state << endl; });

	const size_t messageSize = 65535;
	binary messageData(messageSize);
	fill(messageData.begin(), messageData.end(), byte(0xFF));

	atomic<size_t> receivedSize = 0;

	steady_clock::time_point startTime, openTime, receivedTime, endTime;

	shared_ptr<DataChannel> dc2;
	pc2.onDataChannel([&dc2, &receivedSize, &receivedTime](shared_ptr<DataChannel> dc) {
		dc->onMessage([&receivedTime, &receivedSize](variant<binary, string> message) {
			if (holds_alternative<binary>(message)) {
				const auto &bin = get<binary>(message);
				if (receivedSize == 0)
					receivedTime = steady_clock::now();
				receivedSize += bin.size();
			}
		});

		std::atomic_store(&dc2, dc);
	});

	startTime = steady_clock::now();
	auto dc1 = pc1.createDataChannel("benchmark");

	dc1->onOpen([wdc1 = make_weak_ptr(dc1), &messageData, &openTime]() {
		auto dc1 = wdc1.lock();
		if (!dc1)
			return;

		openTime = steady_clock::now();

		cout << "DataChannel open, sending data..." << endl;
		try {
			while (dc1->bufferedAmount() == 0)
				dc1->send(messageData);
		} catch (const std::exception &e) {
			cout << "Send failed: " << e.what() << endl;
		}
	});

	// When sent data is buffered in the DataChannel,
	// wait for onBufferedAmountLow callback to continue
	dc1->onBufferedAmountLow([wdc1 = make_weak_ptr(dc1), &messageData]() {
		auto dc1 = wdc1.lock();
		if (!dc1)
			return;

		try {
			while (dc1->isOpen() && dc1->bufferedAmount() == 0)
				dc1->send(messageData);
		} catch (const std::exception &e) {
			cout << "Send failed: " << e.what() << endl;
		}
	});

	const int steps = 10;
	const auto stepDuration = duration / 10;
	for (int i = 0; i < steps; ++i) {
		this_thread::sleep_for(stepDuration);
		cout << "Received: " << receivedSize.load() / 1000 << " KB" << endl;
	}

	BenchResult result;
	result.name = name;
	result.connected = dc1->isOpen() && dc2 && dc2->isOpen();

	if (server) {
		if (auto relayType = pc1.selectedRelayType())
			cout << "Selected relay type: " << int(*relayType) << endl;
		else
			cout << "Selected relay type: none (not relayed, or not reported by this backend)"
			     << endl;
	}

	dc1->close();

	endTime = steady_clock::now();

	auto connectDuration = duration_cast<milliseconds>(dc1->isOpen() ? openTime - startTime
	                                                                 : steady_clock::duration(0));
	auto transferDuration = duration_cast<milliseconds>(endTime - receivedTime);

	cout << "Test duration: " << duration.count() << " ms" << endl;
	cout << "Connect duration: " << connectDuration.count() << " ms" << endl;

	size_t received = receivedSize.load();
	result.goodput = transferDuration.count() > 0 ? received / transferDuration.count() : 0;
	cout << "Goodput: " << result.goodput * 0.001 << " MB/s"
	     << " (" << result.goodput * 0.001 * 8 << " Mbit/s)" << endl;

	pc1.close();
	pc2.close();

	return result;
}

} // namespace

size_t benchmark(milliseconds duration) {
	rtc::InitLogger(LogLevel::Warning);
	rtc::Preload();

	size_t goodput = runBenchmark("Direct", duration).goodput;

	rtc::Cleanup();
	return goodput;
}

#ifdef BENCHMARK_MAIN

int main(int argc, char **argv) {
	rtc::InitLogger(LogLevel::Warning);
	rtc::Preload();

	int durationMs = 10000;
	if (const char *s = getenv("BENCH_DURATION_MS"))
		durationMs = atoi(s);
	milliseconds duration(durationMs);

	vector<BenchResult> results;

	results.push_back(runBenchmark("Direct (UDP, no relay)", duration));

	const char *turnHost = getenv("TURN_HOST");
	const char *turnPort = getenv("TURN_PORT");
	const char *turnUsername = getenv("TURN_USERNAME");
	const char *turnPassword = getenv("TURN_PASSWORD");
	if (turnHost && turnPort && turnUsername && turnPassword) {
		uint16_t port = uint16_t(stoul(turnPort));

		results.push_back(runBenchmark(
		    "TURN UDP", duration,
		    IceServer(turnHost, port, turnUsername, turnPassword, IceServer::RelayType::TurnUdp)));

#ifdef RTC_ENABLE_TURN_TCP
		results.push_back(runBenchmark(
		    "TURN TCP", duration,
		    IceServer(turnHost, port, turnUsername, turnPassword, IceServer::RelayType::TurnTcp)));
#endif
	} else {
		cout << endl
		     << "TURN_HOST, TURN_PORT, TURN_USERNAME, and TURN_PASSWORD are not all set; "
		        "skipping TURN UDP/TCP benchmarks"
		     << endl;
	}

#ifdef RTC_ENABLE_TURN_TLS
	const char *turnsHost = getenv("TURNS_HOST");
	const char *turnsPort = getenv("TURNS_PORT");
	const char *turnsUsername = getenv("TURNS_USERNAME");
	const char *turnsPassword = getenv("TURNS_PASSWORD");
	if (turnsHost && turnsPort && turnsUsername && turnsPassword) {
		uint16_t port = uint16_t(stoul(turnsPort));

		results.push_back(
		    runBenchmark("TURN TLS", duration,
		                 IceServer(turnsHost, port, turnsUsername, turnsPassword,
		                           IceServer::RelayType::TurnTls)));
	} else {
		cout << endl
		     << "TURNS_HOST, TURNS_PORT, TURNS_USERNAME, and TURNS_PASSWORD are not all set; "
		        "skipping TURN TLS benchmark"
		     << endl;
	}
#endif

	rtc::Cleanup();

	cout << endl << "=== Summary ===" << endl;
	bool anyFailed = false;
	for (const auto &r : results) {
		if (!r.connected || r.goodput == 0)
			anyFailed = true;

		cout << r.name << ": " << (r.connected ? "connected" : "FAILED") << ", "
		     << r.goodput * 0.001 << " MB/s (" << r.goodput * 0.001 * 8 << " Mbit/s)" << endl;
	}

	return anyFailed ? -1 : 0;
}

#endif // BENCHMARK_MAIN
