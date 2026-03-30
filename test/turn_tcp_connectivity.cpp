/**
 * Copyright (c) 2020 Paul-Louis Ageneau
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
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <thread>

using namespace rtc;
using namespace std;

template <class T> weak_ptr<T> make_weak_ptr(shared_ptr<T> ptr) { return ptr; }

struct BandwidthResult {
	size_t bytes_1to2 = 0;  double send_ms_1to2 = 0.0;  double drain_ms_1to2 = 0.0;  double kbps_1to2 = 0.0;  double rtt_ms_1to2 = -1.0;  bool diff_servers_1to2 = false;
	size_t bytes_2to1 = 0;  double send_ms_2to1 = 0.0;  double drain_ms_2to1 = 0.0;  double kbps_2to1 = 0.0;  double rtt_ms_2to1 = -1.0;  bool diff_servers_2to1 = false;
};

// Connects a fresh pair of PeerConnections, measures throughput in one direction,
// then closes. send_from_1=true measures dc1→dc2; false measures dc2→dc1.
// Returns empty string on success, error message on failure.
static string measure_direction(
    const string &name, const char *dir_label,
    const Configuration &config1, const Configuration &config2,
    bool expected_pc1_tcp, bool expected_pc2_tcp,
    bool send_from_1,
    size_t &out_bytes, double &out_send_ms, double &out_drain_ms,
    double &out_kbps, double &out_rtt_ms, bool &out_diff_servers)
{
	const int MIN_SIZE = 100;
	const int MAX_SIZE = 2048;
	const auto MIN_SEND_DURATION = chrono::seconds(2);
	const size_t MAX_BUFFERED = 32 * 1024;

	PeerConnection pc1(config1);
	PeerConnection pc2(config2);

	pc1.onStateChange([](PeerConnection::State state) { cout << "State 1: " << state << endl; });
	pc1.onIceStateChange(
	    [](PeerConnection::IceState state) { cout << "ICE state 1: " << state << endl; });
	pc1.onGatheringStateChange([&pc1, &pc2](PeerConnection::GatheringState state) {
		cout << "Gathering state 1: " << state << endl;
		if (state == PeerConnection::GatheringState::Complete) {
			auto sdp = pc1.localDescription().value();
			cout << "Description 1: " << sdp << endl;
			pc2.setRemoteDescription(string(sdp));
		}
	});
	pc1.onSignalingStateChange([](PeerConnection::SignalingState state) {
		cout << "Signaling state 1: " << state << endl;
	});

	pc2.onLocalDescription([&pc1](Description sdp) {
		cout << "Description 2: " << sdp << endl;
		pc1.setRemoteDescription(string(sdp));
	});
	pc2.onLocalCandidate([&pc1](Candidate candidate) {
		if (candidate.type() != rtc::Candidate::Type::Relayed) return;
		cout << "Candidate 2: " << candidate << endl;
		pc1.addRemoteCandidate(string(candidate));
	});
	pc2.onStateChange([](PeerConnection::State state) { cout << "State 2: " << state << endl; });
	pc2.onIceStateChange(
	    [](PeerConnection::IceState state) { cout << "ICE state 2: " << state << endl; });
	pc2.onGatheringStateChange([](PeerConnection::GatheringState state) {
		cout << "Gathering state 2: " << state << endl;
	});
	pc2.onSignalingStateChange([](PeerConnection::SignalingState state) {
		cout << "Signaling state 2: " << state << endl;
	});

	atomic<int>    recv_count(0);
	atomic<size_t> recv_bytes(0);

	auto on_recv_packet = [&](size_t sz) {
		recv_bytes += sz;
		int n = ++recv_count;
		if (n % 10 == 9) {
			cout << '.' << flush;
		}
		if (n % 800 == 799) {
			cout << '\n';
		}
	};

	shared_ptr<DataChannel> dc2_atomic;
	pc2.onDataChannel([&](shared_ptr<DataChannel> dc) {
		cout << "DataChannel 2: Received with label \"" << dc->label() << "\"" << endl;
		if (dc->label() != "test") { cerr << "Wrong DataChannel label" << endl; return; }
		dc->onOpen([wdc = make_weak_ptr(dc)]() {
			if (auto dc = wdc.lock()) cout << "DataChannel 2: Open" << endl;
		});
		if (!send_from_1) {
			// measuring 2->1: dc2 is the sender, dc1 is the receiver — set up recv on dc1 below
		} else {
			// measuring 1->2: dc2 receives
			dc->onMessage([&](variant<binary, string> message) {
				if (holds_alternative<binary>(message))
					on_recv_packet(get<binary>(message).size());
			});
		}
		std::atomic_store(&dc2_atomic, dc);
	});

	auto dc1 = pc1.createDataChannel("test");
	dc1->onOpen([wdc1 = make_weak_ptr(dc1)]() {
		if (auto dc1 = wdc1.lock()) cout << "DataChannel 1: Open" << endl;
	});
	dc1->onClosed([]() { cout << "DataChannel 1: Closed" << endl; });
	if (!send_from_1) {
		// measuring 2->1: dc1 receives
		dc1->onMessage([&](const variant<binary, string> &message) {
			if (holds_alternative<binary>(message))
				on_recv_packet(get<binary>(message).size());
		});
	}

	// Wait up to 45s for connection
	int attempts = 45;
	shared_ptr<DataChannel> adc2;
	while ((!(adc2 = std::atomic_load(&dc2_atomic)) || !adc2->isOpen() || !dc1->isOpen()) && attempts--)
		this_thread::sleep_for(1s);

	auto close_both = [&]() {
		pc1.close(); pc2.close();
		int w = 100;
		while ((pc1.state() != PeerConnection::State::Closed ||
		        pc2.state() != PeerConnection::State::Closed) && w--)
			this_thread::sleep_for(100ms);
		this_thread::sleep_for(1s);
	};

	if (pc1.state() != PeerConnection::State::Connected ||
	    pc2.state() != PeerConnection::State::Connected) {
		close_both();
		return name + " [" + dir_label + "]: PeerConnection is not connected";
	}
	if ((pc1.iceState() != PeerConnection::IceState::Connected &&
	     pc1.iceState() != PeerConnection::IceState::Completed) ||
	    (pc2.iceState() != PeerConnection::IceState::Connected &&
	     pc2.iceState() != PeerConnection::IceState::Completed)) {
		close_both();
		return name + " [" + dir_label + "]: ICE is not connected";
	}
	if (!adc2 || !adc2->isOpen() || !dc1->isOpen()) {
		close_both();
		return name + " [" + dir_label + "]: DataChannel is not open";
	}

	if (auto addr = pc1.localAddress())  cout << "Local address 1:  " << *addr << endl;
	if (auto addr = pc1.remoteAddress()) cout << "Remote address 1: " << *addr << endl;
	if (auto addr = pc2.localAddress())  cout << "Local address 2:  " << *addr << endl;
	if (auto addr = pc2.remoteAddress()) cout << "Remote address 2: " << *addr << endl;

	// Check whether pc1 and pc2 landed on the same TURN backend server.
	// Geo-distributed TURN services may assign different backend IPs per allocation,
	// which would explain bandwidth asymmetry between 1->2 and 2->1.
	out_diff_servers = false;
	{
		auto relay_host = [](const string &addr) -> string {
			auto pos = addr.rfind(':');
			return (pos != string::npos) ? addr.substr(0, pos) : addr;
		};
		auto r1 = pc1.localAddress(), r2 = pc2.localAddress();
		if (r1 && r2) {
			string h1 = relay_host(*r1), h2 = relay_host(*r2);
			cout << "Relay host PC1: " << h1 << "  PC2: " << h2;
			if (h1 != h2) {
				out_diff_servers = true;
				cout << "  *** DIFFERENT SERVERS — bandwidth asymmetry expected ***";
			} else {
				cout << "  (same server)";
			}
			cout << endl;
		}
	}

	Candidate local1, remote1, local2, remote2;
	if (!pc1.getSelectedCandidatePair(&local1, &remote1)) {
		close_both();
		return name + " [" + dir_label + "]: getSelectedCandidatePair failed for pc1";
	}
	if (!pc2.getSelectedCandidatePair(&local2, &remote2)) {
		close_both();
		return name + " [" + dir_label + "]: getSelectedCandidatePair failed for pc2";
	}
	cout << "Local  candidate 1: " << local1 << endl;
	cout << "Remote candidate 1: " << remote1 << endl;
	cout << "Local  candidate 2: " << local2 << endl;
	cout << "Remote candidate 2: " << remote2 << endl;

	if (local1.type() != Candidate::Type::Relayed) {
		close_both();
		return name + " [" + dir_label + "]: pc1 local candidate is not relayed";
	}
	if (local2.type() != Candidate::Type::Relayed) {
		close_both();
		return name + " [" + dir_label + "]: pc2 local candidate is not relayed";
	}

	auto pc1_relay = pc1.selectedRelayIsTcp();
	auto pc2_relay = pc2.selectedRelayIsTcp();
	bool pc1_tcp_actual = pc1_relay.value_or(false);
	bool pc2_tcp_actual = pc2_relay.value_or(false);
	cout << "PC1 relay transport: " << (pc1_tcp_actual ? "TCP" : "UDP")
	     << " (expected " << (expected_pc1_tcp ? "TCP" : "UDP") << ")" << endl;
	cout << "PC2 relay transport: " << (pc2_tcp_actual ? "TCP" : "UDP")
	     << " (expected " << (expected_pc2_tcp ? "TCP" : "UDP") << ")" << endl;
	if (pc1_tcp_actual != expected_pc1_tcp) {
		close_both();
		return name + " [" + dir_label + "]: pc1 relay transport mismatch";
	}
	if (pc2_tcp_actual != expected_pc2_tcp) {
		close_both();
		return name + " [" + dir_label + "]: pc2 relay transport mismatch";
	}

	// --- Warmup: grow SCTP cwnd past initial slow-start on the sender side ---
	// The answerer (pc2 as sender) starts at IW=10 with no prior sends,
	// while the offerer (pc1) has already sent DCEP OPEN. Sending ~256KB
	// brings both sides to comparable cwnd state before the timed measurement.
	{
		shared_ptr<DataChannel> warmup_sender = send_from_1 ? dc1 : adc2;
		const size_t WARMUP_BYTES = 256 * 1024;
		binary warmup_pkt(1200);
		size_t sent_w = 0;
		while (sent_w < WARMUP_BYTES) {
			while (warmup_sender->bufferedAmount() > MAX_BUFFERED)
				this_thread::sleep_for(1ms);
			warmup_sender->send(warmup_pkt);
			sent_w += warmup_pkt.size();
		}
		// Drain warmup data before starting timed measurement
		int ww = 200;
		while (warmup_sender->bufferedAmount() > 0 && ww--)
			this_thread::sleep_for(10ms);
		this_thread::sleep_for(50ms); // let ACKs settle
		// Reset counters — warmup packets arrived at receiver; discard those counts
		recv_count = 0;
		recv_bytes = 0;
	}

	// --- Measurement ---
	mt19937 rng(42);
	uniform_int_distribution<int> size_dist(MIN_SIZE, MAX_SIZE);

	shared_ptr<DataChannel> sender = send_from_1 ? dc1 : adc2;
	cout << "  " << dir_label << ": sending..." << endl;
	int sent = 0;
	auto t0 = chrono::steady_clock::now();
	do {
		while (sender->bufferedAmount() > MAX_BUFFERED)
			this_thread::sleep_for(1ms);
		if (chrono::steady_clock::now() - t0 >= MIN_SEND_DURATION)
			break;
		int sz = size_dist(rng);
		binary data(sz);
		for (int j = 0; j < sz; j++) data[j] = byte(rng() & 0xFF);
		sender->send(data);
		++sent;
	} while (chrono::steady_clock::now() - t0 < MIN_SEND_DURATION);
	auto t1 = chrono::steady_clock::now();

	// Flush usrsctp queue before drain wait
	{
		int flush = 200;
		while (sender->bufferedAmount() > 0 && flush--)
			this_thread::sleep_for(10ms);
	}

	int drain_attempts = 300;
	while (recv_count < sent && drain_attempts--)
		this_thread::sleep_for(100ms);
	auto t2 = chrono::steady_clock::now();

	cout << '\n';
	bool ok = (recv_count >= sent);
	out_send_ms  = chrono::duration<double, milli>(t1 - t0).count();
	out_drain_ms = chrono::duration<double, milli>(t2 - t1).count();
	out_bytes    = recv_bytes.load();
	out_kbps     = (out_send_ms > 0.0) ? (out_bytes * 8.0 / (out_send_ms / 1000.0) / 1000.0) : 0.0;
	if (auto r = pc1.rtt()) out_rtt_ms = static_cast<double>(r->count());

	cout << "  " << dir_label << ": " << recv_count << "/" << sent << " packets"
	     << ", " << out_bytes << " bytes"
	     << ", send=" << fixed << setprecision(1) << out_send_ms << "ms"
	     << " drain=" << fixed << setprecision(1) << out_drain_ms << "ms"
	     << " rtt=" << fixed << setprecision(1) << out_rtt_ms << "ms"
	     << " (" << fixed << setprecision(1) << out_kbps << " kbit/s)"
	     << (ok ? "" : " [DRAIN TIMEOUT]") << endl;

	close_both();

	if (!ok)
		return name + " [" + dir_label + "]: drain timed out";
	return {};
}

static TestResult run_relay_test(const string &name, const string &turn_host, uint16_t turn_port,
                                 const string &turn_user, const string &turn_pass,
                                 IceServer::RelayType relayType1, IceServer::RelayType relayType2,
                                 BandwidthResult *bw = nullptr) {
	cout << "\n=== " << name << " ===" << endl;

	Configuration config1;
	config1.iceTransportPolicy = TransportPolicy::Relay;
	config1.iceServers.emplace_back(turn_host, turn_port, turn_user, turn_pass, relayType1);

	Configuration config2;
	config2.iceTransportPolicy = TransportPolicy::Relay;
	config2.iceServers.emplace_back(turn_host, turn_port, turn_user, turn_pass, relayType2);

	bool expected_pc1_tcp = (relayType1 == IceServer::RelayType::TurnTcp);
	bool expected_pc2_tcp = (relayType2 == IceServer::RelayType::TurnTcp);

	BandwidthResult bw_local;

	static const int MAX_ATTEMPTS = 2;
	auto try_direction = [&](const char *dir_label, bool send_from_1,
	                         size_t &bytes, double &send_ms, double &drain_ms,
	                         double &kbps, double &rtt_ms, bool &diff_servers) -> string {
		for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
			cout << name << ": measuring " << dir_label
			     << " (attempt " << attempt << "/" << MAX_ATTEMPTS << ")" << endl;
			auto err = measure_direction(name, dir_label, config1, config2,
			                             expected_pc1_tcp, expected_pc2_tcp, send_from_1,
			                             bytes, send_ms, drain_ms, kbps, rtt_ms, diff_servers);
			if (err.empty())
				return {};
			if (attempt < MAX_ATTEMPTS &&
			    err.find("not connected") != string::npos) {
				cout << "  Connection failed, retrying..." << endl;
				this_thread::sleep_for(3s);
				continue;
			}
			return err;
		}
		return {}; // unreachable
	};

	auto err12 = try_direction("1->2", true,
	    bw_local.bytes_1to2, bw_local.send_ms_1to2,
	    bw_local.drain_ms_1to2, bw_local.kbps_1to2, bw_local.rtt_ms_1to2, bw_local.diff_servers_1to2);
	if (!err12.empty())
		return TestResult(false, err12);

	auto err21 = try_direction("2->1", false,
	    bw_local.bytes_2to1, bw_local.send_ms_2to1,
	    bw_local.drain_ms_2to1, bw_local.kbps_2to1, bw_local.rtt_ms_2to1, bw_local.diff_servers_2to1);
	if (!err21.empty())
		return TestResult(false, err21);

	if (bw) *bw = bw_local;
	cout << name << ": Success" << endl;
	return TestResult(true);
}

TestResult test_turn_tcp_connectivity() {
	const char *turn_host_env = getenv("TURN_HOST");
	const char *turn_port_env = getenv("TURN_PORT");
	const char *turn_user_env = getenv("TURN_USERNAME");
	const char *turn_pass_env = getenv("TURN_PASSWORD");

	if (!turn_host_env || !turn_port_env || !turn_user_env || !turn_pass_env) {
		cout << "TURN TCP connectivity test skipped (missing environment)" << endl;
		return TestResult(true);
	}
	string turn_host = turn_host_env;
	uint16_t turn_port = (uint16_t)stoi(turn_port_env);
	string turn_user = turn_user_env;
	string turn_pass = turn_pass_env;

	InitLogger(LogLevel::Debug);

	using RT = IceServer::RelayType;
	struct Combo { RT r1; RT r2; const char *label; };
	static const Combo combos[] = {
		{RT::TurnUdp, RT::TurnUdp, "UDP/UDP"},
		{RT::TurnTcp, RT::TurnTcp, "TCP/TCP"},
		{RT::TurnTcp, RT::TurnUdp, "TCP/UDP"},
		{RT::TurnUdp, RT::TurnTcp, "UDP/TCP"},
	};

	struct Summary { const char *label; BandwidthResult bw; };
	vector<Summary> summaries;

	for (auto &c : combos) {
		BandwidthResult bw;
		auto result = run_relay_test(string("TURN relay ") + c.label,
		                             turn_host, turn_port, turn_user, turn_pass,
		                             c.r1, c.r2, &bw);
		if (!result.success)
			return result;
		summaries.push_back({c.label, bw});
	}

	auto row = [](const char *dir, size_t bytes, double send_ms, double drain_ms, double rtt_ms, double kbps, bool diff_servers) {
		cout << "  " << left  << setw(5) << dir
		     << right << setw(12) << bytes
		     << right << setw(11) << fixed << setprecision(1) << send_ms
		     << right << setw(11) << fixed << setprecision(1) << drain_ms
		     << right << setw(10) << fixed << setprecision(1) << rtt_ms
		     << right << setw(12) << fixed << setprecision(1) << kbps
		     << (diff_servers ? " *" : "") << endl;
	};

	cout << "\n=== Bandwidth Summary ===" << endl;
	cout << left  << setw(7) << ""
	     << right << setw(12) << "bytes"
	     << right << setw(11) << "send(ms)"
	     << right << setw(11) << "drain(ms)"
	     << right << setw(10) << "rtt(ms)"
	     << right << setw(12) << "kbit/s" << endl;
	for (auto &s : summaries) {
		cout << s.label << ":" << endl;
		row("1->2", s.bw.bytes_1to2, s.bw.send_ms_1to2, s.bw.drain_ms_1to2, s.bw.rtt_ms_1to2, s.bw.kbps_1to2, s.bw.diff_servers_1to2);
		row("2->1", s.bw.bytes_2to1, s.bw.send_ms_2to1, s.bw.drain_ms_2to1, s.bw.rtt_ms_2to1, s.bw.kbps_2to1, s.bw.diff_servers_2to1);
	}
	cout << "(* = different TURN backend servers detected)" << endl;

	return TestResult(true);
}
