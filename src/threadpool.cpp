/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "threadpool.hpp"

namespace rtc {

ThreadPool::ThreadPool(int count) { spawn(count); }

ThreadPool::~ThreadPool() { join(); }

int ThreadPool::count() const {
	std::unique_lock lock(mMutex);
	return mWorkers.size();
}

void ThreadPool::spawn(int count) {
	std::unique_lock lock(mMutex);
	while (count-- > 0)
		mWorkers.emplace_back(std::bind(&ThreadPool::run, this));
}

void ThreadPool::join() {
	try {
		std::unique_lock lock(mMutex);
		mJoining = true;
		mCondition.notify_all();

		auto workers = std::move(mWorkers);
		mWorkers.clear();

		lock.unlock();
		for (auto &w : workers)
			w.join();

	} catch (...) {
		mJoining = false;
		throw;
	}

	mJoining = false;
}

void ThreadPool::run() {
	while (runOne()) {
	}
}

bool ThreadPool::runOne() {
	if (auto task = dequeue()) {
		try {
			task();
		} catch (const std::exception &e) {
			PLOG_WARNING << "Unhandled exception in task: " << e.what();
		}
		return true;
	}
	return false;
}

std::function<void()> ThreadPool::dequeue() {
	std::unique_lock lock(mMutex);
	mCondition.wait(lock, [this]() { return !mTasks.empty() || mJoining; });
	if (mTasks.empty())
		return nullptr;
	auto task = std::move(mTasks.front());
	mTasks.pop();
	return task;
}

} // namespace rtc

