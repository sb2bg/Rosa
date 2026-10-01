#include "darwin/Threads.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace rosa::darwin {

void GuestScheduler::ensureMainThread() {
    if (threads_.empty()) {
        auto main = std::make_unique<GuestThread>();
        main->id = mainThreadId;
        main->port = detachedMain_.port;
        main->signalMask = detachedMain_.signalMask;
        main->signalsDisabled = detachedMain_.signalsDisabled;
        threads_.push_back(std::move(main));
        current_ = 0;
    }
}

void GuestScheduler::bindMainThread(x86::X86State &state) {
    ensureMainThread();
    threads_.front()->state = &state;
}

GuestThread &GuestScheduler::create(const x86::X86State &initial) {
    ensureMainThread();
    auto thread = std::make_unique<GuestThread>();
    thread->id = nextId_++;
    thread->ownedState = std::make_unique<x86::X86State>(initial);
    thread->state = thread->ownedState.get();
    threads_.push_back(std::move(thread));
    return *threads_.back();
}

GuestThread &GuestScheduler::current() noexcept {
    return threads_.empty() ? detachedMain_ : *threads_[current_];
}

const GuestThread &GuestScheduler::current() const noexcept {
    return threads_.empty() ? detachedMain_ : *threads_[current_];
}

GuestThread *GuestScheduler::find(std::uint64_t id) noexcept {
    for (auto &thread : threads_) {
        if (thread->id == id) {
            return thread.get();
        }
    }
    return threads_.empty() && id == mainThreadId ? &detachedMain_ : nullptr;
}

GuestThread *GuestScheduler::findByPort(GuestMachPortName port) noexcept {
    for (auto &thread : threads_) {
        if (thread->port == port && thread->status != GuestThreadStatus::Exited) {
            return thread.get();
        }
    }
    return threads_.empty() && detachedMain_.port == port ? &detachedMain_ : nullptr;
}

void GuestScheduler::block(GuestWait wait) {
    if (threads_.empty()) {
        throw std::runtime_error("guest thread blocked with no other guest thread to wake it: " +
                                 wait.description);
    }
    auto &thread = current();
    thread.wait = std::move(wait);
    thread.status = GuestThreadStatus::Blocked;
}

void GuestScheduler::finishWait(GuestThread &thread, GuestWakeReason reason) {
    auto wait = std::move(*thread.wait);
    thread.wait.reset();
    thread.status = GuestThreadStatus::Runnable;
    if (wait.complete) {
        wait.complete(*thread.state, reason);
    }
}

std::size_t GuestScheduler::wake(GuestWaitKind kind, std::uint64_t channel,
                                 std::size_t maximum, GuestWakeReason reason) {
    std::size_t woken = 0;
    for (auto &thread : threads_) {
        if (woken == maximum) {
            break;
        }
        if (thread->status == GuestThreadStatus::Blocked && thread->wait &&
            thread->wait->kind == kind && thread->wait->channel == channel) {
            finishWait(*thread, reason);
            ++woken;
        }
    }
    return woken;
}

bool GuestScheduler::wakeThread(GuestThread &thread, GuestWaitKind kind, std::uint64_t channel) {
    if (thread.status != GuestThreadStatus::Blocked || !thread.wait ||
        thread.wait->kind != kind || thread.wait->channel != channel) {
        return false;
    }
    finishWait(thread, GuestWakeReason::Signaled);
    return true;
}

std::size_t GuestScheduler::waiters(GuestWaitKind kind, std::uint64_t channel) const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(threads_, [&](const auto &thread) {
        return thread->status == GuestThreadStatus::Blocked && thread->wait &&
               thread->wait->kind == kind && thread->wait->channel == channel;
    }));
}

void GuestScheduler::exitCurrent() noexcept {
    auto &thread = current();
    thread.status = GuestThreadStatus::Exited;
    thread.wait.reset();
}

void GuestScheduler::expireDeadlines(GuestClock::time_point now) {
    for (auto &thread : threads_) {
        if (thread->status == GuestThreadStatus::Blocked && thread->wait &&
            thread->wait->deadline && *thread->wait->deadline <= now) {
            finishWait(*thread, GuestWakeReason::TimedOut);
        }
    }
}

GuestThread *GuestScheduler::nextRunnable(bool rotate) noexcept {
    const auto count = threads_.size();
    const auto first = rotate ? 1U : 0U;
    for (std::size_t step = first; step <= count; ++step) {
        const auto index = (current_ + step) % count;
        if (threads_[index]->status == GuestThreadStatus::Runnable) {
            current_ = index;
            return threads_[index].get();
        }
    }
    return nullptr;
}

GuestThread *GuestScheduler::schedule(bool rotate, const ServiceEvents &service) {
    if (threads_.empty()) {
        return nullptr;
    }
    for (;;) {
        const auto serviceDeadline = service ? service() : std::nullopt;
        std::optional<GuestClock::time_point> earliest = serviceDeadline;
        bool anyDeadline = false;
        for (const auto &thread : threads_) {
            anyDeadline |= thread->status == GuestThreadStatus::Blocked && thread->wait &&
                           thread->wait->deadline.has_value();
        }
        if (anyDeadline) {
            expireDeadlines(GuestClock::now());
        }
        if (auto *thread = nextRunnable(rotate)) {
            return thread;
        }
        if (liveThreadCount() == 0) {
            return nullptr;
        }
        for (const auto &thread : threads_) {
            if (thread->status == GuestThreadStatus::Blocked && thread->wait &&
                thread->wait->deadline) {
                earliest = earliest ? std::min(*earliest, *thread->wait->deadline)
                                    : *thread->wait->deadline;
            }
        }
        if (!earliest) {
            throw std::runtime_error("every guest thread is blocked with nothing to wake it\n" +
                                     summary());
        }
        std::this_thread::sleep_until(*earliest);
    }
}

bool GuestScheduler::hasOtherRunnable() const noexcept {
    for (std::size_t index = 0; index < threads_.size(); ++index) {
        if (index != current_ && threads_[index]->status == GuestThreadStatus::Runnable) {
            return true;
        }
    }
    return false;
}

std::size_t GuestScheduler::liveThreadCount() const noexcept {
    return static_cast<std::size_t>(std::ranges::count_if(threads_, [](const auto &thread) {
        return thread->status != GuestThreadStatus::Exited;
    }));
}

std::string GuestScheduler::summary() const {
    std::ostringstream stream;
    stream << "  guest threads: " << threads_.size() << '\n';
    for (std::size_t index = 0; index < threads_.size(); ++index) {
        const auto &thread = *threads_[index];
        stream << "    id=" << thread.id << (index == current_ ? " (current)" : "") << " status=";
        switch (thread.status) {
        case GuestThreadStatus::Runnable:
            stream << "runnable";
            break;
        case GuestThreadStatus::Blocked:
            stream << "blocked on " << (thread.wait ? thread.wait->description : "?");
            break;
        case GuestThreadStatus::Exited:
            stream << "exited";
            break;
        }
        if (thread.port) {
            stream << " port=0x" << std::hex << thread.port->value << std::dec;
        }
        if (thread.state != nullptr) {
            stream << " RIP=0x" << std::hex << thread.state->rip << " RSP=0x" << thread.state->rsp
                   << std::dec;
        }
        stream << '\n';
    }
    return stream.str();
}

} // namespace rosa::darwin
