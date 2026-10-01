#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace rosa::darwin {

// struct kevent_qos_s, the 72-byte x86_64 layout kevent_qos and the
// workqueue exchange with the guest.
struct GuestKevent {
    std::uint64_t ident{};
    std::int16_t filter{};
    std::uint16_t flags{};
    std::int32_t qos{};
    std::uint64_t udata{};
    std::uint32_t fflags{};
    std::uint32_t xflags{};
    std::int64_t data{};
    std::array<std::uint64_t, 4> ext{};

    static constexpr std::size_t size = 72;
    [[nodiscard]] static GuestKevent decode(std::span<const std::uint8_t> bytes);
    void encode(std::span<std::uint8_t> bytes) const;
};

inline constexpr std::int16_t evfiltRead = -1;
inline constexpr std::int16_t evfiltWrite = -2;
inline constexpr std::int16_t evfiltProc = -5;
inline constexpr std::int16_t evfiltSignal = -6;
inline constexpr std::int16_t evfiltTimer = -7;
inline constexpr std::int16_t evfiltMachPort = -8;
inline constexpr std::int16_t evfiltUser = -10;
inline constexpr std::int16_t evfiltVm = -12;
inline constexpr std::int16_t evfiltMemoryStatus = -14;
inline constexpr std::int16_t evfiltWorkloop = -17;

inline constexpr std::uint16_t evAdd = 0x0001;
inline constexpr std::uint16_t evDelete = 0x0002;
inline constexpr std::uint16_t evEnable = 0x0004;
inline constexpr std::uint16_t evDisable = 0x0008;
inline constexpr std::uint16_t evOneshot = 0x0010;
inline constexpr std::uint16_t evClear = 0x0020;
inline constexpr std::uint16_t evReceipt = 0x0040;
inline constexpr std::uint16_t evDispatch = 0x0080;
inline constexpr std::uint16_t evUdataSpecific = 0x0100;
inline constexpr std::uint16_t evVanished = 0x0200;
inline constexpr std::uint16_t evError = 0x4000;

// QoS buckets of the workqueue kqueue: thread QoS 1-6, plus the event
// manager for knotes registered without a QoS.
inline constexpr std::uint32_t kqueueManagerBucket = 7;

struct GuestKnote {
    // The registration as XNU's kn_kevent keeps it; ext[0] and data hold
    // timer state for EVFILT_TIMER.
    GuestKevent registration;
    std::uint32_t savedFilterFlags{};
    std::int64_t savedData{};
    std::uint32_t bucket{};
    bool active{};
    bool disabled{};
    // The workqueue thread processing this knote's last delivery; XNU's
    // KN_SUPPRESSED keeps it from being delivered again meanwhile.
    std::optional<std::uint64_t> suppressedBy;
    // EVFILT_TIMER, in guest mach_absolute_time units.
    std::optional<std::uint64_t> timerDeadline;
    std::uint64_t timerInterval{};
};

// One kqueue: the process's workqueue kqueue, or one from kqueue(2). Times
// are guest mach_absolute_time units. Registration and processing follow
// XNU's kevent_register and filter f_attach/f_touch/f_process.
class GuestKqueue {
  public:
    explicit GuestKqueue(bool workqueue) : workqueue_(workqueue) {}

    // Applies one change. Returns zero or an errno for an EV_ERROR result.
    [[nodiscard]] int registerChange(const GuestKevent &change, std::uint64_t now);

    // Delivers up to `maximum` ready events, from `bucket` when given.
    // Knotes delivered to a `thread` stay suppressed until unsuppress(thread).
    [[nodiscard]] std::vector<GuestKevent> process(std::optional<std::uint32_t> bucket,
                                                   std::size_t maximum, std::uint64_t now,
                                                   std::optional<std::uint64_t> thread);
    void unsuppress(std::uint64_t thread);

    // Marks the Mach-port knotes watching `port` active (a message arrived)
    // or inactive (its queue drained). Rosa's guest IPC calls these.
    void setMachPortReady(std::uint64_t port, bool ready);

    // Activates every timer due at `now`; returns whether any fired.
    bool expireTimers(std::uint64_t now);
    [[nodiscard]] std::optional<std::uint64_t> nextTimerDeadline() const;
    // The highest QoS bucket with a deliverable event.
    [[nodiscard]] std::optional<std::uint32_t> readyBucket() const;
    [[nodiscard]] bool hasReadyEvents(std::uint32_t bucket) const;
    [[nodiscard]] std::size_t size() const noexcept { return knotes_.size(); }
    [[nodiscard]] bool isWorkqueue() const noexcept { return workqueue_; }

  private:
    [[nodiscard]] GuestKnote *find(const GuestKevent &change);
    [[nodiscard]] bool deliverable(const GuestKnote &knote) const noexcept;
    [[nodiscard]] std::uint32_t bucketFor(std::int32_t qos) const noexcept;
    [[nodiscard]] int attach(GuestKnote &knote, const GuestKevent &change, std::uint64_t now);
    [[nodiscard]] int touch(GuestKnote &knote, const GuestKevent &change, std::uint64_t now);

    bool workqueue_{};
    std::vector<std::unique_ptr<GuestKnote>> knotes_;
};

// A dispatch workloop: XNU's kqworkloop, identified by libdispatch's queue
// address. Its EVFILT_WORKLOOP knotes request a servicer thread or park
// dispatch_sync waiters; other filters registered on it live in `sources`.
struct GuestWorkloop {
    std::uint64_t id{};
    // The NOTE_WL_THREAD_REQUEST knote, its fflags as XNU's kn_sfflags.
    std::optional<GuestKevent> threadRequest;
    bool threadRequestDelivered{};
    std::optional<std::uint64_t> servicer;
    std::optional<std::uint64_t> owner;
    struct SyncKnote {
        GuestKevent registration;
        std::uint32_t savedFilterFlags{};
        std::optional<std::uint64_t> waiter;
    };
    std::map<std::uint64_t, SyncKnote> syncKnotes;
    GuestKqueue sources{false};
};

// Guest mach_absolute_time units per nanosecond (the virtual TSC rate).
inline constexpr std::uint64_t guestMachTicksPerNanosecond = 2;

} // namespace rosa::darwin
