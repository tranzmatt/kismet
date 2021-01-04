/*

    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __KISMET_MUTEX_H__
#define __KISMET_MUTEX_H__

#include "config.h"

#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <thread>

#include <limits.h>

#include "fmt.h"

#define KIS_THREAD_TIMEOUT      5

class kis_mutex {
private:
    std::recursive_timed_mutex mutex;
    std::string name;

public:
    kis_mutex() :
        name{"UNNAMED"} { }
    kis_mutex(const std::string& name) :
        name{name} { }

    kis_mutex(const kis_mutex&) = delete;
    kis_mutex& operator=(const kis_mutex&) = delete;

    ~kis_mutex() = default;

    void set_name(const std::string& name) {
        this->name = name;
    }

    const std::string& get_name() const {
        return name;
    }

    void lock() {
        mutex.lock();
    }

    bool try_lock() {
        return mutex.try_lock();
    }

    template<class Rep, class Period>
    bool try_lock_for(const std::chrono::duration<Rep, Period>& timeout_duration) {
        return mutex.try_lock_for(timeout_duration);
    }

    template<class Clock, class Duration>
    bool try_lock_until(const std::chrono::time_point<Clock, Duration>& timeout_time) {
        return mutex.try_lock_until(timeout_time);
    }

    void unlock() {
        return mutex.unlock();
    }
};

namespace kismet {
    typedef struct { } retain_lock_t;
    constexpr retain_lock_t retain_lock;
}

template<class M>
class kis_lock_guard {
public:
    kis_lock_guard(M& m, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        retain{false} {
            if (!mutex.try_lock_for(std::chrono::seconds(KIS_THREAD_TIMEOUT)))
                throw std::runtime_error(fmt::format("potential deadlock: mutex {} not available within "
                            "timeout period for op {}", mutex.get_name(), op));
        }

    kis_lock_guard(M& m, std::adopt_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        retain{false} { }

    kis_lock_guard(M& m, kismet::retain_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        retain{true} {
            if (!mutex.try_lock_for(std::chrono::seconds(KIS_THREAD_TIMEOUT)))
                throw std::runtime_error(fmt::format("potential deadlock: mutex {} not available within "
                            "timeout period for op {}", mutex.get_name(), op));
        }

    kis_lock_guard(const kis_lock_guard&) = delete;
    kis_lock_guard& operator=(const kis_lock_guard&) = delete;

    ~kis_lock_guard() {
        if (!retain)
            mutex.unlock();
    }

protected:
    M& mutex;
    std::string op;
    bool retain;
};

template<class M>
class kis_unique_lock {
public:
    kis_unique_lock(M& m, const std::string& op) :
        mutex{m},
        op{op} {
            if (!mutex.try_lock_for(std::chrono::seconds(KIS_THREAD_TIMEOUT)))
                throw std::runtime_error(fmt::format("potential deadlock: mutex {} not available within "
                            "timeout period for op {}", mutex.get_name(), op));
        }

    kis_unique_lock(M& m, std::defer_lock_t t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op} { }

    kis_unique_lock(M& m, std::adopt_lock_t, const std::string& op = "UNKNOWN") :
        mutex{m},
        op{op},
        locked{true} { }

    kis_unique_lock(const kis_unique_lock&) = delete;
    kis_unique_lock& operator=(const kis_unique_lock&) = delete;

    ~kis_unique_lock() {
        if (locked)
            mutex.unlock();
    }

    void lock(const std::string& op = "UNKNOWN") {
        if (locked)
            throw std::runtime_error(fmt::format("invalid use: thread {} attempted to lock "
                        "unique lock {} when already locked fo {}", 
                        std::this_thread::get_id(), mutex.get_name(), op));

        locked = true;

        if (!mutex.try_lock_for(std::chrono::seconds(KIS_THREAD_TIMEOUT)))
            throw std::runtime_error(fmt::format("potential deadlock: mutex {} not available within "
                        "timeout period for op {}", mutex.get_name(), op));
    }

    bool try_lock(const std::string& op = "UNKNOWN") {
        if (locked)
            throw std::runtime_error(fmt::format("invalid use: thread {} attempted to try_lock "
                        "unique lock {} when already locked for {}", 
                        std::this_thread::get_id(), mutex.get_name(), op));

        auto r = mutex.try_lock_for(std::chrono::seconds(KIS_THREAD_TIMEOUT));
        locked = r;

        return r;
    }

    void unlock() {
        if (!locked)
            throw std::runtime_error(fmt::format("unvalid use:  thread{} attempted to unlock "
                        "unique lock {} when not locked", std::this_thread::get_id(), 
                        mutex.get_name()));

        mutex.unlock();
        locked = false;
    }

protected:
    M& mutex;
    std::string op;
    bool locked{false};
};

#endif

