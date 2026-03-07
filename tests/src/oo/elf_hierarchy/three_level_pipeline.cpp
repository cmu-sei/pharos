#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace telemetry {

enum class Severity : uint8_t {
  kInfo,
  kWarn,
  kError
};

struct Event {
  uint64_t id = 0;
  Severity severity = Severity::kInfo;
  std::string topic;
  std::string payload;
};

class IAuditSink {
 public:
  virtual ~IAuditSink() = default;
  virtual void on_event(const Event& event) = 0;
  virtual std::string flush() = 0;
};

class C {
 public:
  explicit C(std::string service_name)
      : service_name_(std::move(service_name)),
        seed_(std::random_device{}()),
        rng_(seed_) {
    counters_["ingest"] = 0;
    counters_["score"] = 0;
  }

  virtual ~C() = default;

  virtual void ingest(const Event& event) {
    uint64_t digest = stable_digest(event.topic + ":" + event.payload);
    hot_window_.push_back(digest);
    if (hot_window_.size() > kWindowLimit) {
      hot_window_.erase(hot_window_.begin());
    }
    ++counters_["ingest"];
  }

  virtual int score() const {
    if (hot_window_.empty()) {
      return 0;
    }

    uint64_t sum = std::accumulate(hot_window_.begin(), hot_window_.end(), uint64_t{0});
    return static_cast<int>(sum % 997);
  }

  virtual std::unique_ptr<C> clone() const {
    return std::make_unique<C>(*this);
  }

  virtual std::string name() const {
    return service_name_;
  }

 protected:
  static uint64_t stable_digest(const std::string& text) {
    uint64_t hash = 1469598103934665603ULL;
    for (unsigned char c : text) {
      hash ^= static_cast<uint64_t>(c);
      hash *= 1099511628211ULL;
    }
    return hash;
  }

  static constexpr size_t kWindowLimit = 96;

  std::string service_name_;
  uint64_t seed_ = 0;
  mutable std::mt19937_64 rng_;
  std::vector<uint64_t> hot_window_;
  std::unordered_map<std::string, uint64_t> counters_;
};

class B : public C, public IAuditSink {
 public:
  explicit B(std::string service_name)
      : C(std::move(service_name)) {
    counters_["audit"] = 0;
    counters_["flush"] = 0;
  }

  B(const B& other)
      : C(other),
        policy_callback_(other.policy_callback_),
        audit_log_(other.audit_log_),
        quarantine_(other.quarantine_) {}

  ~B() override = default;

  void set_policy_callback(std::function<bool(const Event&)> callback) {
    policy_callback_ = std::move(callback);
  }

  void ingest(const Event& event) override {
    if (policy_callback_ && !policy_callback_(event)) {
      quarantine_.push_back(event.id);
      return;
    }

    C::ingest(event);
    if (event.severity != Severity::kInfo) {
      std::lock_guard<std::mutex> lock(log_mu_);
      audit_log_.push_back("severity!=info:" + std::to_string(event.id));
      if (audit_log_.size() > kAuditLimit) {
        audit_log_.pop_front();
      }
    }
  }

  int score() const override {
    int base = C::score();
    int penalty = static_cast<int>(quarantine_.size() % 31);
    return std::max(0, base - penalty);
  }

  std::unique_ptr<C> clone() const override {
    return std::make_unique<B>(*this);
  }

  std::string name() const override {
    return "B{" + service_name_ + "}";
  }

  void on_event(const Event& event) override {
    std::lock_guard<std::mutex> lock(log_mu_);
    ++counters_["audit"];
    std::ostringstream oss;
    oss << "audit#" << std::setw(6) << std::setfill('0') << event.id
        << " topic=" << event.topic
        << " sev=" << static_cast<int>(event.severity);
    audit_log_.push_back(oss.str());
    if (audit_log_.size() > kAuditLimit) {
      audit_log_.pop_front();
    }
  }

  std::string flush() override {
    std::lock_guard<std::mutex> lock(log_mu_);
    ++counters_["flush"];

    std::ostringstream oss;
    oss << "flush(" << audit_log_.size() << ")";
    for (const auto& line : audit_log_) {
      oss << "\n  - " << line;
    }
    audit_log_.clear();
    return oss.str();
  }

 protected:
  static constexpr size_t kAuditLimit = 32;

  std::function<bool(const Event&)> policy_callback_;
  mutable std::mutex log_mu_;
  std::deque<std::string> audit_log_;
  std::vector<uint64_t> quarantine_;
};

class A final : public B {
 public:
  explicit A(std::string service_name)
      : B(std::move(service_name)) {}

  A(const A& other)
      : B(other),
        tenant_id_(other.tenant_id_),
        session_start_(other.session_start_),
        sessions_started_(other.sessions_started_.load()),
        recent_ids_(other.recent_ids_) {}

  ~A() override = default;

  void start_session(uint64_t tenant_id) {
    tenant_id_ = tenant_id;
    session_start_ = std::chrono::steady_clock::now();
    ++sessions_started_;
  }

  void ingest(const Event& event) override {
    if (tenant_id_ == 0) {
      throw std::logic_error("session not started");
    }

    Event rewritten = event;
    rewritten.topic = "tenant." + std::to_string(tenant_id_) + "." + event.topic;
    B::ingest(rewritten);
    recent_ids_.push_back(event.id);
    if (recent_ids_.size() > 20) {
      recent_ids_.erase(recent_ids_.begin());
    }
  }

  int score() const override {
    int base = B::score();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - session_start_).count();
    int timing_bonus = static_cast<int>(elapsed_ms % 13);
    int churn_bonus = static_cast<int>(recent_ids_.size() % 7);
    return base + timing_bonus + churn_bonus;
  }

  std::unique_ptr<C> clone() const override {
    return std::make_unique<A>(*this);
  }

  std::string name() const override {
    return "A{" + service_name_ + "}";
  }

  std::string render_snapshot() const {
    std::ostringstream oss;
    oss << "snapshot tenant=" << tenant_id_
        << " sessions=" << sessions_started_.load()
        << " score=" << score()
        << " recent_ids=";
    for (uint64_t id : recent_ids_) {
      oss << id << ",";
    }
    return oss.str();
  }

 private:
  uint64_t tenant_id_ = 0;
  std::chrono::steady_clock::time_point session_start_ = std::chrono::steady_clock::now();
  std::atomic<uint64_t> sessions_started_{0};
  std::vector<uint64_t> recent_ids_;
};

template <typename SinkT>
void replay_to_sink(SinkT& sink, const std::vector<Event>& events) {
  for (const auto& event : events) {
    sink.on_event(event);
  }
}

void exercise_vtable_paths(C* c_view, B* b_view, IAuditSink* audit_view,
                           const std::vector<Event>& events) {
  for (const auto& event : events) {
    c_view->ingest(event);
    b_view->ingest(event);
    audit_view->on_event(event);
  }

  std::cout << "c_view name=" << c_view->name() << " score=" << c_view->score() << "\n";
  std::cout << "b_view name=" << b_view->name() << " score=" << b_view->score() << "\n";
  std::cout << audit_view->flush() << "\n";
}

std::vector<Event> generate_events() {
  std::vector<Event> events;
  events.reserve(40);

  for (uint64_t i = 1; i <= 40; ++i) {
    Event ev;
    ev.id = i;
    ev.topic = (i % 5 == 0) ? "billing" : ((i % 2 == 0) ? "orders" : "auth");
    ev.payload = "payload:" + std::to_string(i * 17);
    ev.severity = (i % 11 == 0) ? Severity::kError : ((i % 7 == 0) ? Severity::kWarn : Severity::kInfo);
    events.push_back(std::move(ev));
  }

  return events;
}

}  // namespace telemetry

int main() {
  using namespace telemetry;

  try {
    auto events = generate_events();

    A orchestrator("inventory.pipeline");
    orchestrator.set_policy_callback([](const Event& e) {
      return !(e.topic == "billing" && e.severity == Severity::kError);
    });
    orchestrator.start_session(42);

    C* c_ptr = &orchestrator;
    B* b_ptr = &orchestrator;
    IAuditSink* audit_ptr = &orchestrator;

    replay_to_sink(*audit_ptr, events);
    exercise_vtable_paths(c_ptr, b_ptr, audit_ptr, events);

    auto cloned = c_ptr->clone();
    std::cout << "clone name=" << cloned->name() << " score=" << cloned->score() << "\n";

    if (auto* a_ptr = dynamic_cast<A*>(c_ptr)) {
      std::cout << a_ptr->render_snapshot() << "\n";
    }
  } catch (const std::exception& e) {
    std::cerr << "fatal: " << e.what() << "\n";
    return 1;
  }

  return 0;
}
