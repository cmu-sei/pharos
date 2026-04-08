#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#if defined(_MSC_VER)
#define PHAROS_NOINLINE __declspec(noinline)
#else
#define PHAROS_NOINLINE __attribute__((noinline))
#endif

namespace matrix10 {

static volatile std::int64_t g_sink = 0;

class Entity {
 public:
  explicit Entity(std::string name) : name_(std::move(name)) {}
  virtual ~Entity() = default;

  PHAROS_NOINLINE virtual int tick(int epoch) {
    state_ += epoch;
    g_sink += state_;
    return state_;
  }

  PHAROS_NOINLINE virtual int calibrate(int seed) {
    state_ ^= seed * 31;
    g_sink += state_;
    return state_;
  }

  PHAROS_NOINLINE virtual int health() const {
    return std::abs(state_) % 101;
  }

  PHAROS_NOINLINE virtual std::string label() const {
    return "Entity{" + name_ + "}";
  }

 protected:
  std::string name_;
  int state_ = 7;
};

class Device : public virtual Entity {
 public:
  explicit Device(std::string name) : Entity(std::move(name)) {}
  ~Device() override = default;

  PHAROS_NOINLINE void set_mode(int m) {
    mode_ = (m & 3);
    g_sink += mode_;
  }

  PHAROS_NOINLINE int tick(int epoch) override {
    state_ += (epoch + mode_ * 3);
    return state_;
  }

  PHAROS_NOINLINE int health() const override {
    return 80 - (std::abs(state_) % 17);
  }

  PHAROS_NOINLINE std::string label() const override {
    return "Device{" + name_ + "}";
  }

 protected:
  int mode_ = 1;
};

class Sensor : public Device {
 public:
  explicit Sensor(std::string name) : Entity(name), Device(std::move(name)) {}
  ~Sensor() override = default;

  PHAROS_NOINLINE int sample(int input) {
    last_sample_ = input * gain_ + bias_;
    g_sink += last_sample_;
    return last_sample_;
  }

  PHAROS_NOINLINE int tick(int epoch) override {
    sample(epoch + state_);
    return Device::tick(epoch);
  }

  PHAROS_NOINLINE int calibrate(int seed) override {
    gain_ = 1 + (seed % 5);
    bias_ = seed % 9;
    return Device::calibrate(seed);
  }

  PHAROS_NOINLINE std::string label() const override {
    return "Sensor{" + name_ + "}";
  }

 private:
  int gain_ = 2;
  int bias_ = 1;
  int last_sample_ = 0;
};

class Actuator : public Device {
 public:
  explicit Actuator(std::string name) : Entity(name), Device(std::move(name)) {}
  ~Actuator() override = default;

  PHAROS_NOINLINE int drive(int demand) {
    effort_ = demand * (mode_ + 1);
    g_sink += effort_;
    return effort_;
  }

  PHAROS_NOINLINE int tick(int epoch) override {
    drive(epoch + state_);
    return Device::tick(epoch);
  }

  PHAROS_NOINLINE int health() const override {
    return 90 - (std::abs(effort_) % 23);
  }

  PHAROS_NOINLINE std::string label() const override {
    return "Actuator{" + name_ + "}";
  }

 private:
  int effort_ = 0;
};

class Controller : public virtual Entity {
 public:
  explicit Controller(std::string name) : Entity(std::move(name)) {}
  ~Controller() override = default;

  PHAROS_NOINLINE void bind(Device* d) { bound_ = d; }

  PHAROS_NOINLINE virtual int regulate(int setpoint) {
    if (!bound_) return setpoint;
    int out = setpoint - bound_->health();
    g_sink += out;
    return out;
  }

  PHAROS_NOINLINE int tick(int epoch) override {
    state_ += regulate(epoch + state_);
    return state_;
  }

  PHAROS_NOINLINE std::string label() const override {
    return "Controller{" + name_ + "}";
  }

 protected:
  Device* bound_ = nullptr;
};

class PIDController : public Controller {
 public:
  explicit PIDController(std::string name) : Entity(name), Controller(std::move(name)) {}
  ~PIDController() override = default;

  PHAROS_NOINLINE void tune(float p, float i, float d) {
    kp_ = p;
    ki_ = i;
    kd_ = d;
  }

  PHAROS_NOINLINE int regulate(int setpoint) override {
    int err = setpoint - (bound_ ? bound_->health() : 0);
    integral_ += err;
    int deriv = err - prev_err_;
    prev_err_ = err;
    int out = static_cast<int>(kp_ * err + ki_ * integral_ + kd_ * deriv);
    g_sink += out;
    return out;
  }

  PHAROS_NOINLINE int health() const override {
    return 70 - (std::abs(integral_) % 19);
  }

  PHAROS_NOINLINE std::string label() const override {
    return "PID{" + name_ + "}";
  }

 private:
  float kp_ = 0.2f;
  float ki_ = 0.05f;
  float kd_ = 0.01f;
  int integral_ = 0;
  int prev_err_ = 0;
};

class NetworkNode : public virtual Entity {
 public:
  explicit NetworkNode(std::string name) : Entity(std::move(name)) {}
  ~NetworkNode() override = default;

  PHAROS_NOINLINE virtual int transmit(int bytes) {
    tx_total_ += bytes;
    g_sink += tx_total_;
    return tx_total_;
  }

  PHAROS_NOINLINE int tick(int epoch) override {
    return transmit(epoch + 4);
  }

  PHAROS_NOINLINE int health() const override {
    return 95 - (tx_total_ % 29);
  }

  PHAROS_NOINLINE std::string label() const override {
    return "Node{" + name_ + "}";
  }

 protected:
  int tx_total_ = 0;
};

class Gateway : public NetworkNode, public Controller {
 public:
  explicit Gateway(std::string name)
      : Entity(name), NetworkNode(name), Controller(std::move(name)) {}
  ~Gateway() override = default;

  PHAROS_NOINLINE int regulate(int setpoint) override {
    int routed = setpoint + 3;
    if (bound_) routed -= bound_->health() / 2;
    g_sink += routed;
    return routed;
  }

  PHAROS_NOINLINE int transmit(int bytes) override {
    return NetworkNode::transmit(bytes + 8);
  }

  PHAROS_NOINLINE int tick(int epoch) override {
    int ctrl = regulate(epoch + state_);
    int net = transmit(epoch + 2);
    state_ += ctrl + net;
    return state_;
  }

  PHAROS_NOINLINE std::string label() const override {
    return "Gateway{" + name_ + "}";
  }
};

class Diagnostics : public virtual Entity {
 public:
  explicit Diagnostics(std::string name) : Entity(std::move(name)) {}
  ~Diagnostics() override = default;

  PHAROS_NOINLINE void record(int value) {
    checksum_ = (checksum_ * 131) ^ value;
    g_sink += checksum_;
  }

  PHAROS_NOINLINE int tick(int epoch) override {
    record(epoch + state_);
    state_ += epoch;
    return state_;
  }

  PHAROS_NOINLINE int health() const override {
    return 88 - (std::abs(checksum_) % 31);
  }

  PHAROS_NOINLINE std::string label() const override {
    return "Diag{" + name_ + "}";
  }

 private:
  int checksum_ = 0;
};

class Supervisor : public PIDController, public Diagnostics {
 public:
  explicit Supervisor(std::string name)
      : Entity(name), PIDController(name), Diagnostics(std::move(name)) {}
  ~Supervisor() override = default;

  PHAROS_NOINLINE int orchestrate(int epoch) {
    int a = PIDController::regulate(epoch + 5);
    Diagnostics::record(epoch + a);
    g_sink += a;
    return a;
  }

  PHAROS_NOINLINE int tick(int epoch) override {
    int c = orchestrate(epoch);
    state_ += c;
    return state_;
  }

  PHAROS_NOINLINE int health() const override {
    return (PIDController::health() + Diagnostics::health()) / 2;
  }

  PHAROS_NOINLINE std::string label() const override {
    return "Supervisor{" + name_ + "}";
  }
};

PHAROS_NOINLINE int exercise_entity(Entity* e, int base_epoch) {
  int acc = 0;
  for (int i = 0; i < 6; ++i) {
    acc += e->tick(base_epoch + i);
    acc += e->calibrate(base_epoch + i * 3);
    acc += e->health();
    if ((i & 1) == 0) {
      std::string lbl = e->label();
      acc += static_cast<int>(lbl.size());
    }
  }
  return acc;
}

}  // namespace matrix10

int main() {
  using namespace matrix10;

  auto sensor = std::make_unique<Sensor>("sensor.alpha");
  auto actuator = std::make_unique<Actuator>("actuator.bravo");
  auto pid = std::make_unique<PIDController>("pid.ctrl");
  auto gateway = std::make_unique<Gateway>("gw.delta");
  auto supervisor = std::make_unique<Supervisor>("sup.epsilon");

  sensor->set_mode(2);
  actuator->set_mode(1);
  pid->bind(sensor.get());
  pid->tune(0.35f, 0.08f, 0.015f);
  gateway->bind(actuator.get());
  supervisor->bind(sensor.get());
  supervisor->tune(0.5f, 0.1f, 0.02f);

  std::vector<Entity*> entities = {
      sensor.get(), actuator.get(), pid.get(), gateway.get(), supervisor.get()};

  int total = 0;
  for (size_t i = 0; i < entities.size(); ++i) {
    total += exercise_entity(entities[i], static_cast<int>(i * 11 + 3));
  }

#ifndef NO_RTTI_EXERCISE
  for (Entity* e : entities) {
    if (auto* as_gateway = dynamic_cast<Gateway*>(e)) {
      total += as_gateway->transmit(21);
    }
    if (auto* as_diag = dynamic_cast<Diagnostics*>(e)) {
      total += as_diag->health();
    }
  }
#endif

  std::cout << "matrix10 total=" << total << " sink=" << g_sink << "\n";
  return (total == 0) ? 1 : 0;
}
