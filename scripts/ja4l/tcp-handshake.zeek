module JA4PLUS::JA4L;

# Sensor observes the Originator sending a SYN to the Responder
#   ___      _      ___
#  | O |--->|S|    | R |
#  |___|    |_|    |___|
#
# We do not record this value as it is set in c$start_time

# Sensor observes the Responder sending a SYN+ACK to the Originator
#   ___      _      ___
#  | O |    |S|--->| R |
#  |___|    |_|<---|___|
#
# Find the interval between the sensor and responder
event connection_established(c: connection) {
  if (!c?$ja4plus) { c$ja4plus = []; }
  if (!c$ja4plus?$ja4l) { c$ja4plus$ja4l = []; }
  c$ja4plus$ja4l$resp_from_sensor = (network_time() - c$start_time) / 2.0;
}
    
# Sensor observes the Originator sending a ACK with optional DATA to the Responder
#   ___      _      ___
#  | O |<---|S|    | R |
#  |___|--->|_|    |___|
#
# Find the interval between the sensor and originator
event connection_first_ACK(c: connection) {
  if (!c?$ja4plus) { c$ja4plus = []; }
  if (!c$ja4plus?$ja4l) { c$ja4plus$ja4l = []; }
  c$ja4plus$ja4l$orig_from_sensor = (network_time() - c$start_time - c$ja4plus$ja4l$resp_from_sensor) / 2.0;
}
