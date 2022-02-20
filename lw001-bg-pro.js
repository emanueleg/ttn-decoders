/*
 * Packet Decoder for MOKO LW001-BG PRO GPS tracker
 * by Emanuele Goldoni, 2022 <emanuele.goldoni@gmail.com>
 */

function decodeUplink(input) {
  bytes = input.bytes
  port = input.fPort
  warnings = []
  errors = []

  var decoded = {};
  decoded.sensor = "MOKO LW001-BG PRO";
  common_header = bytes.slice(0,3)
  
  statusB = common_header[0];
  decoded.operation_mode = (statusB) & 0x03
  decoded.battery_low = (statusB >> 2) & 0x01
  decoded.tamper_alarm = (statusB >> 3) & 0x01
  decoded.man_down_alarm = (statusB >> 4) & 0x01
  decoded.has_moved = (statusB >> 5) & 0x01

  decoded.temperature = common_header[1];
  decoded.temperature -= decoded.temperature > 128 ? 256 : 0;
  
  decoded.ack_frm_cnt = common_header[2] & 0x0f;
  decoded.battery_voltage = (common_header[2] >> 4) & 0x0f
  decoded.battery_voltage = Math.round(10* (2.2 + 0.1*decoded.battery_voltage)) / 10

  if (port === 1) {
    decoded.payload_type = "heartbeat"
    decoded.reboot_reason = bytes[3]
    decoded.fw_ver = ((bytes[4] >> 6) & 0x03) + "." + ((bytes[4] >> 4) & 0x03) + "."  +(bytes[4] & 0x0f)
    decoded.active_state_counts = Bytes2Int(bytes.slice(5,8))
  }
  
  if (port === 2) {
    decoded.payload_type = "location_fixed"
    decoded.positioning_type = (decoded.status >> 6) & 0x01
    decoded.positioning_success_type = bytes[3]
    decoded.date_time = Bytes2DateTime(bytes.slice(4,12))
    decoded.data_length = bytes[12]
    payload = bytes.slice(13, 13+decoded.data_length+1)
    if (decoded.positioning_success_type === 0) {  //wifi
      decoded.wifi = {}
      for (i = 0; i < (decoded.data_length/7); i++) {
        decoded.wifi[Bytes2MAC(payload.slice(i*7, i*7+6))] = payload[i*7+6]-256 
      }
    } else if (decoded.positioning_success_type === 1) {  //bt
      decoded.bluetooth = {}
      for (i = 0; i < (decoded.data_length/7); i++) {
        decoded.bluetooth[Bytes2MAC(payload.slice(i*7, i*7+6))] = payload[i*7+6]-256 
      }
    } else if (decoded.positioning_success_type === 2) {  //gps
      decoded.gps = {}
      decoded.gps.pdop = Math.round(payload[8]/10)
      decoded.gps.latitude = Bytes2Int(payload.slice(0,4))
      decoded.gps.latitude -= (decoded.latitude > 0x80000000) ? 0x0100000000 : 0
      decoded.gps.latitude /= 10000000
      decoded.gps.longitude = Bytes2Int(payload.slice(4,8))
      decoded.gps.longitude -= (decoded.longitude > 0x80000000) ? 0x0100000000 : 0
      decoded.gps.longitude /= 10000000
      decoded.Latitude = decoded.gps.latitude
      decoded.Longitude =  decoded.gps.longitude
    }  
  }
  
  if (port === 3){
    decoded.payload_type = "location_failure"
    decoded.position_failure = Bytes2Hex([bytes[3]])
    decoded.data_length = bytes[4]
    payload = bytes.slice(5, 5+decoded.data_length+1)
    if (bytes[3] < 0x03) {  //wifi
      decoded.wifi = {}
      for (i = 0; i < (decoded.data_length/7); i++) {
        decoded.wifi[Bytes2MAC(payload.slice(i*7, i*7+6))] = payload[i*7+6]-256 
      }
    } else if (bytes[3] < 0x06) {  //bt
      decoded.bluetooth = {}
      for (i = 0; i < (decoded.data_length/7); i++) {
        decoded.bluetooth[Bytes2MAC(payload.slice(i*7, i*7+6))] = payload[i*7+6]-256 
      }
    } else if (bytes[3] < 0x0C) {  //gps
      decoded.gps = {}
      decoded.gps.pdop = (payload[0] === 0xff) ? "unknown" : Math.round(payload[0]/10)
      decoded.gps.cn = payload.slice(1,5)
    }
  }
  
  if (port === 4) {
    decoded.payload_type = "shutdown"
    decoded.shutdown_type = bytes[3]
  }

  if (port == 5) {
    decoded.payload_type = "vibration"
    decoded.vibrations_count = Bytes2Int([bytes[3], bytes[4]])
  }

  if (port === 6) {
    decoded.payload_type = "man_down"
    decoded.idle_hours = Bytes2Int([bytes[3], bytes[4]])
  }
  
  if (port === 7) {
    decoded.payload_type = "tamper_alarm"
    decoded.date_time = Bytes2DateTime(bytes.slice(3,11))
  }
  
  if (port === 8) {
    decoded.payload_type = "event_message"
    decoded.event_type = bytes[3]
  }

  if (port === 9) {
    decoded.payload_type = "battery_consumption"
    decoded.gps_worktime = Bytes2Int(bytes.slice(3,7))
    decoded.wifi_worktime = Bytes2Int(bytes.slice(7,11))
    decoded.bt_scan_worktime = Bytes2Int(bytes.slice(11,15))
    decoded.bt_brdcast_worktime = Bytes2Int(bytes.slice(15,19))
    decoded.lora_worktime = Bytes2Int(bytes.slice(19,23))
  }
  
  decoded.raw_bytes = bytes;
  decoded.raw_original = Bytes2Hex(bytes);
  
  return {
    data: decoded,
    warnings: [],
    errors: []
  };
  
}

/* 4-byte float in IEEE 754 standard, byte order is low byte first */
function Bytes2Float(byteArray) {
  var bits = ((byteArray[3] << 24) | (byteArray[2] << 16) | (byteArray[1] << 8) | (byteArray[0]));
  var sign = ((bits >>> 31) === 0) ? 1.0 : -1.0;
  var e = ((bits >>> 23) & 0xff);
  var m = (e === 0) ? (bits & 0x7fffff) << 1 : (bits & 0x7fffff) | 0x800000;
  var f = sign * m * Math.pow(2, e - 150);
  return f
}

/* n-bytes array to integer - most significant byte is stored first (Big Endian) */
function Bytes2Int(byteArray) {
  var n = 0;
  for (i = 0; i < byteArray.length; i++) {
    n = (n << 8) + byteArray[i]
  }
  return n
}

function Bytes2Hex(byteArray) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

function Bytes2MAC(byteArray) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join(':')
}

function Bytes2DateTime(byteArray) {
  dt = {}
  dt.ts_year = Bytes2Int([byteArray[0], byteArray[1]])
  dt.ts_month = byteArray[2]
  dt.ts_day = byteArray[3]
  dt.ts_hour = byteArray[4]
  dt.ts_min = byteArray[5]
  dt.ts_sec = byteArray[6]

  dt.ts_tz = byteArray[7];
  dt.ts_tz -= dt.ts_tz > 128 ? 256 : 0;
  dt.ts_tz = (dt.ts_tz >= 0) ? "+" + dt.ts_tz : dt.ts_tz;
  
  dt.datetime = ""
  dt.datetime += dt.ts_year + "-" + dt.ts_month + "-" + dt.ts_day
  dt.datetime += " " + dt.ts_hour + ":" + dt.ts_min + ":" + dt.ts_sec
  dt.datetime += " " + "UTC" + dt.ts_tz
  return dt
}
