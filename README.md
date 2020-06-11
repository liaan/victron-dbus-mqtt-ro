# Victron Dbus Mqtt Read only
Victron Dbus-mqtt  Read Only version just pushing data all the time to mqtt from the Dbus.  Does not connect to MQTT cloud etc

dbus-mqtt 1.20 or higher needed (git pull)



#### Expanded options
* Topic prefic
* retain
* LWT

```
usage: dbus_mqtt-ro.py [-h] [-d] [-q [MQTT_SERVER]] [-u MQTT_USER]
                       [-P MQTT_PASSWORD] [-c MQTT_CERTIFICATE] [-b DBUS]
                       [-t TOPIC] [-Mr MQTT_RETAIN] [-LWT MQTT_LWT]

Publishes values from the D-Bus to an MQTT broker

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           set logging level to debug
  -q [MQTT_SERVER], --mqtt-server [MQTT_SERVER]
                        name of the mqtt server
  -u MQTT_USER, --mqtt-user MQTT_USER
                        mqtt user name
  -P MQTT_PASSWORD, --mqtt-password MQTT_PASSWORD
                        mqtt password
  -c MQTT_CERTIFICATE, --mqtt-certificate MQTT_CERTIFICATE
                        path to CA certificate used for SSL communication
  -b DBUS, --dbus DBUS  dbus address
  -t TOPIC, --topic TOPIC
                        Mqtt topic publish prefix, not used for read / write
  -Mr MQTT_RETAIN, --mqtt-retain MQTT_RETAIN
                        Mqtt Retain True/False
  -LWT MQTT_LWT, --mqtt-lwt MQTT_LWT
                        Mqtt Retain True/False
```

#### todo:
Setup service scripts to make it run automigly
