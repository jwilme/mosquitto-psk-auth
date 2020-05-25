# mosquitto-psk-auth 

A suite of tools to manage and monitor authentication and access for the 
Mosquitto MQTT Broker

## What is this ?

This project aims to provide a series of tool to improve the authentication
and ACL feature of the mosquitto-broker.

At the moment, the project only provides a plugin to use with the 
mosquitto-broker, that is able to authenticate a client through username/password, and
only supports a MySQL back-end.

In the long term, I'd like this project to provide a series of tool to easily
and efficiently authenticate clients connecting to the broker through different
(even multiple?) backends, to easily manage access to topics, but also to monitor 
the incoming authentication requests, and to easily add/revoke access to clients.
