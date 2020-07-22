#!/bin/bash
set -e
CONFIG_PATH=/data/options.json
SYSTEM_USER=/data/system_user.json
LOGINS=$(jq --raw-output ".logins | length" $CONFIG_PATH)
LOG_LEVEL=$(jq --raw-output ".log_level" $CONFIG_PATH)
MAX_DB_MEMORY_PERCENTAGE=$(jq --raw-output ".max_db_memory_percentage" $CONFIG_PATH)
SSL=$(jq --raw-output ".ssl" $CONFIG_PATH)
HTTP=$(jq --raw-output ".http" $CONFIG_PATH)
KEYFILE=$(jq --raw-output ".keyfile" $CONFIG_PATH)
CAFILE=$(jq --raw-output ".cafile" $CONFIG_PATH)
CERTFILE=$(jq --raw-output ".certfile" $CONFIG_PATH)
WEBSOCKETS=$(jq --raw-output ".websockets" $CONFIG_PATH)
ALLOWED_PROTOCOL_VERSIONS=$(jq --raw-output ".allowed_protocol_versions" $CONFIG_PATH)

HOMEASSISTANT_PW=
ADDONS_PW=

function write_system_users() {
    (
        echo "{\"homeassistant\": {\"password\": \"$HOMEASSISTANT_PW\"}, \"addons\": {\"password\": \"$ADDONS_PW\"}}"
    ) > "${SYSTEM_USER}"
}

function call_hassio() {
    local method=$1
    local path=$2
    local data="${3}"
    local token=

    token="X-Hassio-Key: ${HASSIO_TOKEN}"
    url="http://hassio/${path}"

    # Call API
    if [ -n "${data}" ]; then
        curl -f -s -X "${method}" -d "${data}" -H "${token}" "${url}"
    else
        curl -f -s -X "${method}" -H "${token}" "${url}"
    fi

    return $?
}

function constrain_host_config() {
    local user=$1
    local password=$2

    echo "{"
    echo "  \"host\": \"$(hostname)\","
    echo "  \"port\": 1883,"
    echo "  \"ssl\": false,"
    echo "  \"protocol\": \"3.1.1\","
    echo "  \"username\": \"${user}\","
    echo "  \"password\": \"${password}\""
    echo "}"
}

function constrain_discovery() {
    local user=$1
    local password=$2
    local config=

    config="$(constrain_host_config "${user}" "${password}")"
    echo "{"
    echo "  \"service\": \"mqtt\","
    echo "  \"config\": ${config}"
    echo "}"
}

## Main ##
echo "[INFO] Updating configuration"
echo "accept_eula = yes" >/etc/vernemq/vernemq.conf
MY_IP="$(facter --no-ruby networking.ip)"
if [ ! -e "/ssl/$CERTFILE" ] && [ ! -e "/ssl/$KEYFILE" ]; then
  echo "[WARN] SSL not enabled!"
  SSL="false"
fi
if [[ "$HTTP" == "true" ]]; then
  echo "[INFO] Configuring HTTP"
  echo "listener.http.default = ${MY_IP}:8888" >> /etc/vernemq/vernemq.conf
  if [[ "$SSL" == "true" ]]; then
    echo "[INFO] Configuring HTTP (SSL)"
    echo "listener.https.default = ${MY_IP}:8889" >> /etc/vernemq/vernemq.conf
    echo "listener.https.keyfile = /ssl/${KEYFILE}" >> /etc/vernemq/vernemq.conf
    echo "listener.https.cafile = /ssl/${CAFILE}" >> /etc/vernemq/vernemq.conf
    echo "listener.https.certfile = /ssl/${CERTFILE}" >> /etc/vernemq/vernemq.conf
  fi
fi
echo "[INFO] Configuring MQTT"
echo "listener.tcp.default = ${MY_IP}:1883" >> /etc/vernemq/vernemq.conf
if [[ "$SSL" == "true" ]]; then
  echo "[INFO] Configuring MQTT (SSL)"
  echo "listener.ssl.default = ${MY_IP}:8883" >> /etc/vernemq/vernemq.conf
  echo "listener.ssl.keyfile = /ssl/${KEYFILE}" >> /etc/vernemq/vernemq.conf
  echo "listener.ssl.cafile = /ssl/${CAFILE}" >> /etc/vernemq/vernemq.conf
  echo "listener.ssl.certfile = /ssl/${CERTFILE}" >> /etc/vernemq/vernemq.conf
  echo "listener.ssl.tls_version = tlsv1.2" >> /etc/vernemq/vernemq.conf
fi
if [[ "$WEBSOCKETS" == "true" ]]; then
  echo "[INFO] Configuring Websockets"
  echo "listener.ws.default = ${MY_IP}:9000" >> /etc/vernemq/vernemq.conf
  if [[ "$SSL" == "true" ]]; then
    echo "[INFO] Configuring Websockets (SSL)"
    echo "listener.wss.default = ${MY_IP}:9001" >> /etc/vernemq/vernemq.conf
    echo "listener.wss.keyfile = /ssl/${KEYFILE}" >> /etc/vernemq/vernemq.conf
    echo "listener.wss.certfile = /ssl/${CERTFILE}" >> /etc/vernemq/vernemq.conf
    echo "listener.wss.cafile = /ssl/${CAFILE}" >> /etc/vernemq/vernemq.conf
    echo "listener.wss.tls_version = tlsv1.2" >> /etc/vernemq/vernemq.conf
  fi
fi
touch /etc/vernemq/vmq.passwd
if [ "$LOGINS" -gt "0" ]; then
    logins=$(jq --raw-output '.logins | length' $CONFIG_PATH)
    echo "[INFO] Creating ${logins} user account(s)"
    for (( i=0; i < "$logins"; i++ )); do
        username="$(jq --raw-output ".logins[$i].username" $CONFIG_PATH)"
        password="$(jq --raw-output ".logins[$i].password" $CONFIG_PATH)"
        yes "${password}" | vmq-passwd /etc/vernemq/vmq.passwd "${username}" >/dev/null
    done
else
  echo "[WARN] Enabling anonymous authentication!"
  echo "allow_anonymous = on" >> /etc/vernemq/vernemq.conf
  echo "plugins.vmq_passwd = off" >> /etc/vernemq/vernemq.conf
fi

if [[ -n "${LOG_LEVEL}" ]]; then
  echo "[INFO] Setting Log Level to '${LOG_LEVEL}'"
  echo "log.console.level = ${LOG_LEVEL}" >> /etc/vernemq/vernemq.conf
  echo "log.console = off" >> /etc/vernemq/vernemq.conf
  echo "log.syslog = on" >> /etc/vernemq/vernemq.conf
fi
if [[ -n "${MAX_DB_MEMORY_PERCENTAGE}" ]]; then
  echo "[INFO] Setting LevelDB Memory limit to ${MAX_DB_MEMORY_PERCENTAGE}%"
  echo "leveldb.maximum_memory.percent = ${MAX_DB_MEMORY_PERCENTAGE}" >> /etc/vernemq/vernemq.conf
fi
echo "nodename = VerneMQ@127.0.0.1" >> /etc/vernemq/vernemq.conf
echo "distributed_cookie = vmq" >> /etc/vernemq/vernemq.conf

if [[ -n "${ALLOWED_PROTOCOL_VERSIONS}" ]]; then
  echo "[INFO] Setting allowed protocol versions to '${ALLOWED_PROTOCOL_VERSIONS}'"
  echo "listener.tcp.allowed_protocol_versions = ${ALLOWED_PROTOCOL_VERSIONS}" >> /etc/vernemq/vernemq.conf
fi

# Prepare System Accounts
if [ ! -e "${SYSTEM_USER}" ]; then
    HOMEASSISTANT_PW="$(pwgen 64 1)"
    ADDONS_PW="$(pwgen 64 1)"

    echo "[INFO] Initialise system configuration."
    write_system_users
else
    HOMEASSISTANT_PW=$(jq --raw-output '.homeassistant.password' $SYSTEM_USER)
    ADDONS_PW=$(jq --raw-output '.addons.password' $SYSTEM_USER)
fi

# Initial Service
if call_hassio GET "services/mqtt" | jq --raw-output ".data.host" | grep -v "$(hostname)" > /dev/null; then
    echo "[WARN] There is already a MQTT services running!"
else
    echo "[INFO] Initialise Hass.io Add-on services"
    if ! call_hassio POST "services/mqtt" "$(constrain_host_config addons "${ADDONS_PW}")" > /dev/null; then
        echo "[ERROR] Can't setup Hass.io service mqtt"
    fi

    echo "[INFO] Initialise Home Assistant discovery"
    if ! call_hassio POST "discovery" "$(constrain_discovery homeassistant "${HOMEASSISTANT_PW}")" > /dev/null; then
        echo "[ERROR] Can't setup Home Assistant discovery mqtt"
    fi
fi

if [[ -d /data ]]; then
  if [[ ! -d /data/vernemq ]]; then
    echo "[INFO] Moving persistent storage"
    mv -f /var/lib/vernemq /data/vernemq
  else
    rm -rf /var/lib/vernemq
  fi
  echo "[INFO] Activating persistent storage"
  ln -fs /data/vernemq /var/lib/vernemq
else
  echo "[WARN] Unable to setup persistent storage!"
fi

echo "[INFO] Start mqtt daemon"
START_CONSOLE="$(vernemq start)"
if [[ $? -gt 0 ]]; then
  echo "${START_CONSOLE}"
  echo "[ERROR] Configuration error!"
  echo ""
  cat /etc/vernemq/vernemq.conf
  echo ""
fi
PID="$(vernemq getpid)"
vmq-admin listener show

if [[ "$HTTP" == "true" ]]; then
  echo "[INFO] Configuring HTTP API Key"
  if [[ $(vmq-admin api-key show | wc -l) -eq 0 ]]; then
    vmq-admin api-key create >/dev/null
  fi
  vmq-admin api-key show
fi

echo "[INFO] Starting with the following configuration"
echo ""
cat /etc/vernemq/vernemq.conf
echo ""
echo "[INFO] Startup completed"

# Handling Closing
function stop_mqtt() {
    echo "[INFO] Shutdown mqtt system"
    if call_hassio GET "services/mqtt" | jq --raw-output ".data.host" | grep "$(hostname)" > /dev/null; then
        if ! call_hassio DELETE "services/mqtt"; then
            echo "[WARN] Service unregister fails!"
        fi
    fi

    vernemq stop > /dev/null
    while [[ $(ps -p ${PID} | wc -l) -gt 1 ]]; do
      sleep 3s
    done
}

if [[ -n "${PID}" ]]; then
  trap "stop_mqtt" SIGTERM SIGHUP
  if [[ $(ps -p ${PID} | wc -l) -gt 1 ]]; then
    while [[ $(ps -p ${PID} | wc -l) -gt 1 ]]; do
      sleep 3s
    done
  fi
fi
