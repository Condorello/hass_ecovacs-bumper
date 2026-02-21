ARG BUILD_FROM
FROM ${BUILD_FROM}

ARG BUILD_VERSION
ARG BUILD_ARCH

ARG BUMPER_REPO="https://github.com/Condorello/bumper.git"
ARG BUMPER_BRANCH="master"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apk add --no-cache \
    python3 py3-pip py3-virtualenv \
    git bash jq \
    build-base linux-headers \
    libffi-dev openssl-dev

# --- Clone (cache-bust con BUILD_VERSION) ---
RUN echo "Cache bust -> BUILD_VERSION=${BUILD_VERSION} ARCH=${BUILD_ARCH}" \
 && rm -rf /opt/bumper \
 && git clone --depth 1 --branch "${BUMPER_BRANCH}" "${BUMPER_REPO}" /opt/bumper \
 && cd /opt/bumper \
 && echo "Bumper git HEAD:" \
 && git rev-parse --short HEAD \
 && git log -1 --oneline

# --- Requirements tweaks (opzionali) ---
RUN sed -i '/^websockets==/d' /opt/bumper/requirements.txt || true
RUN sed -i '/^aiohttp==/d' /opt/bumper/requirements.txt || true \
 && grep -q '^aiohttp' /opt/bumper/requirements.txt || echo 'aiohttp>=3.10.0' >> /opt/bumper/requirements.txt

# --- OVERRIDE proxy.py (compat amqtt) ---
RUN cat > /opt/bumper/bumper/mqtt/proxy.py <<'PY'
"""Mqtt proxy module."""
import asyncio
import ssl
import typing
from collections.abc import MutableMapping
from typing import Any
from urllib.parse import urlparse, urlunparse

import websockets
from amqtt.adapters import (
    StreamReaderAdapter,
    StreamWriterAdapter,
    WebSocketsReader,
    WebSocketsWriter,
)

from amqtt.client import MQTTClient

# ConnectException: cambia nome tra versioni di amqtt
try:
    from amqtt.client import ConnectException
except ImportError:
    try:
        from amqtt.errors import ConnectError as ConnectException
    except ImportError:
        from amqtt.errors import AMQTTException as ConnectException

from amqtt.mqtt.connack import CONNECTION_ACCEPTED
from amqtt.mqtt.constants import QOS_0, QOS_1, QOS_2
from amqtt.mqtt.protocol.client_handler import ClientProtocolHandler

# ProtocolHandlerException: rinominata in alcune versioni
try:
    from amqtt.mqtt.protocol.handler import ProtocolHandlerException
except ImportError:
    from amqtt.mqtt.protocol.handler import ProtocolHandlerError as ProtocolHandlerException

from cachetools import TTLCache
from websockets.exceptions import InvalidHandshake, InvalidURI

import bumper
from ..util import get_logger

_LOGGER = get_logger("mqtt_proxy")


class ProxyClient:
    """Mqtt client, which proxies all messages to the ecovacs servers."""

    def __init__(
        self,
        client_id: str,
        host: str,
        port: int = 443,
        config: dict[str, Any] | None = None,
        timeout: float = 180,
    ):
        self.request_mapper: MutableMapping[str, str] = TTLCache(
            maxsize=int(timeout * timeout), ttl=timeout * 1.1
        )
        self._client = _NoCertVerifyClient(client_id=client_id, config=config)
        self._host = host
        self._port = port

    async def connect(self, username: str, password: str) -> None:
        """Connect."""
        await self._client.connect(
            f"mqtts://{username}:{password}@{self._host}:{self._port}"
        )
        asyncio.create_task(self._handle_messages())

    async def _handle_messages(self) -> None:
        while self._client.session.transitions.is_connected():
            try:
                message = await self._client.deliver_message()
                data = message.data.decode("utf-8") if message.data else ""

                _LOGGER.info(
                    "Message Received From Ecovacs - Topic: %s - Message: %s",
                    message.topic,
                    data,
                )
                topic = message.topic
                ttopic = topic.split("/")
                if len(ttopic) > 10 and ttopic[1] == "p2p":
                    if ttopic[3] == "proxyhelper":
                        _LOGGER.error('"proxyhelper" was sender - INVALID!! Topic: %s', topic)
                        continue

                    self.request_mapper[ttopic[10]] = ttopic[3]
                    ttopic[3] = "proxyhelper"
                    topic = "/".join(ttopic)
                    _LOGGER.info("Converted Topic From %s TO %s", message.topic, topic)

                _LOGGER.info(
                    "Proxy Forward Message to Robot - Topic: %s - Message: %s",
                    topic,
                    data,
                )

                bumper.mqtt_helperbot.publish(topic, message.data)
            except Exception:
                _LOGGER.error("An error occurred during handling a message", exc_info=True)

    async def subscribe(self, topic: str, qos: QOS_0 | QOS_1 | QOS_2 = QOS_0) -> None:
        await self._client.subscribe([(topic, qos)])

    async def disconnect(self) -> None:
        await self._client.disconnect()

    async def publish(self, topic: str, message: bytes, qos: int | None = None) -> None:
        await self._client.publish(topic, message, qos)


class _NoCertVerifyClient(MQTTClient):  # type:ignore[misc]
    @typing.no_type_check
    async def _connect_coro(self):
        kwargs = {}

        uri_attributes = urlparse(self.session.broker_uri)
        scheme = uri_attributes.scheme
        secure = scheme in ("mqtts", "wss")

        self.session.username = self.session.username or uri_attributes.username
        self.session.password = self.session.password or uri_attributes.password
        self.session.remote_address = uri_attributes.hostname
        self.session.remote_port = uri_attributes.port

        if scheme in ("mqtt", "mqtts") and not self.session.remote_port:
            self.session.remote_port = 8883 if scheme == "mqtts" else 1883
        if scheme in ("ws", "wss") and not self.session.remote_port:
            self.session.remote_port = 443 if scheme == "wss" else 80

        if scheme in ("ws", "wss"):
            uri = (
                scheme,
                f"{self.session.remote_address}:{self.session.remote_port}",
                uri_attributes[2],
                uri_attributes[3],
                uri_attributes[4],
                uri_attributes[5],
            )
            self.session.broker_uri = urlunparse(uri)

        self._handler = ClientProtocolHandler(self.plugins_manager)

        if secure:
            sc = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=self.session.cafile,
                capath=self.session.capath,
                cadata=self.session.cadata,
            )
            if "certfile" in self.config and "keyfile" in self.config:
                sc.load_cert_chain(self.config["certfile"], self.config["keyfile"])
            if isinstance(self.config.get("check_hostname"), bool):
                sc.check_hostname = self.config["check_hostname"]

            sc.verify_mode = ssl.CERT_NONE
            kwargs["ssl"] = sc

        try:
            self._connected_state.clear()

            if scheme in ("mqtt", "mqtts"):
                conn_reader, conn_writer = await asyncio.open_connection(
                    self.session.remote_address, self.session.remote_port, **kwargs
                )
                reader = StreamReaderAdapter(conn_reader)
                writer = StreamWriterAdapter(conn_writer)
            elif scheme in ("ws", "wss"):
                websocket = await websockets.connect(
                    self.session.broker_uri,
                    subprotocols=["mqtt"],
                    extra_headers=self.extra_headers,
                    **kwargs,
                )
                reader = WebSocketsReader(websocket)
                writer = WebSocketsWriter(websocket)
            else:
                raise ConnectException(f"Unsupported scheme: {scheme}")

            self._handler.attach(self.session, reader, writer)
            return_code = await self._handler.mqtt_connect()

            if return_code is not CONNECTION_ACCEPTED:
                self.session.transitions.disconnect()
                raise ConnectException("Connection rejected by broker")

            await self._handler.start()
            self.session.transitions.connect()
            self._connected_state.set()
            return return_code

        except (InvalidURI, InvalidHandshake, ProtocolHandlerException, ConnectionError, OSError) as e:
            self.session.transitions.disconnect()
            raise ConnectException(str(e)) from e
PY

# --- VERIFICA BUILD: stampa righe chiave dei file patchati (le vedrai nel log di build) ---
RUN echo "=== proxy.py head ===" \
 && sed -n '1,80p' /opt/bumper/bumper/mqtt/proxy.py \
 && echo "=== grep ProtocolHandler ===" \
 && grep -n "ProtocolHandler" /opt/bumper/bumper/mqtt/proxy.py \
 && echo "=== __init__.py grep mqtt_helperbot.disconnect ===" \
 && grep -n "mqtt_helperbot.disconnect" -n /opt/bumper/bumper/__init__.py || true

# --- venv + deps ---
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel \
 && /opt/venv/bin/pip install --no-cache-dir "setuptools<81" \
 && /opt/venv/bin/pip install --no-cache-dir -r /opt/bumper/requirements.txt

ENV PATH="/opt/venv/bin:${PATH}"
WORKDIR /opt/bumper

# s6 services (Home Assistant add-on runtime)
COPY rootfs/ /

# rootfs/ contiene /run.sh
RUN sed -i 's/\r$//' /run.sh 2>/dev/null || true \
 && chmod +x /run.sh

# IMPORTANTISSIMO: override dell'ENTRYPOINT della base image (s6 /init)
ENTRYPOINT ["/run.sh"]
CMD []

RUN echo "=== IMAGE CONFIG /ENTRYPOINT/CMD) === " \
 && cat /proc/1/cmdline || true
