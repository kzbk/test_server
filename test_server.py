"""
Autor: Kazbek Kakimbekov 2023
Event: Interview
"""

import socket
import asyncio
import random
import time
from hexdump import hexdump
from protocol import Serializer
from onionaddr import feed_onionaddr


conf = {'TO_ADDR': ('127.0.0.1', 8333),
        'FROM_ADDR': ('127.0.0.1', 8333),
        'SOCKET_TIMEOUT': 60,
        'SOCKET_PROXY': ('127.0.0.1', 9050),
        'MAGIC_NUMBER': b'\xF9\xBE\xB4\xD9',
        'VERSION': 70016,
        'TO_SERVICES': 1032,
        'FROM_SERVICES': 1033,
        'USER_AGENT': '/test:0.1/',
        'HEIGHT': 776366,
        'RELAY': 0
        }


def get_serializer():
    serializer = Serializer(magic_number=conf.get('MAGIC_NUMBER'),
                            version=conf.get('VERSION'),
                            to_services=conf.get('TO_SERVICES'),
                            from_services=conf.get('FROM_SERVICES'),
                            user_agent=conf.get('USER_AGENT'),
                            height=conf.get('HEIGHT'),
                            relay=conf.get('RELAY')
                            )
    return serializer


async def random_address_anounce(sock, addr, serializer):
    data = b''
    # have to answer's time be arbitrary
    await asyncio.sleep(random.randint(1, 10))
    ts = int(time.time())
    services = conf.get('FROM_SERVICES')
    port = 8333
    addr = feed_onionaddr[random.randint(0, 1000)]
    addr_list = [(ts, services, addr, port)]
    data = serializer.serialize_msg(command=b'addrv2', addr_list=addr_list)
    await handle_connection_write(sock, addr, data)


async def handle_message(sock, addr, msgs, serializer):
    data = b''
    for msg in msgs:
        # step 1 send msg =  version + wtxidrelay + sendaddrv2 + verack
        # step 2 send msg = sendheaders
        # step 3 send msg = ping
        if msg.get('command') == b'version':
            # step 1
            # version command
            data = serializer.serialize_msg(command=b'version',
                                            to_addr=addr,
                                            from_addr=conf.get('FROM_ADDR'))
            # wtxidrelay command
            data += serializer.serialize_msg(command=b'wtxidrelay')
            # sendaddrv2 command
            data += serializer.serialize_msg(command=b'sendaddrv2')
            # verack command
            data += serializer.serialize_msg(command=b'verack')
            await handle_connection_write(sock, addr, data)

            # step 2
            data = serializer.serialize_msg(command=b'sendheaders')
            await handle_connection_write(sock, addr, data)

            # step 3
            data = serializer.serialize_msg(command=b'ping',
                                            nonce=random.getrandbits(64))
            # await asyncio.sleep(1)
            await handle_connection_write(sock, addr, data)
        # send answer msg with from addr
        elif msg.get('command') == b'sendaddrv2':
            serializer.addr_version = 2
            ts = int(time.time())
            services = conf.get('FROM_SERVICES')
            from_addr = conf.get('FROM_ADDR')  # tuple (addr, port)
            data = serializer.serialize_msg(command=b'addrv2',
                                            addr_list=[((ts,
                                                        services) + from_addr)
                                                       ])
            await handle_connection_write(sock, addr, data)
        elif msg.get('command') == b'ping':
            # prepare pong
            data = serializer.serialize_msg(command=b'pong',
                                            nonce=msg['nonce'])
            await handle_connection_write(sock, addr, data)
            # feed by random address
            await random_address_anounce(sock, addr, serializer)
        # feeding with prepared addresses
        elif msg.get('command') == b'getaddr':
            ts = int(time.time())
            services = conf.get('FROM_SERVICES')
            port = 8333
            addr_list = [(ts, services, addr, port) for addr in feed_onionaddr]
            data = serializer.serialize_msg(command=b'addrv2',
                                            addr_list=addr_list)
            # await asyncio.sleep(1)
            await handle_connection_write(sock, addr, data)
            # TODO correct output message
            print('All addresses feed')
        else:
            await random_address_anounce(sock, addr, serializer)


# not used
async def handle_connection(reader, writer, serializer):
    addr = writer.get_extra_info("peername")
    print("Connected by", addr)
    while True:
        # Receive
        try:
            header = await reader.read(24)
        except ConnectionError:
            print(f"Client suddenly closed while receiving header from {addr}")
            break
        # print(f"Header {header} from: {addr}")
        if not header:
            break
        msg = serializer.deserialize_msg_header(header)
        length = msg['length']
        payload = bytearray()
        while len(payload) < length:
            try:
                packet = await reader.read(length - len(payload))
            except ConnectionError:
                print(f'Client closed while receiving payload from {addr}')
                break
            if not packet:
                break
            payload.extend(packet)
        # print(f"Payload {payload} from: {addr}")
        # Process
        data = header + payload
        print('<' * 20)
        msgs = []
        while len(data) > 0:
            (msg, data) = serializer.deserialize_msg(data)
            msgs.append(msg)
        print(msgs)
        print('<' * 20)
        data = handle_message(msgs)
        # Send
        # print(f"Send: {data} to: {addr}")
        print('>' * 20)
        msgs_send = []
        while len(data) > 0:
            (msg, data) = serializer.deserialize_msg(data)
            msgs_send.append(msg)
        print(msgs_send)
        print('>' * 20)
        try:
            writer.write(data)  # New
            await writer.drain()
        except ConnectionError:
            print("Client suddenly closed, cannot send")
            break
    writer.close()
    print("Disconnected by", addr)


async def handle_connection_read(sock, addr, serializer):
    loop = asyncio.get_running_loop()
    print('Connected by', addr)
    while True:
        try:
            header = await loop.sock_recv(sock, 24)
        except ConnectionError:
            print(f'Client suddenly closed while recv {addr}')
            break
        if not header:
            break
        msg = serializer.deserialize_header(header)
        length = msg['length']
        payload = bytearray()
        while len(payload) < length:
            try:
                packet = await loop.sock_recv(sock, length - len(payload))
            except ConnectionError:
                print(f'Client closed while recv payload from {addr}')
                break
            if not packet:
                break
            payload.extend(packet)
        # print(f"Payload {payload} from: {addr}")
        # Process
        data = header + payload
        data_print = data
        print('<' * 20, 'RECV_START', '<' * 20)
        hexdump(data_print)
        msgs = []
        while len(data) > 0:
            (msg, data) = serializer.deserialize_msg(data)
            msgs.append(msg)
        # print(msgs)
        print('<' * 20, 'RECV_END', '<' * 20, '\n')
        await handle_message(sock, addr, msgs, serializer)
        # loop.create_task(handle_message(sock, addr, data))


async def handle_connection_write(sock, addr, data):
    loop = asyncio.get_running_loop()
    print('>' * 20, 'SEND_START', '>' * 20)
    hexdump(data)
    """ msgs_send = []
    while len(data) > 0:
        (msg, data) = serializer.deserialize_msg(data)
        msgs_send.append(msg)
    print(msgs_send) """
    print('>' * 20, 'SEND_END', '>' * 20, '\n')
    try:
        await loop.sock_sendall(sock, data)
    except ConnectionError:
        print(f'Client suddenly closed, cannot send to {addr}')
        sock.close()


async def main(host, port):
    """ server = await asyncio.start_server(handle_connection, host, port)
    print("Start server...")
    async with server:
        await server.serve_forever() """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serv_sock:
        serv_sock.bind((host, port))
        serv_sock.listen(5)
        serv_sock.setblocking(False)
        print('Server started')

        loop = asyncio.get_running_loop()
        while True:
            print('Connection waiting...')
            sock, addr = await loop.sock_accept(serv_sock)
            serializer = get_serializer()
            loop.create_task(handle_connection_read(sock, addr, serializer))


HOST = ""    # Symbolic name meaning all available interfaces
PORT = 8333  # Arbitrary non-privileged port

if __name__ == "__main__":
    asyncio.run(main(HOST, PORT))
