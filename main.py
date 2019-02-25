
#
# config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
#
# conn = H2Connection(config)
# conn.initiate_connection()
# conn.ping(b'deadbeef')
# conn.send_headers(100501, [(':method', 'GET'), (':scheme', 'https'), (':authority', 'auth'), (':path', '/your/mama')], end_stream=False)
# conn.send_data(100501, b'pidor', end_stream=False)
# conn.send_headers(100501, [hpack.NeverIndexedHeaderTuple('status', 'okayokayokay')], end_stream=True)
#
#
# data = conn.data_to_send()
# del conn
#
# config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
# conn = H2Connection(config)
# conn.initiate_connection()
#
# print(data)
# print(conn.receive_data(data))
#
# conn_h2 = h2.connection.H2Connection(config)
# conn_h2.initiate_connection()
# print(conn_h2.receive_data(data))
#
# del conn
#
# headers = [("the" + str(i), str(i)) for i in range(100)]
# data = ' '.join(name for name, _ in headers)
#
# import time
#
# for ConnectionCls in (h2.connection.H2Connection, H2Connection):
#     start = time.time()
#     for i in range(200):
#         config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
#         conn = ConnectionCls(config)
#         conn.ping(b'deadbeef')
#         conn.send_headers(100501, [(':method', 'GET'), (':scheme', 'https'), (':authority', 'auth'), (':path', '/your/mama')], end_stream=False)
#         conn.send_data(100501, data.encode("utf-8"))
#         conn.send_headers(100501, headers, end_stream=True)
#         result = conn.data_to_send()
#     end = time.time()
#     print(ConnectionCls, end - start)
#


# import time
#
# for ConnectionCls in (h2.connection.H2Connection, H2Connection):
#     start = time.time()
#     for i in range(20000):
#         config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
#         conn = ConnectionCls(config)
#         conn.receive_data(data)
#     end = time.time()
#     print(ConnectionCls, end - start)
#
