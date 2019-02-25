import collections
import struct
from typing import Iterable

from ngh2._nghttp2 import ffi, lib
import hpack
import h2.config
import h2.events
import h2.settings
import h2.errors
import h2.exceptions
import h2.connection


class DataSource:
    __slots__ = ("data", "pos")

    def __init__(self, data, pos):
        self.data = data
        self.pos = pos


class H2Connection:
    def __init__(self, config: h2.config.H2Configuration = None, initial_settings: dict = None):
        if config is None:
            config = h2.config.H2Configuration(client_side=True)
        if initial_settings is None:
            initial_settings = {}

        initial_values = self._initial_setting_values(config)
        initial_values.update(initial_settings)
        self._config = config
        self._session = self._make_session()
        self._local_settigns = h2.settings.Settings(client=config.client_side, initial_values=initial_values)

        self._data_frame_recv_chunk_buffer = bytearray()
        self._data_to_send = bytearray()
        self._data_to_send_ptr = ffi.new("uint8_t**")
        self._padding_amount = 0

        self._pending_events = []
        self._callback_exc_info = None

    def _initial_setting_values(self, config):
        return {
            h2.settings.SettingCodes.HEADER_TABLE_SIZE: 4096,
            h2.settings.SettingCodes.ENABLE_PUSH: int(config.client_side),
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: 100,
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: 65535,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: 16384,
            h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE: 1024,
            h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 0,
        }

    def _on_callback_error(exc_tp, exc_val, exc_tb):
        if exc_tb is None:
            raise ValueError("exc_tb is None, cannot extract H2Connection information")
        user_data = exc_tb.tb_frame.f_locals['user_data']
        self = ffi.from_handle(ffi.cast("userdata_t*", user_data).handle)  # type: H2Connection
        self._callback_exc_info = (exc_tp, exc_val, exc_tb)
        return 0

    def _check_callback_exc_info(self):
        if self._callback_exc_info is not None:
            exc_tp, exc_val, exc_tb = self._callback_exc_info
            self._callback_exc_info = None
            raise exc_tp.with_traceback(exc_val, exc_tb)

    def clear_outbound_data_buffer(self):
        self._data_to_send.clear()

    def _prepare_for_sending(self):
        while True:
            num_bytes = lib.nghttp2_session_mem_send(self._session, self._data_to_send_ptr)
            assert num_bytes >= 0
            self._data_to_send += ffi.buffer(self._data_to_send_ptr[0], num_bytes)
            if num_bytes == 0:
                break
        self._check_callback_exc_info()

    @property
    def config(self):
        return self._config

    @property
    def local_settings(self):
        return self._local_settigns

    @local_settings.setter
    def local_settings(self, value):
        self._local_settigns = value

    def update_settings(self, new_settings: dict):
        if new_settings is not None:
            self._local_settigns.update(new_settings)
        else:
            new_settings = self._local_settigns

        iv = ffi.new("nghttp2_settings_entry[]", len(new_settings))
        for idx, (key, value) in enumerate(new_settings.items()):
            iv[idx].settings_id = key
            iv[idx].value = value

        assert lib.nghttp2_submit_settings(self._session, lib.NGHTTP2_FLAG_NONE, iv, len(iv)) == 0
        self._prepare_for_sending()

    def initiate_connection(self):
        self.update_settings(None)

    def data_to_send(self, amount: int = None):
        if amount is None:
            data = self._data_to_send
            self._data_to_send = bytearray()
            return data
        else:
            data = self._data_to_send[:amount]
            self._data_to_send = self._data_to_send[amount:]
            return data

    def acknowledge_received_data(self, acknowledged_size: int, stream_id: int):
        assert lib.nghttp2_session_consume(self._session, stream_id, acknowledged_size) == 0
        self._prepare_for_sending()

    def close_connection(self, error_code: h2.errors.ErrorCodes = h2.errors.ErrorCodes.NO_ERROR,
                         additional_data: bytes = None,
                         last_stream_id: int = None):
        if last_stream_id is None:
            last_stream_id = lib.nghttp2_session_get_last_proc_stream_id(self._session)

        if additional_data is not None:
            opaque_data = ffi.from_buffer("uint8_t[]", additional_data)
            opaque_data_len = len(additional_data)
        else:
            opaque_data = ffi.NULL
            opaque_data_len = 0

        assert lib.nghttp2_submit_goaway(self._session, lib.NGHTTP2_FLAG_NONE, last_stream_id, error_code,
                                         opaque_data, opaque_data_len) == 0
        self._prepare_for_sending()

    def get_next_available_stream_id(self) -> int:
        next_stream_id = lib.nghttp2_session_get_next_stream_id(self._session)
        if next_stream_id == 2 ** 31:
            raise h2.exceptions.NoAvailableStreamIDError
        return next_stream_id

    def ping(self, opaque_data: bytes):
        if not isinstance(opaque_data, bytes) or len(opaque_data) != 8:
            raise ValueError("Invalid value for ping data: %r" % opaque_data)

        # TODO: can add optional boolean ack to acknowledge ping frames manually (should also enable this via
        # nghttp2_option_set_no_auto_ping_ack())
        opaque_data_array = ffi.from_buffer("uint8_t[]", opaque_data)
        assert lib.nghttp2_submit_ping(self._session, lib.NGHTTP2_FLAG_NONE, opaque_data_array) == 0
        self._prepare_for_sending()

    def reset_stream(self, stream_id: int, error_code: h2.errors.ErrorCodes = h2.errors.ErrorCodes.NO_ERROR):
        if lib.nghttp2_session_find_stream(self._session, stream_id) == ffi.NULL:
            raise h2.exceptions.NoSuchStreamError(stream_id)
        assert lib.nghttp2_submit_rst_stream(self._session, lib.NGHTTP2_FLAG_NONE, stream_id, error_code) == 0
        self._prepare_for_sending()

    def _build_nva_initializer(self, headers):
        header_encoding = self._config.header_encoding or "utf-8"
        nva_initializer = []
        for idx, header in enumerate(headers):
            name, value = header

            name = name if isinstance(name, bytes) else name.encode(header_encoding)
            value = value if isinstance(value, bytes) else value.encode(header_encoding)

            flags = lib.NGHTTP2_NV_FLAG_NONE
            if isinstance(header, hpack.NeverIndexedHeaderTuple):
                flags = lib.NGHTTP2_NV_FLAG_NO_INDEX

            nva_initializer.append((ffi.from_buffer("uint8_t[]", name), ffi.from_buffer("uint8_t[]", value),
                                    len(name), len(value), flags))
        return nva_initializer

    def send_headers(self, stream_id: int, headers: Iterable[tuple], end_stream: bool = False,
                     priority_weight: int = None, priority_depends_on: int = None, priority_exclusive: bool = None):
        priority_spec = ffi.new("nghttp2_priority_spec*")
        lib.nghttp2_priority_spec_default_init(priority_spec)
        if priority_weight is not None:
            priority_spec.weight = priority_weight
        if priority_depends_on is not None:
            priority_spec.stream_id = priority_depends_on
        if priority_exclusive is not None:
            priority_spec.exclusive = priority_exclusive

        nva_initializer = self._build_nva_initializer(headers)
        nva = ffi.new("nghttp2_nv[]", nva_initializer)

        if lib.nghttp2_session_find_stream(self._session, stream_id) == ffi.NULL:
            next_available_stream_id = self.get_next_available_stream_id()
            if next_available_stream_id > stream_id:
                raise h2.exceptions.StreamIDTooLowError(stream_id, next_available_stream_id - 2)
            assert lib.nghttp2_session_set_next_stream_id(self._session, stream_id) == 0
            ret_val = stream_id
            stream_id = -1
        else:
            ret_val = 0

        if end_stream:
            flags = lib.NGHTTP2_FLAG_END_STREAM
        else:
            flags = lib.NGHTTP2_FLAG_NONE

        assert lib.nghttp2_submit_headers(self._session, flags, stream_id, priority_spec, nva, len(nva), ffi.NULL) == ret_val
        self._prepare_for_sending()

    def push_stream(self, stream_id, promised_stream_id, request_headers):
        nva_initializer = self._build_nva_initializer(request_headers)
        nva = ffi.new("nghttp2_nv[]", nva_initializer)

        if lib.nghttp2_session_find_stream(self._session, promised_stream_id) != ffi.NULL:
            raise ValueError("promised stream id already exists")

        next_available_stream_id = self.get_next_available_stream_id()
        if next_available_stream_id > promised_stream_id:
            raise h2.exceptions.StreamIDTooLowError(promised_stream_id, next_available_stream_id - 2)
        assert lib.nghttp2_session_set_next_stream_id(self._session, promised_stream_id) == 0

        assert lib.nghttp2_submit_push_promise(self._session, lib.NGHTTP2_FLAG_NONE, stream_id, nva, len(nva), ffi.NULL) == promised_stream_id
        self._prepare_for_sending()

    def send_data(self, stream_id: int, data: bytes, end_stream: bool = False, pad_length: int = None):
        if pad_length is not None:
            if not isinstance(pad_length, int):
                raise TypeError("pad_length should be integer")
            if not (0 <= pad_length <= 255):
                raise ValueError("pad_length should be between [0, 255]")

        flags = lib.NGHTTP2_FLAG_NONE
        if end_stream:
            flags |= lib.NGHTTP2_FLAG_END_STREAM

        if len(data) > self.max_outbound_frame_size:
            raise h2.exceptions.FrameTooLargeError
        if len(data) > self.local_flow_control_window(stream_id):
            raise h2.exceptions.FlowControlError

        data_handle = ffi.new_handle(DataSource(data, 0))

        data_provider = ffi.new("nghttp2_data_provider*")
        data_provider.source.ptr = data_handle
        data_provider.read_callback = lib.py_nghttp2_data_source_read_callback

        if pad_length is not None:
            self._padding_amount = pad_length + 1
        assert lib.nghttp2_submit_data(self._session, flags, stream_id, data_provider) == 0
        self._prepare_for_sending()
        self._padding_amount = 0

    def remote_flow_control_window(self, stream_id: int):
        return min(
            lib.nghttp2_session_get_stream_local_window_size(self._session, stream_id),
            lib.nghttp2_session_get_local_window_size(self._session)
        )

    def local_flow_control_window(self, stream_id: int):
        return min(
            lib.nghttp2_session_get_stream_remote_window_size(self._session, stream_id),
            lib.nghttp2_session_get_remote_window_size(self._session)
        )

    @property
    def max_inbound_frame_size(self):
        return lib.nghttp2_session_get_local_settings(self._session, lib.NGHTTP2_SETTINGS_MAX_FRAME_SIZE)

    @property
    def max_outbound_frame_size(self):
        return lib.nghttp2_session_get_remote_settings(self._session, lib.NGHTTP2_SETTINGS_MAX_FRAME_SIZE)

    def end_stream(self, stream_id: int):
        self.send_data(stream_id, b'', end_stream=True)

    def receive_data(self, data: bytes):
        try:
            buffer = ffi.from_buffer(data)
            assert lib.nghttp2_session_mem_recv(self._session, buffer, len(data)) == len(data)
            self._check_callback_exc_info()
            events = self._pending_events
            self._pending_events = []
            return events
        finally:
            self._prepare_for_sending()

    def increment_flow_control_window(self, increment, stream_id: int = 0):
        assert lib.nghttp2_submit_window_update(self._session, lib.NGHTTP2_FLAG_NONE, stream_id, increment) == 0

    def __del__(self):
        lib.nghttp2_session_del(self._session)

    def _make_option(self):
        self._option_ptr = ffi.new("nghttp2_option**")
        assert lib.nghttp2_option_new(self._option_ptr) == 0
        option = self._option_ptr[0]

        lib.nghttp2_option_set_no_auto_window_update(option, 1)
        return option

    def _nva_to_header_list(self, nva, nvlen):
        header_encoding = self._config.header_encoding
        headers = []
        for idx in range(nvlen):
            nv = nva[idx]
            name = ffi.string(nv.name, nv.namelen)
            value = ffi.string(nv.value, nv.valuelen)
            headers.append((
                name.decode(header_encoding) if header_encoding else name,
                value.decode(header_encoding) if header_encoding else value,
            ))
        return headers

    def _make_session(self):
        session_callbacks_ptr = ffi.new("nghttp2_session_callbacks**")
        assert lib.nghttp2_session_callbacks_new(session_callbacks_ptr) == 0
        session_callbacks = session_callbacks_ptr[0]


        lib.set_c_header_callbacks(session_callbacks)


        lib.nghttp2_session_callbacks_set_on_data_chunk_recv_callback(session_callbacks,
                                                                      lib.py_nghttp2_on_data_chunk_recv_callback)
        lib.nghttp2_session_callbacks_set_on_frame_recv_callback(session_callbacks,
                                                                 lib.py_nghttp2_on_frame_recv_callback)
        # lib.nghttp2_session_callbacks_set_on_stream_close_callback(session_callbacks,
        #                                                            lib.py_nghttp2_on_stream_close_callback)
        # lib.nghttp2_session_callbacks_set_on_frame_send_callback(session_callbacks,
        #                                                          lib.py_nghttp2_on_frame_send_callback)
        lib.nghttp2_session_callbacks_set_on_frame_not_send_callback(session_callbacks,
                                                                     lib.py_nghttp2_on_frame_not_send_callback)
        lib.nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(session_callbacks,
                                                                         lib.py_nghttp2_on_invalid_frame_recv_callback)
        # lib.nghttp2_session_callbacks_set_on_begin_frame_callback(session_callbacks,
        #                                                           lib.py_nghttp2_on_begin_frame_callback)
        lib.nghttp2_session_callbacks_set_select_padding_callback(session_callbacks,
                                                                  lib.py_nghttp2_select_padding_callback)
        lib.nghttp2_session_callbacks_set_error_callback2(session_callbacks,
                                                          lib.py_nghttp2_error_callback2)

        self._session_ptr = ffi.new("nghttp2_session**")
        self._handle = ffi.new_handle(self)
        self._userdata = ffi.new("userdata_t*")

        self._userdata.handle = self._handle

        option = self._make_option()

        if self._config.client_side:
            assert lib.nghttp2_session_client_new2(self._session_ptr, session_callbacks, self._userdata, option) == 0
        else:
            assert lib.nghttp2_session_server_new2(self._session_ptr, session_callbacks, self._userdata, option) == 0

        lib.nghttp2_option_del(option)
        lib.nghttp2_session_callbacks_del(session_callbacks)
        return self._session_ptr[0]

    # @ffi.def_extern(name="py_nghttp2_on_begin_frame_callback", onerror=_on_callback_error)
    # def _on_begin_frame_callback(session, hd, user_data):
    #     self = ffi.from_handle(user_data)  # type: H2Connection
    #
    #     # print(">" * 20, "Begin receive frame stream_id =", hd.stream_id, "type =", hd.type)
    #     frame_type = hd.type
    #     if frame_type == lib.NGHTTP2_DATA:
    #         self._data_frame_recv_chunk_buffer.clear()
    #     elif frame_type == lib.NGHTTP2_HEADERS or frame_type == lib.NGHTTP2_PUSH_PROMISE:
    #         self._headers_frame_recv_buffer.clear()
    #
    #     return 0

    # @ffi.def_extern(name="py_nghttp2_on_begin_headers_callback")
    # def _on_begin_headers_callback(session, frame, user_data):
    #     self = ffi.from_handle(user_data)  # type: H2Connection
    #     return 0

    # @ffi.def_extern(name="py_nghttp2_on_header_callback", onerror=_on_callback_error)
    # def _on_header_callback(session, frame, name, namelen, value, valuelen, flags, user_data):
    #     self = ffi.from_handle(ffi.cast("userdata_t*", user_data).handle)  # type: H2Connection
    #     return 0

    @ffi.def_extern(name="py_nghttp2_on_data_chunk_recv_callback", onerror=_on_callback_error)
    def _on_data_chunk_recv_callback(session, flags, stream_id, data, len, user_data):
        self = ffi.from_handle(ffi.cast("userdata_t*", user_data).handle)  # type: H2Connection
        self._data_frame_recv_chunk_buffer += ffi.buffer(data, len)
        return 0

    @ffi.def_extern(name="py_nghttp2_on_frame_recv_callback", onerror=_on_callback_error)
    def _on_frame_recv_callback(session, frame, user_data):
        self = ffi.from_handle(ffi.cast("userdata_t*", user_data).handle)  # type: H2Connection

        # print(">" * 20, "Received frame stream_id =", frame.hd.stream_id, "type =", frame.hd.type)

        frame_type = frame.hd.type
        stream_id = frame.hd.stream_id
        end_flag = (frame.hd.flags & lib.NGHTTP2_FLAG_END_STREAM) != 0
        ack_flag = (frame.hd.flags & lib.NGHTTP2_FLAG_ACK) != 0

        if frame_type == lib.NGHTTP2_DATA:
            event = h2.events.DataReceived()
            event.data = self._data_frame_recv_chunk_buffer
            event.stream_id = stream_id
            event.flow_controlled_length = len(event.data) + frame.data.padlen
            event.stream_ended = end_flag
            self._data_frame_recv_chunk_buffer = bytearray()
        elif frame_type == lib.NGHTTP2_HEADERS:
            headers_category = frame.headers.cat
            if headers_category == lib.NGHTTP2_HCAT_REQUEST:
                event = h2.events.RequestReceived()
            elif headers_category == lib.NGHTTP2_HCAT_RESPONSE:
                event = h2.events.ResponseReceived()
            elif headers_category == lib.NGHTTP2_HCAT_PUSH_RESPONSE:
                event = h2.events.ResponseReceived()
            else:
                event = h2.events.TrailersReceived()
            event.stream_id = stream_id
            event.headers = self._nva_to_header_list(self._userdata.nva, self._userdata.nvlen)
            event.stream_ended = end_flag
        elif frame_type == lib.NGHTTP2_PRIORITY:
            event = h2.events.PriorityUpdated()
        elif frame_type == lib.NGHTTP2_RST_STREAM:
            event = h2.events.StreamReset()
            event.remote_reset = True
            event.stream_id = stream_id
            error_code = frame.rst_stream.error_code
            try:
                event.error_code = h2.errors.ErrorCodes(error_code)
            except ValueError:
                event.error_code = error_code
        elif frame_type == lib.NGHTTP2_SETTINGS:
            if ack_flag:
                event = h2.events.SettingsAcknowledged()
                event.changed_settings = self.local_settings.acknowledge()
            else:
                event = h2.events.RemoteSettingsChanged()
                event.changed_settings = {}
                frame_settings_buffer = frame.settings.iv
                for idx in range(frame.settings.niv):
                    settings_id = h2.settings.SettingCodes(frame_settings_buffer[idx].settings_id)
                    value = frame_settings_buffer[idx].value
                    event.changed_settings[settings_id] = h2.settings.ChangedSetting(settings_id, None, value)
        elif frame_type == lib.NGHTTP2_PUSH_PROMISE:
            event = h2.events.PushedStreamReceived()
            event.pushed_stream_id = frame.push_promise.promised_stream_id
            event.parent_stream_id = stream_id
            event.headers = self._nva_to_header_list(self._userdata.nva, self._userdata.nvlen)
        elif frame_type == lib.NGHTTP2_PING:
            if ack_flag:
                event = h2.events.PingAckReceived()
            else:
                event = h2.events.PingReceived()
            event.ping_data = bytes(ffi.buffer(frame.ping.opaque_data, 8))
        elif frame_type == lib.NGHTTP2_WINDOW_UPDATE:
            event = h2.events.WindowUpdated()
            event.stream_id = stream_id
            event.delta = frame.window_update.window_size_increment
        elif frame_type == lib.NGHTTP2_GOAWAY:
            frame_goaway = frame.goaway
            error_code = frame_goaway.error_code
            event = h2.events.ConnectionTerminated()
            try:
                event.error_code = h2.errors.ErrorCodes(error_code)
            except ValueError:
                event.error_code = error_code
            event.last_stream_id = frame_goaway.last_stream_id
            if frame_goaway.opaque_data_len > 0:
                event.additional_data = bytes(ffi.buffer(frame_goaway.opaque_data, frame_goaway.opaque_data_len))
        else:
            event = h2.events.UnknownFrameReceived()
            event.frame = None

        self._pending_events.append(event)

        if end_flag and stream_id > 0:
            event = h2.events.StreamEnded()
            event.stream_id = stream_id
            self._pending_events.append(event)
        return 0

    # @ffi.def_extern(name="py_nghttp2_on_stream_close_callback", onerror=_on_callback_error)
    # def _on_stream_close_callback(session, stream_id, error_code, user_data):
    #     self = ffi.from_handle(user_data)  # type: H2Connection
    #     return 0
    #
    # @ffi.def_extern(name="py_nghttp2_on_frame_send_callback", onerror=_on_callback_error)
    # def _on_frame_send_callback(session, frame, user_data):
    #     self = ffi.from_handle(user_data)  # type: H2Connection
    #     return 0

    @ffi.def_extern(name="py_nghttp2_on_frame_not_send_callback", onerror=_on_callback_error)
    def _on_frame_not_send_callback(session, frame, lib_error_code, user_data):
        self = ffi.from_handle(ffi.cast("userdata_t*", user_data).handle)  # type: H2Connection
        error_string = ffi.string(lib.nghttp2_strerror(lib_error_code)).decode("utf-8")
        if lib_error_code == lib.NGHTTP2_ERR_PUSH_DISABLED:
            raise h2.exceptions.ProtocolError(error_string)
        raise ValueError(error_string)

    @ffi.def_extern(name="py_nghttp2_on_invalid_frame_recv_callback", onerror=_on_callback_error)
    def _on_invalid_frame_recv_callback(session, frame, lib_error_code, user_data):
        self = ffi.from_handle(ffi.cast("userdata_t*", user_data).handle)  # type: H2Connection
        # print(">" * 20, "On invalid frame recv stream_id =", frame.hd.stream_id, "type =", frame.hd.type, "code =", lib_error_code)
        error_string = ffi.string(lib.nghttp2_strerror(lib_error_code)).decode("utf-8")
        if lib_error_code == lib.NGHTTP2_ERR_PROTO or lib_error_code == lib.NGHTTP2_ERR_HTTP_MESSAGING or lib_error_code == lib.NGHTTP2_ERR_STREAM_CLOSED:
            raise h2.exceptions.ProtocolError(error_string)
        else:
            raise ValueError(error_string)

    @ffi.def_extern(name="py_nghttp2_data_source_read_callback", onerror=_on_callback_error)
    def _data_source_read_callback(session, stream_id, buf, length, data_flags, source, user_data):
        self = ffi.from_handle(ffi.cast("userdata_t*", user_data).handle)  # type: H2Connection
        data_source = ffi.from_handle(source.ptr)  # type: DataSource

        output_buffer = ffi.buffer(buf, length)
        data_to_write = data_source.data[data_source.pos:data_source.pos+length]
        output_buffer[:len(data_to_write)] = data_to_write
        data_source.pos += len(data_to_write)

        if data_source.pos >= len(data_source.data):
            data_flags[0] |= lib.NGHTTP2_DATA_FLAG_EOF
        return len(data_to_write)

    @ffi.def_extern(name="py_nghttp2_select_padding_callback", onerror=_on_callback_error)
    def _select_padding_callback(session, frame, max_payloadlen, user_data):
        if frame.hd.type == lib.NGHTTP2_DATA:
            self = ffi.from_handle(ffi.cast("userdata_t*", user_data).handle)  # type: H2Connection
            return frame.hd.length + self._padding_amount
        return frame.hd.length

    @ffi.def_extern(name="py_nghttp2_error_callback2", onerror=_on_callback_error)
    def _error_callback2(session, lib_error_code, msg, len, user_data):
        raise ValueError(ffi.string(msg, len))
