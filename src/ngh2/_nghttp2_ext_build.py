import os
import glob

from cffi import FFI


ffibuilder = FFI()

ffibuilder.set_source(
    "ngh2._nghttp2",
    """
    #include <nghttp2/nghttp2.h>
    
    #define NV_BUF_SIZE 2048
    #define CHAR_BUF_SIZE 16384
    
    typedef struct userdata {
        void* handle;
        size_t nvlen;
        size_t charlen;
        nghttp2_nv nva[NV_BUF_SIZE];
        char chardata[CHAR_BUF_SIZE];
    } userdata_t;

    int c_nghttp2_on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
        ((userdata_t*)user_data)->nvlen = 0;
        ((userdata_t*)user_data)->charlen = 0;
        return 0;
    }
                                                         
    int c_nghttp2_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                                      const uint8_t *name, size_t namelen,
                                                      const uint8_t *value, size_t valuelen,
                                                      uint8_t flags, void *user_data) {
        
        size_t *nvlen = &((userdata_t*)user_data)->nvlen;
        size_t *charlen = &((userdata_t*)user_data)->charlen;
        nghttp2_nv* nva = ((userdata_t*)user_data)->nva;
        char* chardata = ((userdata_t*)user_data)->chardata;
        
        if (*nvlen >= NV_BUF_SIZE) {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
        
        if (*charlen + namelen + valuelen >= CHAR_BUF_SIZE) {
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }

        nva[*nvlen].name = memcpy(chardata + *charlen, name, namelen);
        nva[*nvlen].value = memcpy(chardata + *charlen + namelen, value, valuelen);

        nva[*nvlen].namelen = namelen;
        nva[*nvlen].valuelen = valuelen;
        nva[*nvlen].flags = flags;
        
        ++(*nvlen);
        *charlen += namelen + valuelen;
        return 0;
    }
    
    void set_c_header_callbacks(nghttp2_session_callbacks* callbacks) {
        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, c_nghttp2_on_begin_headers_callback);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, c_nghttp2_on_header_callback);
    }
    """,
    sources=glob.glob("third_party/nghttp2/lib/*.c"),
    include_dirs=["third_party/nghttp2/lib/includes", "third_party/nghttp2_version/includes"],
    # extra_compile_args=["-DDEBUGBUILD"]
)


python_callbacks = """

#define NV_BUF_SIZE 2048
#define CHAR_BUF_SIZE 16384


typedef struct userdata {
    void* handle;
    size_t nvlen;
    size_t charlen;
    nghttp2_nv nva[NV_BUF_SIZE];
    char chardata[CHAR_BUF_SIZE];
} userdata_t;


void set_c_header_callbacks(nghttp2_session_callbacks* callbacks);

extern "Python" int py_nghttp2_on_begin_headers_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                                         void *user_data);
                                                         
extern "Python" int py_nghttp2_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                                  const uint8_t *name, size_t namelen,
                                                  const uint8_t *value, size_t valuelen,
                                                  uint8_t flags, void *user_data);
                                                  
extern "Python" int py_nghttp2_on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                                                           const uint8_t *data, size_t len, void *user_data);
                                                           
extern "Python" int py_nghttp2_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                                      void *user_data);
                                                      
extern "Python" int py_nghttp2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                                        uint32_t error_code, void *user_data);
                                                        
extern "Python" int py_nghttp2_on_frame_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                                      void *user_data);
                                                      
extern "Python" int py_nghttp2_on_frame_not_send_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                                          int lib_error_code, void *user_data);

extern "Python" int py_nghttp2_on_invalid_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                                              int lib_error_code, void *user_data);
                                                              
extern "Python" ssize_t py_nghttp2_data_source_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf,
                                                             size_t length, uint32_t *data_flags,
                                                             nghttp2_data_source *source, void *user_data);
                                                             
extern "Python" int py_nghttp2_on_begin_frame_callback(nghttp2_session *session, const nghttp2_frame_hd *hd,
                                                       void *user_data);
                                                       
extern "Python" ssize_t py_nghttp2_select_padding_callback(nghttp2_session *session, const nghttp2_frame *frame,
                                                           size_t max_payloadlen, void *user_data);
                                                           
extern "Python" int py_nghttp2_error_callback2(nghttp2_session *session, int lib_error_code, const char *msg,
                                               size_t len, void *user_data);

"""

with open(os.path.join(os.path.dirname(__file__), "nghttp2.cffi-def.h")) as fin:
    ffibuilder.cdef(fin.read() + python_callbacks)


if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
