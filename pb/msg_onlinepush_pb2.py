# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: msg_onlinepush.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import msg_comm_pb2 as msg__comm__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='msg_onlinepush.proto',
  package='',
  syntax='proto2',
  serialized_pb=_b('\n\x14msg_onlinepush.proto\x1a\x0emsg_comm.proto\"K\n\x0emsg_onlinepush\x1a\x39\n\tPbPushMsg\x12\x1a\n\x03msg\x18\x01 \x01(\x0b\x32\r.msg_comm.Msg\x12\x10\n\x05svrip\x18\x02 \x01(\x05:\x01\x30')
  ,
  dependencies=[msg__comm__pb2.DESCRIPTOR,])




_MSG_ONLINEPUSH_PBPUSHMSG = _descriptor.Descriptor(
  name='PbPushMsg',
  full_name='msg_onlinepush.PbPushMsg',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='msg', full_name='msg_onlinepush.PbPushMsg.msg', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='svrip', full_name='msg_onlinepush.PbPushMsg.svrip', index=1,
      number=2, type=5, cpp_type=1, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=58,
  serialized_end=115,
)

_MSG_ONLINEPUSH = _descriptor.Descriptor(
  name='msg_onlinepush',
  full_name='msg_onlinepush',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[_MSG_ONLINEPUSH_PBPUSHMSG, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=40,
  serialized_end=115,
)

_MSG_ONLINEPUSH_PBPUSHMSG.fields_by_name['msg'].message_type = msg__comm__pb2._MSG_COMM_MSG
_MSG_ONLINEPUSH_PBPUSHMSG.containing_type = _MSG_ONLINEPUSH
DESCRIPTOR.message_types_by_name['msg_onlinepush'] = _MSG_ONLINEPUSH
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

msg_onlinepush = _reflection.GeneratedProtocolMessageType('msg_onlinepush', (_message.Message,), dict(

  PbPushMsg = _reflection.GeneratedProtocolMessageType('PbPushMsg', (_message.Message,), dict(
    DESCRIPTOR = _MSG_ONLINEPUSH_PBPUSHMSG,
    __module__ = 'msg_onlinepush_pb2'
    # @@protoc_insertion_point(class_scope:msg_onlinepush.PbPushMsg)
    ))
  ,
  DESCRIPTOR = _MSG_ONLINEPUSH,
  __module__ = 'msg_onlinepush_pb2'
  # @@protoc_insertion_point(class_scope:msg_onlinepush)
  ))
_sym_db.RegisterMessage(msg_onlinepush)
_sym_db.RegisterMessage(msg_onlinepush.PbPushMsg)


# @@protoc_insertion_point(module_scope)
