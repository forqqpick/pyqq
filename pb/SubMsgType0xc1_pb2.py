# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: SubMsgType0xc1.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='SubMsgType0xc1.proto',
  package='',
  syntax='proto2',
  serialized_pb=_b('\n\x14SubMsgType0xc1.proto\"\xb2\x05\n\x0eSubMsgType0xc1\x1a\xfa\x02\n\x07MsgBody\x12\x16\n\x0e\x62ytes_file_key\x18\x01 \x01(\x0c\x12\x1a\n\x0fuint64_from_uin\x18\x02 \x01(\x04:\x01\x30\x12\x18\n\ruint64_to_uin\x18\x03 \x01(\x04:\x01\x30\x12\x18\n\ruint32_status\x18\x04 \x01(\r:\x01\x30\x12\x15\n\nuint32_ttl\x18\x05 \x01(\r:\x01\x30\x12\x16\n\x0buint32_type\x18\x06 \x01(\r:\x01\x30\x12(\n\x1duint32_encrypt_prehead_length\x18\x07 \x01(\r:\x01\x30\x12\x1e\n\x13uint32_encrypt_type\x18\x08 \x01(\r:\x01\x30\x12\x19\n\x11\x62ytes_encrypt_key\x18\t \x01(\x0c\x12\x1c\n\x11uint32_read_times\x18\n \x01(\r:\x01\x30\x12\x1b\n\x10uint32_left_time\x18\x0b \x01(\r:\x01\x30\x12\x38\n\x10not_online_image\x18\x0c \x01(\x0b\x32\x1e.SubMsgType0xc1.NotOnlineImage\x1a\xa2\x02\n\x0eNotOnlineImage\x12\x11\n\tfile_path\x18\x01 \x01(\x0c\x12\x13\n\x08\x66ile_len\x18\x02 \x01(\r:\x01\x30\x12\x15\n\rdownload_path\x18\x03 \x01(\x0c\x12\x19\n\x11old_ver_send_file\x18\x04 \x01(\x0c\x12\x13\n\x08img_type\x18\x05 \x01(\r:\x01\x30\x12\x16\n\x0epreviews_image\x18\x06 \x01(\x0c\x12\x0f\n\x07pic_md5\x18\x07 \x01(\x0c\x12\x15\n\npic_height\x18\x08 \x01(\r:\x01\x30\x12\x14\n\tpic_width\x18\t \x01(\r:\x01\x30\x12\x0e\n\x06res_id\x18\n \x01(\x0c\x12\x0c\n\x04\x66lag\x18\x0b \x01(\x0c\x12\x18\n\x10str_download_url\x18\x0c \x01(\t\x12\x13\n\x08original\x18\r \x01(\r:\x01\x30')
)




_SUBMSGTYPE0XC1_MSGBODY = _descriptor.Descriptor(
  name='MsgBody',
  full_name='SubMsgType0xc1.MsgBody',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='bytes_file_key', full_name='SubMsgType0xc1.MsgBody.bytes_file_key', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint64_from_uin', full_name='SubMsgType0xc1.MsgBody.uint64_from_uin', index=1,
      number=2, type=4, cpp_type=4, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint64_to_uin', full_name='SubMsgType0xc1.MsgBody.uint64_to_uin', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_status', full_name='SubMsgType0xc1.MsgBody.uint32_status', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_ttl', full_name='SubMsgType0xc1.MsgBody.uint32_ttl', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_type', full_name='SubMsgType0xc1.MsgBody.uint32_type', index=5,
      number=6, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_encrypt_prehead_length', full_name='SubMsgType0xc1.MsgBody.uint32_encrypt_prehead_length', index=6,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_encrypt_type', full_name='SubMsgType0xc1.MsgBody.uint32_encrypt_type', index=7,
      number=8, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='bytes_encrypt_key', full_name='SubMsgType0xc1.MsgBody.bytes_encrypt_key', index=8,
      number=9, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_read_times', full_name='SubMsgType0xc1.MsgBody.uint32_read_times', index=9,
      number=10, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_left_time', full_name='SubMsgType0xc1.MsgBody.uint32_left_time', index=10,
      number=11, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='not_online_image', full_name='SubMsgType0xc1.MsgBody.not_online_image', index=11,
      number=12, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
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
  serialized_start=44,
  serialized_end=422,
)

_SUBMSGTYPE0XC1_NOTONLINEIMAGE = _descriptor.Descriptor(
  name='NotOnlineImage',
  full_name='SubMsgType0xc1.NotOnlineImage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='file_path', full_name='SubMsgType0xc1.NotOnlineImage.file_path', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='file_len', full_name='SubMsgType0xc1.NotOnlineImage.file_len', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='download_path', full_name='SubMsgType0xc1.NotOnlineImage.download_path', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='old_ver_send_file', full_name='SubMsgType0xc1.NotOnlineImage.old_ver_send_file', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='img_type', full_name='SubMsgType0xc1.NotOnlineImage.img_type', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='previews_image', full_name='SubMsgType0xc1.NotOnlineImage.previews_image', index=5,
      number=6, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='pic_md5', full_name='SubMsgType0xc1.NotOnlineImage.pic_md5', index=6,
      number=7, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='pic_height', full_name='SubMsgType0xc1.NotOnlineImage.pic_height', index=7,
      number=8, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='pic_width', full_name='SubMsgType0xc1.NotOnlineImage.pic_width', index=8,
      number=9, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='res_id', full_name='SubMsgType0xc1.NotOnlineImage.res_id', index=9,
      number=10, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='flag', full_name='SubMsgType0xc1.NotOnlineImage.flag', index=10,
      number=11, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='str_download_url', full_name='SubMsgType0xc1.NotOnlineImage.str_download_url', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='original', full_name='SubMsgType0xc1.NotOnlineImage.original', index=12,
      number=13, type=13, cpp_type=3, label=1,
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
  serialized_start=425,
  serialized_end=715,
)

_SUBMSGTYPE0XC1 = _descriptor.Descriptor(
  name='SubMsgType0xc1',
  full_name='SubMsgType0xc1',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[_SUBMSGTYPE0XC1_MSGBODY, _SUBMSGTYPE0XC1_NOTONLINEIMAGE, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=25,
  serialized_end=715,
)

_SUBMSGTYPE0XC1_MSGBODY.fields_by_name['not_online_image'].message_type = _SUBMSGTYPE0XC1_NOTONLINEIMAGE
_SUBMSGTYPE0XC1_MSGBODY.containing_type = _SUBMSGTYPE0XC1
_SUBMSGTYPE0XC1_NOTONLINEIMAGE.containing_type = _SUBMSGTYPE0XC1
DESCRIPTOR.message_types_by_name['SubMsgType0xc1'] = _SUBMSGTYPE0XC1
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SubMsgType0xc1 = _reflection.GeneratedProtocolMessageType('SubMsgType0xc1', (_message.Message,), dict(

  MsgBody = _reflection.GeneratedProtocolMessageType('MsgBody', (_message.Message,), dict(
    DESCRIPTOR = _SUBMSGTYPE0XC1_MSGBODY,
    __module__ = 'SubMsgType0xc1_pb2'
    # @@protoc_insertion_point(class_scope:SubMsgType0xc1.MsgBody)
    ))
  ,

  NotOnlineImage = _reflection.GeneratedProtocolMessageType('NotOnlineImage', (_message.Message,), dict(
    DESCRIPTOR = _SUBMSGTYPE0XC1_NOTONLINEIMAGE,
    __module__ = 'SubMsgType0xc1_pb2'
    # @@protoc_insertion_point(class_scope:SubMsgType0xc1.NotOnlineImage)
    ))
  ,
  DESCRIPTOR = _SUBMSGTYPE0XC1,
  __module__ = 'SubMsgType0xc1_pb2'
  # @@protoc_insertion_point(class_scope:SubMsgType0xc1)
  ))
_sym_db.RegisterMessage(SubMsgType0xc1)
_sym_db.RegisterMessage(SubMsgType0xc1.MsgBody)
_sym_db.RegisterMessage(SubMsgType0xc1.NotOnlineImage)


# @@protoc_insertion_point(module_scope)
