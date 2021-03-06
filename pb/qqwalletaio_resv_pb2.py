# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: qqwalletaio_resv.proto

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
  name='qqwalletaio_resv.proto',
  package='',
  syntax='proto2',
  serialized_pb=_b('\n\x16qqwalletaio_resv.proto\"\x89\x04\n\x10qqwalletaio_resv\x1a\x38\n\x05Payer\x12\x15\n\nuint64_uin\x18\x01 \x01(\x04:\x01\x30\x12\x18\n\ruint32_amount\x18\x02 \x01(\r:\x01\x30\x1a\x33\n\x15qqwalletaio_body_resv\x12\x1a\n\x0fuint32_pfa_type\x18\x01 \x01(\r:\x01\x30\x1a\x85\x03\n\x15qqwalletaio_elem_resv\x12\x1b\n\x13\x62ytes_subject_image\x18\x01 \x01(\x0c\x12\x16\n\x0etransaction_id\x18\x02 \x01(\x0c\x12 \n\x15sound_record_duration\x18\x03 \x01(\r:\x01\x30\x12\x1f\n\x14uint32_resource_type\x18\x04 \x01(\r:\x01\x30\x12\x19\n\x0euint32_skin_id\x18\x05 \x01(\r:\x01\x30\x12\x1c\n\x11uint32_effects_id\x18\x06 \x01(\r:\x01\x30\x12\x1f\n\x14int32_special_pop_id\x18\x07 \x01(\x05:\x01\x30\x12*\n\trpt_payer\x18\x08 \x03(\x0b\x32\x17.qqwalletaio_resv.Payer\x12\x1b\n\x10uint32_subjectid\x18\t \x01(\r:\x01\x30\x12\x19\n\x0euint32_hb_from\x18\n \x01(\r:\x01\x30\x12\x19\n\x0euint32_song_id\x18\x0b \x01(\r:\x01\x30\x12\x1b\n\x10uint32_song_flag\x18\x0c \x01(\r:\x01\x30')
)




_QQWALLETAIO_RESV_PAYER = _descriptor.Descriptor(
  name='Payer',
  full_name='qqwalletaio_resv.Payer',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='uint64_uin', full_name='qqwalletaio_resv.Payer.uint64_uin', index=0,
      number=1, type=4, cpp_type=4, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_amount', full_name='qqwalletaio_resv.Payer.uint32_amount', index=1,
      number=2, type=13, cpp_type=3, label=1,
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
  serialized_start=47,
  serialized_end=103,
)

_QQWALLETAIO_RESV_QQWALLETAIO_BODY_RESV = _descriptor.Descriptor(
  name='qqwalletaio_body_resv',
  full_name='qqwalletaio_resv.qqwalletaio_body_resv',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='uint32_pfa_type', full_name='qqwalletaio_resv.qqwalletaio_body_resv.uint32_pfa_type', index=0,
      number=1, type=13, cpp_type=3, label=1,
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
  serialized_start=105,
  serialized_end=156,
)

_QQWALLETAIO_RESV_QQWALLETAIO_ELEM_RESV = _descriptor.Descriptor(
  name='qqwalletaio_elem_resv',
  full_name='qqwalletaio_resv.qqwalletaio_elem_resv',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='bytes_subject_image', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.bytes_subject_image', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='transaction_id', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.transaction_id', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sound_record_duration', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.sound_record_duration', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_resource_type', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.uint32_resource_type', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_skin_id', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.uint32_skin_id', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_effects_id', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.uint32_effects_id', index=5,
      number=6, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='int32_special_pop_id', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.int32_special_pop_id', index=6,
      number=7, type=5, cpp_type=1, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='rpt_payer', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.rpt_payer', index=7,
      number=8, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_subjectid', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.uint32_subjectid', index=8,
      number=9, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_hb_from', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.uint32_hb_from', index=9,
      number=10, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_song_id', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.uint32_song_id', index=10,
      number=11, type=13, cpp_type=3, label=1,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='uint32_song_flag', full_name='qqwalletaio_resv.qqwalletaio_elem_resv.uint32_song_flag', index=11,
      number=12, type=13, cpp_type=3, label=1,
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
  serialized_start=159,
  serialized_end=548,
)

_QQWALLETAIO_RESV = _descriptor.Descriptor(
  name='qqwalletaio_resv',
  full_name='qqwalletaio_resv',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[_QQWALLETAIO_RESV_PAYER, _QQWALLETAIO_RESV_QQWALLETAIO_BODY_RESV, _QQWALLETAIO_RESV_QQWALLETAIO_ELEM_RESV, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=27,
  serialized_end=548,
)

_QQWALLETAIO_RESV_PAYER.containing_type = _QQWALLETAIO_RESV
_QQWALLETAIO_RESV_QQWALLETAIO_BODY_RESV.containing_type = _QQWALLETAIO_RESV
_QQWALLETAIO_RESV_QQWALLETAIO_ELEM_RESV.fields_by_name['rpt_payer'].message_type = _QQWALLETAIO_RESV_PAYER
_QQWALLETAIO_RESV_QQWALLETAIO_ELEM_RESV.containing_type = _QQWALLETAIO_RESV
DESCRIPTOR.message_types_by_name['qqwalletaio_resv'] = _QQWALLETAIO_RESV
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

qqwalletaio_resv = _reflection.GeneratedProtocolMessageType('qqwalletaio_resv', (_message.Message,), dict(

  Payer = _reflection.GeneratedProtocolMessageType('Payer', (_message.Message,), dict(
    DESCRIPTOR = _QQWALLETAIO_RESV_PAYER,
    __module__ = 'qqwalletaio_resv_pb2'
    # @@protoc_insertion_point(class_scope:qqwalletaio_resv.Payer)
    ))
  ,

  qqwalletaio_body_resv = _reflection.GeneratedProtocolMessageType('qqwalletaio_body_resv', (_message.Message,), dict(
    DESCRIPTOR = _QQWALLETAIO_RESV_QQWALLETAIO_BODY_RESV,
    __module__ = 'qqwalletaio_resv_pb2'
    # @@protoc_insertion_point(class_scope:qqwalletaio_resv.qqwalletaio_body_resv)
    ))
  ,

  qqwalletaio_elem_resv = _reflection.GeneratedProtocolMessageType('qqwalletaio_elem_resv', (_message.Message,), dict(
    DESCRIPTOR = _QQWALLETAIO_RESV_QQWALLETAIO_ELEM_RESV,
    __module__ = 'qqwalletaio_resv_pb2'
    # @@protoc_insertion_point(class_scope:qqwalletaio_resv.qqwalletaio_elem_resv)
    ))
  ,
  DESCRIPTOR = _QQWALLETAIO_RESV,
  __module__ = 'qqwalletaio_resv_pb2'
  # @@protoc_insertion_point(class_scope:qqwalletaio_resv)
  ))
_sym_db.RegisterMessage(qqwalletaio_resv)
_sym_db.RegisterMessage(qqwalletaio_resv.Payer)
_sym_db.RegisterMessage(qqwalletaio_resv.qqwalletaio_body_resv)
_sym_db.RegisterMessage(qqwalletaio_resv.qqwalletaio_elem_resv)


# @@protoc_insertion_point(module_scope)
