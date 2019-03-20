# -*- coding: utf-8 -*-

from jcetype import *
import cStringIO

'''
UVarint             # Unsigned integer.
Varint              # Signed integer.
Bool                # Boolean.
Fixed64             # 8-byte string.
UInt64              # C++'s 64-bit `unsigned long long`
Int64               # C++'s 64-bit `long long`
Float64             # C++'s `double`.
Fixed32             # 4-byte string.
UInt32              # C++'s 32-bit `unsigned int`.
Int32               # C++'s 32-bit `int`.
Float32             # C++'s `float`.
Bytes               # Pure bytes string.
Unicode             # Unicode string.
TypeMetadata        # Type that describes another type.
'''
"""
ByteSimpleList      byte[]
JceListType         ArrayList
JceStructType       JceStruct
"""

class _jce_SvcReqRegister(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'bid', Long)
        self.add_field(2, 'conntype', Byte)
        self.add_field(3, 'other', String)
        self.add_field(4, 'status', Int)
        self.add_field(5, 'onlinepush', Byte)
        self.add_field(6, 'isonline', Byte)
        self.add_field(7, 'isshowonline', Byte)
        self.add_field(8, 'kikpc', Byte)
        self.add_field(9, 'kikweak', Byte)
        self.add_field(10, 'timestamp', Long)        
        self.add_field(11, '_11', Byte) 
        self.add_field(12, '_12', Byte)
        self.add_field(13, '_13', String)
        self.add_field(14, '_14', Byte)
        self.add_field(16, 'imei', ByteSimpleList)

        self.add_field(17, '_17', Short)
        self.add_field(18, '_18', Byte)
        self.add_field(19, '_19_device', String)
        self.add_field(20, '_20_device', String)
        self.add_field(21, '_21_sys_ver', String)

class _jce_HeartBeat(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'qq', Long)
        self.add_field(1, 'hb1', Long)
        self.add_field(2, 'hb2', String)
        self.add_field(3, 'hb3', Long)
        self.add_field(4, 'hb4', Long)
        self.add_field(5, 'hb5', Long)
        self.add_field(6, 'hb6', Long)
        self.add_field(7, 'hb7', Long)
        self.add_field(8, 'hb8', Long)
        self.add_field(9, 'hb9', Long)
        self.add_field(10, 'hb10', Long)
        self.add_field(11, 'hb11', Long)

class _jce_SvrReg(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'reg', JceStructType(_jce_SvcReqRegister))

class _jce_Map(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'map', Map)

class _jce_RequestPacket(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(1, 'version', Long)
        self.add_field(2, 'packagetype', Long)
        self.add_field(3, 'messagetype', Long)
        self.add_field(4, 'requestid', Long)
        self.add_field(5, 'servantname', String)
        self.add_field(6, 'funcname', String)
        self.add_field(7, 'buffer', ByteSimpleList)     
        self.add_field(8, 'timeout', Long)
        self.add_field(9, 'context', Map)
        self.add_field(10, 'status', Map)

class _jce_SimpleList(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(1, 'value', ByteSimpleList)


class _jce_GetGroupList(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'qq', Long)
        self.add_field(1, 'gl1', Long)
        self.add_field(4, 'gl4', Long)
        self.add_field(5, 'gl5', Long)
class _jce_Troop(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'code', Long)
        self.add_field(2, 'cflag', Byte)
        self.add_field(3, 'infoseq', Long)
        self.add_field(4, 'name', String)
        self.add_field(5, 'memo', String)
        self.add_field(6, 'flagext', Long)
        self.add_field(7, 'rankseq', Long)
        self.add_field(8, 'certificationtype', Long)
        self.add_field(9, 'shutuptimestamp', Long)
        self.add_field(10, 'myshutuptimestamp', Long)
        self.add_field(11, 'cmduinuinflag', Long)
        self.add_field(12, 'additionalflag', Long)
        self.add_field(13, 'grouptypeflag', Long)
        self.add_field(14, 'groupsectype', Long)
        self.add_field(15, 'groupsectypeinfo', Long)
        self.add_field(16, 'groupclassext', Long)
        self.add_field(17, 'appprivilegeflag', Long)
        self.add_field(18, 'subscriptionuin', Long)
        self.add_field(19, 'membernum', Long)
        self.add_field(20, 'membernumseq', Long)
        self.add_field(21, 'membercardseq', Long)

        self.add_field(22, 'groupflagext3', Long)
        self.add_field(23, 'groupowneruin', Long)
        self.add_field(24, 'isconfgroup', Byte)
        self.add_field(25, 'ismodifyconfgroupface', Byte)
        self.add_field(26, 'ismodifyconfgroupname', Byte)
        self.add_field(27, 'cmduinjointime', Long)
        self.add_field(28, 'companyid', Long)
        self.add_field(29, 'maxgroupmembernum', Long)

class _jce_TroopWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'troop', JceStructType(_jce_Troop))
        self.structwrap = 1
class _jce_Troop_V1(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'code', Long)
        self.add_field(2, 'cflag', Byte)
        self.add_field(3, 'infoseq', Long)
        self.add_field(4, 'name', String)
        self.add_field(5, 'memo', String)
        self.add_field(6, 'flagext', Long)
        self.add_field(7, 'rankseq', Long)
        self.add_field(8, 'certificationtype', Long)
        self.add_field(9, 'shutuptimestamp', Long)
        self.add_field(10, 'myshutuptimestamp', Long)
        self.add_field(11, 'cmduinuinflag', Long)
        self.add_field(12, 'additionalflag', Long)
        self.add_field(13, 'grouptypeflag', Long)
        self.add_field(14, 'groupsectype', Long)
        self.add_field(15, 'groupsectypeinfo', Long)
        self.add_field(16, 'groupclassext', Long)
        self.add_field(17, 'appprivilegeflag', Long)
        self.add_field(18, 'subscriptionuin', Long)
        self.add_field(19, 'membernum', Long)
        self.add_field(20, 'membernumseq', Long)
        self.add_field(21, 'membercardseq', Long)
        #7.9.7
        self.add_field(22, 'groupflagext3', Long)
        self.add_field(23, 'groupowneruin', Long)
        self.add_field(24, 'isconfgroup', Byte)
        self.add_field(25, 'ismodifyconfgroupface', Byte)
        self.add_field(26, 'ismodifyconfgroupname', Byte)
        self.add_field(27, 'cmduinjointime', Long)
        self.add_field(28, 'companyid', Long)
        self.add_field(29, 'maxgroupmembernum', Long)

class _jce_TroopWrap_V1(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'troop', JceStructType(_jce_Troop_V1))
        self.structwrap = 1

class _jce_stLevelRankPair(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'level', Long)
        self.add_field(1, 'rank', String)

class _jce_stLevelRankPairWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'stLevelRankPair', JceStructType(_jce_stLevelRankPair))
        self.structwrap = 1

class _jce_stGroupRankInfo(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'groupcode', Long)
        self.add_field(1, 'groupranksysflag', Byte)
        self.add_field(2, 'grouprankuserflag', Byte)
        self.add_field(3, 'rankmap', JceListType(_jce_stLevelRankPairWrap))
        self.add_field(4, 'grouprankseq', Long)
        self.add_field(5, 'ownername', String) 
        self.add_field(6, 'adminNname', String)
        self.add_field(7, 'officemode', Long)
class _jce_stGroupRankInfoWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'stGroupRankInfo', JceStructType(_jce_stGroupRankInfo))
        self.structwrap = 1

class _jce_stFavoriteGroup(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'groupcode', Long)
        self.add_field(1, 'timestamp', Long)
        self.add_field(2, 'snsflag', Long)
        self.add_field(3, 'opentimestamp', Long)
class _jce_stFavoriteGroupWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'stFavoriteGroup', JceStructType(_jce_stFavoriteGroup))
        self.structwrap = 1

class _jce_GetTroopListRespV2(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'troopcount', Long)
        self.add_field(2, 'result', Long)
        self.add_field(3, 'errorCode', Long)
        self.add_field(4, 'vecCookies', ByteSimpleList)
        self.add_field(5, 'vecTroopList', JceListType(_jce_TroopWrap))          #ArrayList
        self.add_field(6, 'vecTroopListDel', JceListType(_jce_TroopWrap))
        self.add_field(7, 'vecTroopRank', JceListType(_jce_stGroupRankInfoWrap))
        self.add_field(8, 'vecFavGroup', JceListType(_jce_stFavoriteGroupWrap))
class _jce_GetTroopListRespV2Wrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'TroopListRespV2', JceStructType(_jce_GetTroopListRespV2))
        self.structwrap = 1
class _jce_GetTroopListRespV2_V1(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'troopcount', Long)
        self.add_field(2, 'result', Long)
        self.add_field(3, 'errorCode', Long)
        self.add_field(4, 'vecCookies', ByteSimpleList)
        self.add_field(5, 'vecTroopList', JceListType(_jce_TroopWrap_V1))          #ArrayList
        self.add_field(6, 'vecTroopListDel', JceListType(_jce_TroopWrap_V1))
        self.add_field(7, 'vecTroopRank', JceListType(_jce_stGroupRankInfoWrap))
        self.add_field(8, 'vecFavGroup', JceListType(_jce_stFavoriteGroupWrap))
class _jce_GetTroopListRespV2Wrap_V1(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'TroopListRespV2', JceStructType(_jce_GetTroopListRespV2_V1))
        self.structwrap = 1

class _jce_GetGroupMemberList(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'groupcode', Long)
        self.add_field(2, 'nextuin', Long)
        self.add_field(3, 'groupuin', Long)
        self.add_field(4, 'version', Long)
class _jce_TroopMember(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'memberuin', Long)            #qq
        self.add_field(1, 'faceid', Long)
        self.add_field(2, 'age', Long)
        self.add_field(3, 'gender', Long)
        self.add_field(4, 'nick', String)
        self.add_field(5, 'status', Long)
        self.add_field(6, 'showname', String)
        #self.add_field(7, '_7', x)
        self.add_field(8, 'name', String)
        self.add_field(9, 'cgender', Long)
        self.add_field(10, 'phone', String)
        self.add_field(11, 'email', String)
        self.add_field(12, 'memo', String)
        self.add_field(13, 'autoremark', String)
        self.add_field(14, 'memberlevel', Long)
        self.add_field(15, 'jointime', Long)
        self.add_field(16, 'lastspeaktime', Long)
        self.add_field(17, 'creditlevel', Long)
        self.add_field(18, 'flag', Long)                #flag = 1 -> group manager
        self.add_field(19, 'flagext', Long)             #flag = Ex -> group owner ?
        self.add_field(20, 'point', Long)
        self.add_field(21, 'concerned', Long)
        self.add_field(22, 'shielded', Long)
        self.add_field(23, 'specialtitle', String)
        self.add_field(24, 'specialtitleexpiretime', Long)
        self.add_field(25, 'bytes_job', String)
        self.add_field(26, '_26', Long)
        self.add_field(27, '_27', Long)
        self.add_field(28, '_28', Long)
        self.add_field(29, '_29', Long)
        self.add_field(30, '_30', Long)
        self.add_field(31, '_31', Long)
class _jce_TroopMemberWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'member', JceStructType(_jce_TroopMember))
        self.structwrap = 1
class _jce_GetTroopMemberListResp(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'groupcode', Long)
        self.add_field(2, 'groupuin', Long)
        self.add_field(3, 'vecTroopMember', JceListType(_jce_TroopMemberWrap))
        self.add_field(4, 'nextuin', Long)
        self.add_field(5, 'result', Long)
        self.add_field(6, 'errorcode', Long)
        self.add_field(7, 'office_mode', Long)
        self.add_field(8, '_8', Long)
class _jce_GetTroopMemberListRespWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'GTMLRESP', JceStructType(_jce_GetTroopMemberListResp))
        self.structwrap = 1


class _jce_GroupSendMessage(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'qq', Long)
        self.add_field(1, 'groupcode', Long)
        self.add_field(2, 'message', String)
        self.add_field(3, '_3', Long)
        self.add_field(4, 'utfmessage', ByteSimpleList)
        self.add_field(5, '_5', Long)
        self.add_field(6, '_6', Long)
        self.add_field(7, '_7', Long)
        self.add_field(8, '_8', Long)
        self.add_field(9, '_9', Long)
        self.add_field(10, '_10', Long)
        self.add_field(11, '_11', Long)
        self.add_field(12, '_12', Long)
        self.add_field(13, '_13', Long)



class _jce_PicInfo(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'vPath', ByteSimpleList)
        self.add_field(1, 'vHost', ByteSimpleList)
class _jce_TempMsgHead(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'c2c_type', Long)
        self.add_field(1, 'service_type', Long)
class _jce_QSharedata(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'pkgname', String)
        self.add_field(1, 'msgtail', String)
        self.add_field(2, 'picurl', String)
        self.add_field(3, 'url', String)
#D:\android\QQ6.7.1\jadx\classes4\OnlinePushPack\MsgInfo.java
class _jce_MsgInfo(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'fromuin', Long)
        self.add_field(1, 'msgtime', Long)
        self.add_field(2, 'msgtype', Long)
        self.add_field(3, 'msgseq', Long)
        self.add_field(4, 'msg', String)
        self.add_field(5, 'realmsgtime', Long)
        self.add_field(6, 'vmsg', ByteSimpleList)
        self.add_field(7, 'appshareid', Long)
        self.add_field(8, 'msgcookies', ByteSimpleList)
        self.add_field(9, 'appsharecookie', ByteSimpleList)
        self.add_field(10, 'msguid', Long)
        self.add_field(11, 'lastchangetime', Long)
        self.add_field(12, 'picinfo', JceListType(_jce_PicInfo))
        self.add_field(13, 'sharedata', JceStructType(_jce_QSharedata))
        self.add_field(14, 'frominstid', Long)
        self.add_field(15, 'rmarkofsender', ByteSimpleList)
        self.add_field(16, 'frommobile', String)
        self.add_field(17, 'fromname', String)
        self.add_field(18, 'nickname', JceListType(String))                     
        self.add_field(19, 'c2ctmpmsghead', JceStructType(_jce_TempMsgHead))
class _jce_MsgInfoWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'msginfo', JceStructType(_jce_MsgInfo))
        self.structwrap = 1

#D:\android\QQ6.7.1\jadx\classes2\PushNotifyPack\RequestPushNotify.java
class _jce_RequestPushNotify(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'type', Long)
        self.add_field(2, 'service', String)
        self.add_field(3, 'cmd', String)
        self.add_field(4, 'notifycookie', ByteSimpleList)
        self.add_field(5, 'msgtype', Long)
        self.add_field(6, 'useractive', Long)
        self.add_field(7, 'generalflag', Long)
        self.add_field(8, 'bindeduin', Long)
        self.add_field(9, 'msginfo', JceStructType(_jce_MsgInfo))
        self.add_field(10, '_10', String)
class _jce_RequestPushNotifyWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'requestpushnotify', JceStructType(_jce_RequestPushNotify))
        self.structwrap = 1

class _jce_UinPairMsg(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'lastreadtime', Long)
        self.add_field(1, 'peeruin', Long)
        self.add_field(2, 'msgcompleted', Long)
        self.add_field(3, 'msginfos', JceListType(_jce_MsgInfoWrap))
class _jce_UinPairMsgWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uinpairmsg', JceStructType(_jce_UinPairMsg))
        self.structwrap = 1

class _jce_SvcReqPushMsg(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uin', Long)
        self.add_field(1, 'msgtime', Long)
        self.add_field(2, 'msginfos', JceListType(_jce_MsgInfoWrap))
        self.add_field(3, 'vrip', Long)
        self.add_field(4, 'synccookie', ByteSimpleList)
        self.add_field(5, 'uinpairmsg', JceListType(_jce_UinPairMsgWrap))
        self.add_field(6, 'previews', Map)
        self.add_field(7, 'useractive', Long)
class _jce_SvcReqPushMsgWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'svcreqpushmsg', JceStructType(_jce_SvcReqPushMsg))
        self.structwrap = 1


class _jce_GroupVoiceInfo(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'groupcode', Long)
        self.add_field(1, 'fileid', Long)
        self.add_field(2, 'filemd5', ByteSimpleList)
class _jce_C2CVoiceInfo(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'uuid', String)
class _jce_VoiceMatchStatus(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'isclivoicesdkready', Long)
        self.add_field(1, 'clienttrytime', Long)
        self.add_field(2, 'servertrytime', Long)
        self.add_field(3, 'libversion', String)

class _jce_VoiceRedPackMatchReq(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'grabuin', Long)
        self.add_field(1, 'billno', String)
        self.add_field(2, 'voicetext', String)
        self.add_field(3, 'makeuin', Long)
        self.add_field(4, 'skey', String)
        self.add_field(5, 'appid', Long)
        self.add_field(6, 'fromtype', Long)
        self.add_field(7, 'groupvoiceinfo', JceStructType(_jce_GroupVoiceInfo))
        self.add_field(8, 'platform', Long)
        self.add_field(9, 'c2cvoiceinfo', JceStructType(_jce_C2CVoiceInfo))
        self.add_field(10, 'qqversion', String)
        self.add_field(11, 'voicematchstatus', JceStructType(_jce_VoiceMatchStatus))
class _jce_VoiceRedPackMatchReqWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'voiceredpackmatchreq', JceStructType(_jce_VoiceRedPackMatchReq))
        self.structwrap = 1

class _jce_VoiceRedPackMatchRsp(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'grabuin', Long)
        self.add_field(1, 'billno', String)
        self.add_field(2, 'makeuin', Long)
        self.add_field(3, 'status', Long)
        self.add_field(4, 'timeinterval', Long)
        self.add_field(5, 'strerr', String)
        self.add_field(6, 'degree', String)
class _jce_VoiceRedPackMatchRspWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'voiceredpackmatchrsp', JceStructType(_jce_VoiceRedPackMatchRsp))
        self.structwrap = 1

class _jce_SignatureReq(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(1, 'signatures', JceListType(String))
        self.add_field(2, 'lcid', Long)
        self.add_field(3, 'uins', JceListType(String))
        self.add_field(4, 'base', Byte)
class _jce_SignatureReqWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'signaturereq', JceStructType(_jce_SignatureReq))
        self.structwrap = 1
class _jce_SignatureRsp(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(1, 'status', Long)
class _jce_SignatureRspWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'signaturersp', JceStructType(_jce_SignatureRsp))
        self.structwrap = 1

class _jce_ReqFavoriteHead(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'luin', Long)
        self.add_field(1, 'shversion', Long)
        self.add_field(2, 'iseq', Long)
        self.add_field(3, 'breqtype', Byte)
        self.add_field(4, 'btriggered', Byte)
        self.add_field(5, 'vcookies', ByteSimpleList)
class _jce_ReqFavoriteHeadWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'reqfavoritehead', JceStructType(_jce_ReqFavoriteHead))
        self.structwrap = 1
class _jce_ReqFavorite(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'stheader', JceStructType(_jce_ReqFavoriteHead))
        self.add_field(1, 'lmid', Long)
        self.add_field(2, 'coptype', Long)
        self.add_field(3, 'emsource', Long)
        self.add_field(4, 'icount', Long)
class _jce_ReqFavoriteWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'reqfavorite', JceStructType(_jce_ReqFavorite))
        self.structwrap = 1

class _jce_RespFavoriteHead(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'shversion', Long)
        self.add_field(1, 'iseq', Long)
        self.add_field(2, 'luin', Long)
        self.add_field(3, 'ireplycode', Long)
        self.add_field(4, 'strresult', String)
class _jce_RespFavoriteHeadWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'respfavoritehead', JceStructType(_jce_RespFavoriteHead))
        self.structwrap = 1
class _jce_RespFavorite(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'stheader', JceStructType(_jce_RespFavoriteHead))
        self.add_field(1, 'lmid', Long)
        self.add_field(2, 'coptype', Byte)
        self.add_field(3, 'vnotice', ByteSimpleList)
class _jce_RespFavoriteWrap(MessageType):
    def __init__(self):
        MessageType.__init__(self)
        self.add_field(0, 'respfavorite', JceStructType(_jce_RespFavorite))
        self.structwrap = 1


jce_SvcReqRegister = _jce_SvcReqRegister()
jce_SvrReg = _jce_SvrReg()
jce_Map = _jce_Map()
jce_RequestPacket = _jce_RequestPacket()
jce_HeartBeat = _jce_HeartBeat()
jce_GroupSendMessage = _jce_GroupSendMessage()

jce_SimpleList = _jce_SimpleList()
jce_GetGroupList = _jce_GetGroupList()

jce_Troop = _jce_Troop()
jce_GetTroopListRespV2 = _jce_GetTroopListRespV2()
jce_GetTroopListRespV2Wrap = _jce_GetTroopListRespV2Wrap()
jce_GetTroopListRespV2Wrap_V1 = _jce_GetTroopListRespV2Wrap_V1()

jce_GetGroupMemberList = _jce_GetGroupMemberList()
jce_TroopMember = _jce_TroopMember()
jce_GetTroopMemberListResp = _jce_GetTroopMemberListResp()
jce_GetTroopMemberListRespWrap = _jce_GetTroopMemberListRespWrap()

jce_RequestPushNotify = _jce_RequestPushNotify()
jce_RequestPushNotifyWrap = _jce_RequestPushNotifyWrap()

jce_SvcReqPushMsg = _jce_SvcReqPushMsg()
jce_SvcReqPushMsgWrap = _jce_SvcReqPushMsgWrap()

jce_GroupVoiceInfo = _jce_GroupVoiceInfo()
jce_C2CVoiceInfo = _jce_C2CVoiceInfo()
jce_VoiceMatchStatus = _jce_VoiceMatchStatus()
jce_VoiceRedPackMatchReq = _jce_VoiceRedPackMatchReq()
jce_VoiceRedPackMatchReqWrap = _jce_VoiceRedPackMatchReqWrap()

jce_VoiceRedPackMatchRsp = _jce_VoiceRedPackMatchRsp()
jce_VoiceRedPackMatchRspWrap = _jce_VoiceRedPackMatchRspWrap()

jce_SignatureReq = _jce_SignatureReq()
jce_SignatureReqWrap = _jce_SignatureReqWrap()
jce_SignatureRsp = _jce_SignatureRsp()
jce_SignatureRspWrap = _jce_SignatureRspWrap()

jce_ReqFavoriteHead = _jce_ReqFavoriteHead()
jce_ReqFavoriteHeadWrap = _jce_ReqFavoriteHeadWrap()
jce_ReqFavorite = _jce_ReqFavorite()
jce_ReqFavoriteWrap = _jce_ReqFavoriteWrap()

jce_RespFavoriteHead = _jce_RespFavoriteHead()
jce_RespFavoriteHeadWrap = _jce_RespFavoriteHeadWrap()
jce_RespFavorite = _jce_RespFavorite()
jce_RespFavoriteWrap = _jce_RespFavoriteWrap()
