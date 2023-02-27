144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   1) /*
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   2)  * Copyright (c) 2021 Huawei Device Co., Ltd.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   3)  * Licensed under the Apache License, Version 2.0 (the "License");
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   4)  * you may not use this file except in compliance with the License.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   5)  * You may obtain a copy of the License at
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   6)  *
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   7)  *     http://www.apache.org/licenses/LICENSE-2.0
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   8)  *
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800   9)  * Unless required by applicable law or agreed to in writing, software
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  10)  * distributed under the License is distributed on an "AS IS" BASIS,
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  11)  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  12)  * See the License for the specific language governing permissions and
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  13)  * limitations under the License.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  14)  */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  15) 
2f6afc061c (黄师伟        2022-07-15 19:38:20 +0800  16) #ifndef OHOS_ABILITY_RUNTIME_APP_SPAWN_MSG_WRAPPER_H
2f6afc061c (黄师伟        2022-07-15 19:38:20 +0800  17) #define OHOS_ABILITY_RUNTIME_APP_SPAWN_MSG_WRAPPER_H
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  18) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  19) #include <string>
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  20) #include <vector>
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  21) #include <unistd.h>
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  22) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  23) #include "nocopyable.h"
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  24) #include "client_socket.h"
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800  25) #include "shared_package/base_shared_package_info.h"
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  26) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  27) namespace OHOS {
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  28) namespace AppExecFwk {
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800  29) using AppSpawnMsg = AppSpawn::ClientSocket::AppProperty;
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800  30) using HspList = std::vector<BaseSharedPackageInfo>;
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800  31) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  32) struct AppSpawnStartMsg {
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  33)     int32_t uid;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  34)     int32_t gid;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  35)     std::vector<int32_t> gids;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  36)     std::string procName;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  37)     std::string soPath;
04f88e4266 (jerry         2022-01-25 04:44:20 +0000  38)     uint32_t accessTokenId;
04f88e4266 (jerry         2022-01-25 04:44:20 +0000  39)     std::string apl;
4518391eef (jerry         2022-02-11 01:23:40 +0000  40)     std::string bundleName;
f2efb88342 (bigpumpkin    2022-03-04 18:25:21 +0800  41)     std::string renderParam; // only nweb spawn need this param.
a13aa96ccf (jsjzju        2022-04-20 15:47:09 +0800  42)     int32_t pid;
a13aa96ccf (jsjzju        2022-04-20 15:47:09 +0800  43)     int32_t code = 0; // 0: DEFAULT; 1: GET_RENDER_TERMINATION_STATUS
e141ea545f (unknown       2022-04-24 19:57:49 +0800  44)     uint32_t flags;
a7efdcddfa (Zhang Qilong  2022-06-28 15:43:05 +0800  45)     int32_t bundleIndex;   // when dlp launch another app used, default is 0
cd6282495a (maosiping     2022-07-27 11:24:29 +0800  46)     uint8_t setAllowInternet;
c0fbcb72f9 (zhongjianfei  2022-09-24 11:23:40 +0800  47)     uint8_t allowInternet; // hap socket allowed
cd6282495a (maosiping     2022-07-27 11:24:29 +0800  48)     uint8_t reserved1;
cd6282495a (maosiping     2022-07-27 11:24:29 +0800  49)     uint8_t reserved2;
1759915252 (gongyuechen   2022-11-22 03:10:16 +0000  50)     uint64_t accessTokenIdEx;
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800  51)     HspList hspList; // list of harmony shared package
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  52) };
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  53) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  54) constexpr auto LEN_PID = sizeof(pid_t);
e141ea545f (unknown       2022-04-24 19:57:49 +0800  55) struct StartFlags {
999274ae7f (unknown       2022-04-25 15:19:22 +0800  56)     static const int COLD_START = 0;
999274ae7f (unknown       2022-04-25 15:19:22 +0800  57)     static const int BACKUP_EXTENSION = 1;
68b33aa116 (Lin Qiheng    2022-06-28 10:00:56 +0800  58)     static const int DLP_MANAGER = 2;
2af7f4d897 (wangzhen      2023-02-13 07:36:12 +0000  59)     static const int DEBUGGABLE = 3;
e141ea545f (unknown       2022-04-24 19:57:49 +0800  60) };
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  61) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  62) union AppSpawnPidMsg {
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  63)     pid_t pid = 0;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  64)     char pidBuf[LEN_PID];
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  65) };
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  66) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  67) class AppSpawnMsgWrapper {
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  68) public:
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  69)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  70)      * Constructor.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  71)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  72)     AppSpawnMsgWrapper() = default;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  73) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  74)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  75)      * Destructor
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  76)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  77)     ~AppSpawnMsgWrapper();
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  78) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  79)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  80)      * Disable copy.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  81)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  82)     DISALLOW_COPY_AND_MOVE(AppSpawnMsgWrapper);
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  83) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  84)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  85)      * Verify message and assign to member variable.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  86)      *
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  87)      * @param startMsg, request message.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  88)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  89)     bool AssembleMsg(const AppSpawnStartMsg &startMsg);
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  90) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  91)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  92)      * Get function, return isValid_.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  93)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  94)     bool IsValid() const
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  95)     {
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  96)         return isValid_;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  97)     }
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  98) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800  99)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 100)      * Get function, return member variable message.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 101)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 102)     const void *GetMsgBuf() const
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 103)     {
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 104)         return reinterpret_cast<void *>(msg_);
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 105)     }
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 106) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 107)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 108)      * Get function, return message length.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 109)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 110)     int32_t GetMsgLength() const
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 111)     {
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 112)         return isValid_ ? sizeof(AppSpawnMsg) : 0;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 113)     }
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 114) 
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800 115)     /**
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800 116)      * Get function, return hsp list string
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800 117)     */
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800 118)     const std::string& GetHspListStr() const {
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800 119)         return hspListStr;
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800 120)     }
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800 121) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 122) private:
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 123)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 124)      * Verify message.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 125)      *
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 126)      * @param startMsg, request message.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 127)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 128)     bool VerifyMsg(const AppSpawnStartMsg &startMsg) const;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 129) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 130)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 131)      * Print message.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 132)      *
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 133)      * @param startMsg, request message.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 134)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 135)     void DumpMsg() const;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 136) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 137)     /**
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 138)      * Release message.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 139)      */
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 140)     void FreeMsg();
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 141) 
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 142) private:
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 143)     bool isValid_ = false;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 144)     // because AppSpawnMsg's size is uncertain, so should use raw pointer.
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 145)     AppSpawnMsg *msg_ = nullptr;
7dca8e4f0d (yangmingliang 2022-12-15 11:03:43 +0800 146)     std::string hspListStr;
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 147) };
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 148) }  // namespace AppExecFwk
144b31720d (hanhaibin     2022-01-19 16:24:52 +0800 149) }  // namespace OHOS
2f6afc061c (黄师伟        2022-07-15 19:38:20 +0800 150) #endif  // OHOS_ABILITY_RUNTIME_APP_SPAWN_MSG_WRAPPER_H
