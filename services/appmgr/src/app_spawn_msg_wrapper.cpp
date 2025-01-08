/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "app_spawn_msg_wrapper.h"

#include "securec.h"

#include "hilog_tag_wrapper.h"
#include "nlohmann/json.hpp"
#include "permission_constants.h"
#include "permission_verification.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* HSPLIST_BUNDLES = "bundles";
constexpr const char* HSPLIST_MODULES = "modules";
constexpr const char* HSPLIST_VERSIONS = "versions";
constexpr const char* HSPLIST_SOCKET_TYPE = "|HspList|";
constexpr const char* OVERLAY_SOCKET_TYPE = "|Overlay|";
constexpr const char* DATA_GROUP_SOCKET_TYPE = "|DataGroup|";
constexpr const char* APP_ENV_TYPE = "|AppEnv|";
constexpr const char* DATAGROUPINFOLIST_DATAGROUPID = "dataGroupId";
constexpr const char* DATAGROUPINFOLIST_GID = "gid";
constexpr const char* DATAGROUPINFOLIST_UUID = "uuid";
constexpr const char* DATAGROUPINFOLIST_DIR = "dir";
constexpr const char* JSON_DATA_APP_DIR_EL2 = "/data/app/el2/";
constexpr const char* JSON_DATA_APP_DIR_EL3 = "/data/app/el3/";
constexpr const char* JSON_DATA_APP_DIR_EL4 = "/data/app/el4/";
constexpr const char* JSON_DATA_APP_DIR_EL5 = "/data/app/el5/";
constexpr const char* JSON_GROUP = "/group/";
constexpr const char* VERSION_PREFIX = "v";
}

AppSpawnMsgWrapper::~AppSpawnMsgWrapper()
{
    FreeMsg();
}

static std::string DumpToJson(const HspList &hspList)
{
    nlohmann::json hspListJson;
    for (auto& hsp : hspList) {
        hspListJson[HSPLIST_BUNDLES].emplace_back(hsp.bundleName);
        hspListJson[HSPLIST_MODULES].emplace_back(hsp.moduleName);
        hspListJson[HSPLIST_VERSIONS].emplace_back(VERSION_PREFIX + std::to_string(hsp.versionCode));
    }
    return hspListJson.dump();
}

static std::string DumpToJson(const DataGroupInfoList &dataGroupInfoList)
{
    nlohmann::json dataGroupInfoListJson;
    bool hasScreenLockPermission = AAFwk::PermissionVerification::GetInstance()->VerifyCallingPermission(
        AAFwk::PermissionConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA);
    for (auto& dataGroupInfo : dataGroupInfoList) {
        nlohmann::json dataGroupInfoJson;
        dataGroupInfoJson[DATAGROUPINFOLIST_DATAGROUPID] = dataGroupInfo.dataGroupId;
        dataGroupInfoJson[DATAGROUPINFOLIST_GID] = std::to_string(dataGroupInfo.gid);
        dataGroupInfoJson[DATAGROUPINFOLIST_UUID] = dataGroupInfo.uuid;
        std::string dir = std::to_string(dataGroupInfo.userId) + JSON_GROUP + dataGroupInfo.uuid;
        dataGroupInfoJson[DATAGROUPINFOLIST_DIR] = JSON_DATA_APP_DIR_EL2 + dir;
        dataGroupInfoListJson.emplace_back(dataGroupInfoJson);

        dataGroupInfoJson[DATAGROUPINFOLIST_DIR] = JSON_DATA_APP_DIR_EL3 + dir;
        dataGroupInfoListJson.emplace_back(dataGroupInfoJson);

        dataGroupInfoJson[DATAGROUPINFOLIST_DIR] = JSON_DATA_APP_DIR_EL4 + dir;
        dataGroupInfoListJson.emplace_back(dataGroupInfoJson);
        if (hasScreenLockPermission) {
            dataGroupInfoJson[DATAGROUPINFOLIST_DIR] = JSON_DATA_APP_DIR_EL5 + dir;
            dataGroupInfoListJson.emplace_back(dataGroupInfoJson);
        }
    }
    TAG_LOGD(AAFwkTag::APPMGR, "dataGroupInfoListJson %{public}s", dataGroupInfoListJson.dump().c_str());
    return dataGroupInfoListJson.dump();
}

static std::string DumpAppEnvToJson(const std::map<std::string, std::string> &appEnv)
{
    nlohmann::json appEnvJson;
    for (const auto &[envName, envValue] : appEnv) {
        appEnvJson[envName] = envValue;
    }
    return appEnvJson.dump();
}

bool AppSpawnMsgWrapper::AssembleMsg(const AppSpawnStartMsg &startMsg)
{
    if (!VerifyMsg(startMsg)) {
        return false;
    }
    FreeMsg();
    size_t msgSize = sizeof(AppSpawnMsg) + 1;
    msg_ = static_cast<AppSpawnMsg *>(malloc(msgSize));
    if (msg_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "malloc fail");
        return false;
    }
    if (memset_s(msg_, msgSize, 0, msgSize) != EOK) {
        TAG_LOGE(AAFwkTag::APPMGR, "memset fail");
        return false;
    }
    msg_->code = static_cast<AppSpawn::ClientSocket::AppOperateCode>(startMsg.code);
    if (msg_->code == AppSpawn::ClientSocket::AppOperateCode::DEFAULT ||
        msg_->code == AppSpawn::ClientSocket::AppOperateCode::SPAWN_NATIVE_PROCESS) {
        msg_->uid = startMsg.uid;
        msg_->gid = startMsg.gid;
        msg_->gidCount = startMsg.gids.size() + startMsg.dataGroupInfoList.size();
        msg_->bundleIndex = startMsg.bundleIndex;
        msg_->setAllowInternet = startMsg.setAllowInternet;
        msg_->allowInternet = startMsg.allowInternet;
        msg_->mountPermissionFlags = startMsg.mountPermissionFlags;
        if (strcpy_s(msg_->ownerId, sizeof(msg_->ownerId), startMsg.ownerId.c_str()) != EOK) {
            TAG_LOGE(AAFwkTag::APPMGR, "transform ownerId fail");
            return false;
        }
        for (uint32_t i = 0; i < startMsg.gids.size(); ++i) {
            msg_->gidTable[i] = startMsg.gids[i];
        }
        for (uint32_t i = startMsg.gids.size(); i < msg_->gidCount; ++i) {
            msg_->gidTable[i] = startMsg.dataGroupInfoList[i - startMsg.gids.size()].gid;
        }
        if (strcpy_s(msg_->processName, sizeof(msg_->processName), startMsg.procName.c_str()) != EOK) {
            TAG_LOGE(AAFwkTag::APPMGR, "transform procName fail");
            return false;
        }
        if (strcpy_s(msg_->soPath, sizeof(msg_->soPath), startMsg.soPath.c_str()) != EOK) {
            TAG_LOGE(AAFwkTag::APPMGR, "transform soPath fail");
            return false;
        }
        msg_->accessTokenId = startMsg.accessTokenId;
        if (strcpy_s(msg_->apl, sizeof(msg_->apl), startMsg.apl.c_str()) != EOK) {
            TAG_LOGE(AAFwkTag::APPMGR, "transform apl fail");
            return false;
        }
        if (strcpy_s(msg_->bundleName, sizeof(msg_->bundleName), startMsg.bundleName.c_str()) != EOK) {
            TAG_LOGE(AAFwkTag::APPMGR, "transform bundleName fail");
            return false;
        }

        if (strcpy_s(msg_->renderCmd, sizeof(msg_->renderCmd), startMsg.renderParam.c_str()) != EOK) {
            TAG_LOGE(AAFwkTag::APPMGR, "transform renderCmd fail");
            return false;
        }
        msg_->flags = startMsg.flags;
        msg_->accessTokenIdEx = startMsg.accessTokenIdEx;
        msg_->hapFlags = startMsg.hapFlags;

        BuildExtraInfo(startMsg);
    } else if (msg_->code == AppSpawn::ClientSocket::AppOperateCode::GET_RENDER_TERMINATION_STATUS) {
        msg_->pid = startMsg.pid;
    } else {
        TAG_LOGE(AAFwkTag::APPMGR, "invalid code");
        return false;
    }

    isValid_ = true;
    DumpMsg();
    return isValid_;
}

void AppSpawnMsgWrapper::BuildExtraInfo(const AppSpawnStartMsg &startMsg)
{
    if (!startMsg.hspList.empty()) {
        extraInfoStr_ += HSPLIST_SOCKET_TYPE + DumpToJson(startMsg.hspList) +
                                HSPLIST_SOCKET_TYPE;
    }

    if (!startMsg.dataGroupInfoList.empty()) {
        extraInfoStr_ += DATA_GROUP_SOCKET_TYPE + DumpToJson(startMsg.dataGroupInfoList) +
                                DATA_GROUP_SOCKET_TYPE;
    }

    if (!startMsg.overlayInfo.empty()) {
        extraInfoStr_ += OVERLAY_SOCKET_TYPE + startMsg.overlayInfo +
                                OVERLAY_SOCKET_TYPE;
    }

    if (!startMsg.appEnv.empty()) {
        auto appEnvStr = DumpAppEnvToJson(startMsg.appEnv);
        TAG_LOGD(AAFwkTag::APPMGR, "AppEnv: %{public}s", appEnvStr.c_str());
        extraInfoStr_ += APP_ENV_TYPE + appEnvStr + APP_ENV_TYPE;
    }

    if (!extraInfoStr_.empty()) {
        msg_->extraInfo.totalLength = extraInfoStr_.size() + 1;
    }
}

bool AppSpawnMsgWrapper::VerifyMsg(const AppSpawnStartMsg &startMsg) const
{
    if (startMsg.code == AppSpawn::ClientSocket::AppOperateCode::DEFAULT ||
        startMsg.code == AppSpawn::ClientSocket::AppOperateCode::SPAWN_NATIVE_PROCESS) {
        if (startMsg.uid < 0) {
            TAG_LOGE(AAFwkTag::APPMGR, "invalid uid! [%{public}d]", startMsg.uid);
            return false;
        }

        if (startMsg.gid < 0) {
            TAG_LOGE(AAFwkTag::APPMGR, "invalid gid! [%{public}d]", startMsg.gid);
            return false;
        }

        if (startMsg.gids.size() > AppSpawn::ClientSocket::MAX_GIDS) {
            TAG_LOGE(AAFwkTag::APPMGR, "many app gids");
            return false;
        }

        for (uint32_t i = 0; i < startMsg.gids.size(); ++i) {
            if (startMsg.gids[i] < 0) {
                TAG_LOGE(AAFwkTag::APPMGR, "invalid gids array! [%{public}d]", startMsg.gids[i]);
                return false;
            }
        }

        if (startMsg.procName.empty() || startMsg.procName.size() >= AppSpawn::ClientSocket::LEN_PROC_NAME) {
            TAG_LOGE(AAFwkTag::APPMGR, "invalid procName");
            return false;
        }
    } else if (startMsg.code == AppSpawn::ClientSocket::AppOperateCode::GET_RENDER_TERMINATION_STATUS) {
        if (startMsg.pid < 0) {
            TAG_LOGE(AAFwkTag::APPMGR, "invalid pid");
            return false;
        }
    } else {
        TAG_LOGE(AAFwkTag::APPMGR, "invalid code");
        return false;
    }

    return true;
}

void AppSpawnMsgWrapper::DumpMsg() const
{
    if (!isValid_) {
        return;
    }
    std::string accessTokenIdExString = std::to_string(msg_->accessTokenIdEx);
    TAG_LOGD(AAFwkTag::APPMGR, "uid: %{public}d, gid: %{public}d, procName: %{public}s, accessTokenIdEx :%{public}s",
        msg_->uid, msg_->gid, msg_->processName, accessTokenIdExString.c_str());
}

void AppSpawnMsgWrapper::FreeMsg()
{
    if (msg_ != nullptr) {
        free(msg_);
        msg_ = nullptr;
        isValid_ = false;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
