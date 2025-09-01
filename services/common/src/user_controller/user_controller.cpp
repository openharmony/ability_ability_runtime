/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "user_controller.h"

#include <mutex>

#include "ability_manager_errors.h"
#include "display_util.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "os_account_manager_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t BASE_USER_RANGE = 200000;
constexpr int32_t U0_USER_ID = 0;
constexpr int32_t U1_USER_ID = 1;
constexpr int32_t USER_ID_DEFAULT = 100;
constexpr int32_t ACCOUNT_MGR_SERVICE_UID = 3058;
}
UserController& UserController::GetInstance()
{
    static UserController instance;
    return instance;
}

void UserController::ClearUserId(int32_t userId)
{
    std::lock_guard<ffrt::mutex> guard(userLock_);
    for (auto iter = displayIdMap_.begin(); iter != displayIdMap_.end(); iter++) {
        if (iter->second == userId) {
            displayIdMap_.erase(iter);
            break;
        }
    }
}

int32_t UserController::GetForegroundUserId(uint64_t displayId)
{
    std::lock_guard<ffrt::mutex> guard(userLock_);
    auto iter = displayIdMap_.find(displayId);
    if (iter != displayIdMap_.end()) {
        return iter->second;
    }
    return 0;
}

bool UserController::GetDisplayIdByForegroundUserId(int32_t userId, uint64_t &displayId)
{
    std::lock_guard<ffrt::mutex> guard(userLock_);
    for (auto &item : displayIdMap_) {
        if (item.second == userId) {
            displayId = item.first;
            return true;
        }
    }
    return false;
}

bool UserController::IsForegroundUser(int32_t userId)
{
    std::lock_guard<ffrt::mutex> guard(userLock_);
    for (auto &item : displayIdMap_) {
        if (item.second == userId) {
            return true;
        }
    }
    return false;
}

bool UserController::IsForegroundUser(int32_t userId, uint64_t displayId)
{
    int32_t foregroundUserId = GetForegroundUserId(displayId);
    if (foregroundUserId == userId) {
        return true;
    }
    TAG_LOGI(AAFwkTag::USER_CONTROLLER, "foregroundUserId:%{public}d", foregroundUserId);
    return false;
}

void UserController::SetForegroundUserId(int32_t userId, uint64_t displayId)
{
    std::lock_guard<ffrt::mutex> guard(userLock_);
    displayIdMap_[displayId] = userId;
}

void UserController::GetAllForegroundUserId(std::vector<int32_t> &userIds)
{
    std::lock_guard<ffrt::mutex> guard(userLock_);
    for (auto &item : displayIdMap_) {
        userIds.push_back(item.second);
    }
}

int32_t UserController::GetCallerUserId()
{
    int32_t callerUid = IPCSkeleton::GetCallingUid();
    int32_t callerUser = callerUid / BASE_USER_RANGE;
    TAG_LOGD(AAFwkTag::USER_CONTROLLER, "callerUser = %{public}d, CallingUid = %{public}d.", callerUser, callerUid);
    if (callerUser == U0_USER_ID || callerUser == U1_USER_ID) {
        callerUser = GetForegroundUserId(AAFwk::DisplayUtil::ObtainDefaultDisplayId());
    }
    return callerUser;
}

int32_t UserController::GetFreezingNewUserId() const
{
    return freezingNewUserId_;
}

void UserController::SetFreezingNewUserId(int32_t userId)
{
    freezingNewUserId_ = userId;
}

bool UserController::IsExistOsAccount(int32_t userId) const
{
    bool isExist = false;
    auto errCode = DelayedSingleton<AppExecFwk::OsAccountManagerWrapper>::GetInstance()->IsOsAccountExists(userId,
        isExist);
    return (errCode == 0) && isExist;
}

int32_t UserController::CheckStopUserParam(int32_t userId) const
{
    if (userId == USER_ID_DEFAULT) {
        TAG_LOGE(AAFwkTag::USER_CONTROLLER, "stopUser invalid:%{public}d", userId);
        return AAFwk::INVALID_USERID_VALUE;
    }
    return CheckUserParam(userId);
}

int32_t UserController::CheckUserParam(int32_t userId) const
{
    if (userId <= U0_USER_ID) {
        TAG_LOGE(AAFwkTag::USER_CONTROLLER, "userId invalid:%{public}d", userId);
        return AAFwk::INVALID_USERID_VALUE;
    }

    if (IPCSkeleton::GetCallingUid() != ACCOUNT_MGR_SERVICE_UID) {
        TAG_LOGE(AAFwkTag::USER_CONTROLLER, "permission verification failed, not account process");
        return AAFwk::CHECK_PERMISSION_FAILED;
    }

    if (!IsExistOsAccount(userId)) {
        TAG_LOGE(AAFwkTag::USER_CONTROLLER, "userId not exist");
        return AAFwk::INVALID_USERID_VALUE;
    }
    return ERR_OK;
}
}
}