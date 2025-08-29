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

#ifndef OHOS_ABILITY_RUNTIME_USER_CONTROLLER_H
#define OHOS_ABILITY_RUNTIME_USER_CONTROLLER_H

#include <unordered_map>
#include <unordered_set>

#include "cpp/mutex.h"

namespace OHOS {
namespace AAFwk {
class IUserCallback;
}
namespace AbilityRuntime {
class UserController final {
public:
    UserController& operator=(const UserController&) = delete;
    UserController(const UserController&) = delete;
    virtual ~UserController() = default;
    static UserController& GetInstance();

    int32_t GetForegroundUserId(uint64_t displayId);
    void SetForegroundUserId(int32_t userId, uint64_t displayId);

    bool GetDisplayIdByForegroundUserId(int32_t userId, uint64_t &displayId);

    bool IsForegroundUser(int32_t userId);
    bool IsForegroundUser(int32_t userId, uint64_t displayId);

    void GetAllForegroundUserId(std::vector<int32_t> &userIds);

    void ClearUserId(int32_t userId);

    int32_t GetCallerUserId();

    int32_t GetFreezingNewUserId() const;
    void SetFreezingNewUserId(int32_t userId);

    bool IsExistOsAccount(int32_t userId) const;

    int32_t CheckStopUserParam(int32_t userId) const;
    int32_t CheckUserParam(int32_t userId) const;

private:
    UserController() = default;

    ffrt::mutex userLock_;
    std::unordered_map<uint64_t, int32_t> displayIdMap_;
    ffrt::mutex logoutUserIdLock_;
    std::unordered_set<int32_t> logoutUserIdSet_;
    int32_t freezingNewUserId_ = -1;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_USER_CONTROLLER_H