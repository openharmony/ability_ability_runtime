/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_PERMISSION_UTIL_H
#define OHOS_ABILITY_RUNTIME_ABILITY_PERMISSION_UTIL_H

#include <memory>

#include "iremote_object.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
struct RunningProcessInfo;
}
namespace AAFwk {
struct AbilityRequest;

/**
 * @class Want
 * the struct to open abilities.
 */
class Want;

/**
 * @class AbilityPermissionUtil
 * provides ability permission utilities.
 */
class AbilityPermissionUtil {
public:
    /**
     * GetInstance, get an instance of AbilityPermissionUtil.
     *
     * @return An instance of AbilityPermissionUtil.
     */
    static AbilityPermissionUtil &GetInstance();

    /**
     * IsDelegatorCall, check caller is delegator.
     *
     * @param processInfo The process information.
     * @param abilityRequest The ability request.
     * @return Whether the caller is delegator.
     */
    bool IsDelegatorCall(const AppExecFwk::RunningProcessInfo &processInfo, const AbilityRequest &abilityRequest) const;

    /**
     * IsDominateScreen, check dominate screen.
     *
     * @param want The want.
     * @param isPendingWantCaller Flag of whether it is the pending want caller.
     * @return Whether it is dominate screen.
     */
    bool IsDominateScreen(const Want &want, bool isPendingWantCaller);

    /**
     * CheckMultiInstanceAndAppClone, check if the app is either multi-instance or app-clone.
     *
     * @param want The want.
     * @param userId The user id.
     * @param appIndex The app index.
     * @param callerToken The caller token.
     * @return Whether the app is either multi-instance or app-clone.
     */
    int32_t CheckMultiInstanceAndAppClone(Want &want, int32_t userId, int32_t appIndex,
        sptr<IRemoteObject> callerToken);

    /**
     * CheckMultiInstanceKeyForExtension, check multi-instance key for extension.
     *
     * @param abilityRequest The ability request.
     * @return Whether the key is multi-instance key.
     */
    int32_t CheckMultiInstanceKeyForExtension(const AbilityRequest &abilityRequest);

    bool VerifyCallerToken(AbilityRequest &abilityRequest);

private:
    /**
     * AbilityPermissionUtil, the private constructor.
     *
     */
    AbilityPermissionUtil() = default;

    /**
     * AbilityPermissionUtil, the private destructor.
     *
     */
    ~AbilityPermissionUtil() = default;

    /**
     * CheckMultiInstance, check multi-instance.
     *
     * @param want The want.
     * @param callerToken The caller token.
     * @param isCreating Whether the app is being created.
     * @param instanceKey The instance key.
     * @param maxCount The max number of instances.
     * @return Whether it is a valid multi-instance instance.
     */
    int32_t CheckMultiInstance(Want &want, sptr<IRemoteObject> callerToken, bool isCreating,
        const std::string &instanceKey, int32_t maxCount);

    /**
     * UpdateInstanceKey, update instance key.
     *
     * @param want The want.
     * @param originInstanceKey The original instance key.
     * @param instanceKeyArray Candidate instance keys.
     * @param instanceKey The new instance key.
     * @return Whether the update is successful.
     */
    int32_t UpdateInstanceKey(Want &want, const std::string &originInstanceKey,
        const std::vector<std::string> &instanceKeyArray, const std::string &instanceKey);

    DISALLOW_COPY_AND_MOVE(AbilityPermissionUtil);
};
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ABILITY_PERMISSION_UTIL_H