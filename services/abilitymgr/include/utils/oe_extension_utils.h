/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_OE_EXTENSION_UTILS_H
#define OHOS_ABILITY_RUNTIME_OE_EXTENSION_UTILS_H

#include <mutex>
#include <unordered_set>

#include "ability_info.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {

/**
 * @class OEExtensionUtils
 * Provides utilities for OE (Open Ecosystem) extension operations.
 */
class OEExtensionUtils {
public:
    /**
     * GetInstance, get an instance of OEExtensionUtils.
     *
     * @return An instance of OEExtensionUtils.
     */
    static OEExtensionUtils &GetInstance();

    /**
     * ValidateCaller, validate OE extension caller's legitimacy.
     *
     * @param callingUid The calling UID.
     * @param want The want of target ability.
     * @param callerToken The caller token.
     * @param hostPid The host process ID.
     * @param hostBundleName [out] Returns host bundle name.
     * @return Returns ERR_OK on success, error code on failure.
     */
    int32_t ValidateCaller(
        int32_t callingUid,
        const Want &want,
        const sptr<IRemoteObject> &callerToken,
        int32_t hostPid,
        std::string &hostBundleName,
        int32_t &userId);

    /**
     * AddOEExtRequest, add an OE extension request to tracking set.
     *
     * @param requestId The request ID to track.
     */
    void AddOEExtRequest(int32_t requestId);

    /**
     * RemoveOEExtRequest, check and remove if it's an OE extension request.
     *
     * @param requestId The request ID to check and remove.
     * @return Returns true if it was an OE extension request.
     */
    bool RemoveOEExtRequest(int32_t requestId);
private:
    /**
     * ScheduleDelayedCleanup, schedule delayed cleanup for a request ID.
     *
     * @param requestId The request ID to clean up after delay.
     */
    void ScheduleDelayedCleanup(int32_t requestId);

    OEExtensionUtils() = default;
    ~OEExtensionUtils() = default;

    DISALLOW_COPY_AND_MOVE(OEExtensionUtils);

    std::unordered_set<int32_t> oeExtRequests_;
    mutable std::mutex oeExtRequestsMutex_;
};

} // namespace AAFwk
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_OE_EXTENSION_UTILS_H
