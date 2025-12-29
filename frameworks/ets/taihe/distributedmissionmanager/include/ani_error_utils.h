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
#ifndef OHOS_ANI_ERROR_UTILS_H
#define OHOS_ANI_ERROR_UTILS_H
#include <string>
#include "hilog_tag_wrapper.h"

namespace ani_errorutils {

void ThrowError(const char* message);
void ThrowError(int32_t code, const char* message);
ani_ref ToBusinessError(ani_env *env, int32_t code, const std::string &message);

int32_t ErrorCodeReturn(int32_t code);
std::string ErrorMessageReturn(int32_t code);
bool AniPromiseCallback(ani_env* env, ani_resolver deferred, int32_t result, ani_ref resolveResult = nullptr);

#define CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...)           \
    do {                                                        \
        if (!(cond)) {                                          \
            TAG_LOGE(AAFwkTag::MISSION, fmt, ##__VA_ARGS__);    \
            return ret;                                         \
        }                                                       \
    } while (0)

}  // namespace ani_errorutils

namespace OHOS {
namespace AAFwk {

enum ErrorCode {
    NO_ERROR = 0,
    INVALID_PARAMETER = -1,
    REMOTE_MISSION_NOT_FOUND = -2,
    PERMISSION_DENY = -3,
    REGISTRATION_NOT_FOUND = -4,
    /**
     * Result(201) for permission denied.
     */
    PERMISSION_DENIED = 201,
    /**
     * Result(202) for non-system-app use system-api.
     */
    NOT_SYSTEM_APP = 202,
    /**
     * Result(401) for parameter check failed.
     */
    PARAMETER_CHECK_FAILED = 401,
    /**
     * Result(16300501) for the system ability work abnormally.
     */
    SYSTEM_WORK_ABNORMALLY = 16300501,
    /**
     * Result(29360221) for failed to get the missionInfo of the specified missionId.
     */
    NO_MISSION_INFO_FOR_MISSION_ID = 29360221,
    /**
     * Result(16300503) for the application is not installed on the remote end and installation-free is
     * not supported.
     */
    REMOTE_UNINSTALLED_AND_UNSUPPORT_FREEINSTALL_FOR_CONTINUE = 16300503,
    /**
     * Result(16300504) for the application is not installed on the remote end but installation-free is
     * supported, try again with freeInstall flag.
     */
    CONTINUE_WITHOUT_FREEINSTALL_FLAG = 16300504,
    /**
     * Result(16300506) throw to js for the local continuation task is already in progress.
     */
    ERR_CONTINUE_ALREADY_IN_PROGRESS = 16300506,
    /**
     * Result(16300507) throw to js for Failed to get the missionInfo of the specified bundle name.
     */
    ERR_GET_MISSION_INFO_OF_BUNDLE_NAME = 16300507,
    /**
     * Result(16300508) throw to js for bind error due to the remote device hotspot enable, try again after disable
     * the remote device hotspot.
     */
    ERR_BIND_REMOTE_HOTSPOT_ENABLE_STATE = 16300508,
    /**
     * Result(16300509) throw to js for the remote device has been linked with other devices, try again when
     * the remote device is idle.
     */
    ERR_BIND_REMOTE_IN_BUSY_LINK = 16300509,
    /**
     * Result(29360222) for the operation device must be the device where the application to be continued
     * is located or the target device to be continued.
     */
    OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET = 29360222,
    /**
     * Result(29360223) for the local continuation task is already in progress.
     */
    CONTINUE_ALREADY_IN_PROGRESS = 29360223,
    /**
     * Result(29360224) for the mission is dead, try again after restart mission.
     */
    MISSION_FOR_CONTINUING_IS_NOT_ALIVE = 29360224,
    /*
     * Result(29360144) for get local deviceId fail.
     */
    GET_LOCAL_DEVICE_ERR = 29360144,
    /**
     * Result(29360174) for get remote dms fail.
     */
    GET_REMOTE_DMS_FAIL = 29360174,
    /*
     * Result(29360202) for continue remote not install and support free install.
     */
    CONTINUE_REMOTE_UNINSTALLED_SUPPORT_FREEINSTALL = 29360202,
    /*
     * Result(29360203) for continue remote not install and not support free install.
     */
    CONTINUE_REMOTE_UNINSTALLED_UNSUPPORT_FREEINSTALL = 29360203,
};
}
}
#endif  // OHOS_ANI_ERROR_UTILS_H
