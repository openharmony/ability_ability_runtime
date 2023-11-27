/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "app_utils.h"

#include "hilog_wrapper.h"
#include "scene_board_judgement.h"

namespace OHOS {
namespace AAFwk {
const std::string BUNDLE_NAME_LAUNCHER = "com.ohos.launcher";
const std::string BUNDLE_NAME_SCENEBOARD = "com.ohos.sceneboard";

AppUtils::~AppUtils() {}

AppUtils::AppUtils()
{
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        isSceneBoard_ = true;
    }
}

AppUtils &AppUtils::GetInstance()
{
    static AppUtils utils;
    return utils;
}

bool AppUtils::IsLauncher(const std::string &bundleName) const
{
    if (isSceneBoard_) {
        return bundleName == BUNDLE_NAME_SCENEBOARD;
    }

    return bundleName == BUNDLE_NAME_LAUNCHER;
}
}  // namespace AAFwk
}  // namespace OHOS