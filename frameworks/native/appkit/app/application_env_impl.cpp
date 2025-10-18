/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "application_env_impl.h"
#include "application_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace  {
    constexpr int32_t UNSPECIFIED = 0;
    constexpr int32_t TYPE_CREATE_PROCESS = 1;
    constexpr int32_t TYPE_CREATE_ABILITY_STAGE = 2;
}
/**
 * @brief Sets L1 information about the runtime environment of the application to which the
 *        ability belongs, including the bundle name, source code path, and data path.
 * @param appInfo
 * @return void
 */
void ApplicationEnvImpl::SetAppInfo(const AppInfo &appInfo)
{
    bundleName_ = appInfo.bundleName;
    dataPath_ = appInfo.dataPath;
    srcPath_ = appInfo.srcPath;
}

/**
 * @brief Sets information about the runtime environment of the application to which the
 *        ability belongs, including the bundle name, source code path, and data path.
 * @param appInfo indicates
 * @return void
 */
void ApplicationEnvImpl::SetAppInfo(const ApplicationInfo &appInfo, PreloadMode preloadMode)
{
    bundleName_ = appInfo.bundleName;
    dataPath_ = appInfo.dataDir;
    srcPath_ = appInfo.codePath;
    int32_t appPreloadPhase = static_cast<int32_t>(appInfo.appPreloadPhase);
    switch (preloadMode) {
        case PreloadMode::PRESS_DOWN:
        case PreloadMode::PRE_MAKE:
            appPreloadType_ = appPreloadPhase == 0 ? UNSPECIFIED : TYPE_CREATE_PROCESS;
            break;
        case PreloadMode::PRELOAD_MODULE:
            appPreloadType_ = TYPE_CREATE_ABILITY_STAGE;
            break;
        case PreloadMode::PRELOAD_BY_PHASE:
            appPreloadType_ = appPreloadPhase;
            break;
        default:
            appPreloadType_ = UNSPECIFIED;
            break;
    }
}

/**
 * @brief Gets the bundlename of the application's runtime environment
 * @param -
 * @return bundleName
 */
const std::string &ApplicationEnvImpl::GetBundleName() const
{
    return bundleName_;
}

/**
 * @brief Gets the SrcPath of the application's runtime environment
 * @param -
 * @return SrcPath
 */
const std::string &ApplicationEnvImpl::GetSrcPath() const
{
    return srcPath_;
}

/**
 * @brief Gets the DataPath of the application's runtime environment
 * @param -
 * @return DataPath
 */
const std::string &ApplicationEnvImpl::GetDataPath() const
{
    return dataPath_;
}

/**
* @brief Gets the app preload type of the application's runtime environment
* @param -
* @return AppPreloadType
*/
int32_t ApplicationEnvImpl::GetAppPreloadType() const
{
    return appPreloadType_;
}

/**
* @brief Clear the app preload type of the application's runtime environment
* @param -
*/
void ApplicationEnvImpl::ClearAppPreloadType()
{
    appPreloadType_ = 0;
}
}  // namespace AppExecFwk
}  // namespace OHOS
