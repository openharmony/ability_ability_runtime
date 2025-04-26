/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "remote_client_manager.h"

#include "iservice_registry.h"
#include "singleton.h"
#include "system_ability_definition.h"
#include "mock_my_status.h"
 
namespace OHOS {
namespace AppExecFwk {
RemoteClientManager::RemoteClientManager()
    : appSpawnClient_(std::make_shared<AppSpawnClient>()),
    nwebSpawnClient_(std::make_shared<AppSpawnClient>(true)),
    cjAppSpawnClient_(std::make_shared<AppSpawnClient>("cjappspawn")),
    nativeSpawnClient_(std::make_shared<AppSpawnClient>("nativespawn"))
{}

RemoteClientManager::~RemoteClientManager()
{}

std::shared_ptr<AppSpawnClient> RemoteClientManager::GetSpawnClient()
{
    return nullptr;
}

void RemoteClientManager::SetSpawnClient(const std::shared_ptr<AppSpawnClient> &appSpawnClient)
{
}
 
std::shared_ptr<BundleMgrHelper> RemoteClientManager::GetBundleManagerHelper()
{
    return AAFwk::MyStatus::GetInstance().getBundleManagerHelper_;
}
 
void RemoteClientManager::SetBundleManagerHelper(const std::shared_ptr<BundleMgrHelper> &bundleMgrHelper)
{
}

std::shared_ptr<AppSpawnClient> RemoteClientManager::GetNWebSpawnClient()
{
    return nullptr;
}
 
std::shared_ptr<AppSpawnClient> RemoteClientManager::GetCJSpawnClient()
{
    return nullptr;
}

std::shared_ptr<AppSpawnClient> RemoteClientManager::GetNativeSpawnClient()
{
    return nullptr;
}
}  // namespace AppExecFwk
}  // namespace OHOS
 