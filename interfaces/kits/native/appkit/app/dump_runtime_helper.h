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

#ifndef OHOS_ABILITY_RUNTIME_DUMP_RUNTIME_HELPER_H
#define OHOS_ABILITY_RUNTIME_DUMP_RUNTIME_HELPER_H

#include "app_jsheap_mem_info.h"
#include "app_cjheap_mem_info.h"
#include "napi_common_want.h"
#include "ohos_application.h"
#include "runtime.h"

namespace OHOS {
namespace AppExecFwk {
class DumpRuntimeHelper : public std::enable_shared_from_this<DumpRuntimeHelper> {
public:
    explicit DumpRuntimeHelper(const std::shared_ptr<OHOSApplication> &application);
    ~DumpRuntimeHelper() = default;
    void SetAppFreezeFilterCallback();
    void DumpJsHeap(const OHOS::AppExecFwk::JsHeapDumpInfo &info);
    void DumpCjHeap(const OHOS::AppExecFwk::CjHeapDumpInfo &info);
private:
    std::shared_ptr<OHOSApplication> application_ = nullptr;

    static bool Check2DOOMDumpOpt();
    void GetCheckList(const std::unique_ptr<AbilityRuntime::Runtime> &runtime, std::string &checkList);
    void WriteCheckList(const std::string &checkList);
    napi_value GetJsLeakModule(napi_env env, napi_value global);
    napi_value GetMethodCheck(napi_env env, napi_value requireValue, napi_value global);
    static bool Init2DOOMDumpQuota(const std::string &path, uint32_t oomDumpProcessMaxQuota);
    static bool Check2DOOMDumpQuota(uint32_t oomDumpMaxQuota, uint32_t oomDumpProcessMaxQuota);
    static bool Get2DQuota(const std::string &path, const std::string &property, uint64_t &timestamp, int &quota);
    static bool GetQuota(const std::string &path, const std::string &property,
                         std::vector<int64_t> &output, size_t size);
    static bool Set2DQuota(const std::string &path, uint64_t timestamp, int newQuota);
    static uint64_t GetCurrentTimestamp();
    static bool CheckOOMFreeSpace(uint64_t maxSpace);
    static uint64_t GetMaskFromDirXattr(const std::string &path);
    static bool CheckAppListenedEvents(const std::string &path);
    static bool SetDirXattr(const std::string &path, const std::string &name, const std::string &value);
    static bool GetDirXattr(const std::string &path, const std::string &name, std::string &value);
    static bool IsFileExists(const std::string &file);
    static bool ForceCreateDirectory(const std::string &path);
    static bool CreateDir(const std::string &path);
    static void CreateDirDelay(const std::string &path);
    static bool CheckOomdumpSwitch();
    static bool Check2CQuota();
    static bool Check2DQuota(bool needDecreaseQuota);
    static bool SafeStoll(const std::string &str, long long &value);
    static int GetCompressQuota (const std::vector<int64_t> &quotas);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_DUMP_RUNTIME_HELPER_H
