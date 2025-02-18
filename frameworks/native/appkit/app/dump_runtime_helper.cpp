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

#include "dump_runtime_helper.h"

#include "app_mgr_client.h"
#include "faultloggerd_client.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "singleton.h"
#include "dfx_jsnapi.h"
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
const char *MODULE_NAME = "hiviewdfx.jsLeakWatcher";
const char *CHECK = "check";
const char *REQUIRE_NAPI = "requireNapi";

static bool g_betaVersion = OHOS::system::GetParameter("const.logsystem.versiontype", "unknown") == "beta";
static bool g_developMode = (OHOS::system::GetParameter("persist.hiview.leak_detector", "unknown") == "enable") ||
                            (OHOS::system::GetParameter("persist.hiview.leak_detector", "unknown") == "true");
static int g_oomDumpProcessQuota = 0;
static uint64_t g_lastOOMDumpTime = 0;
static constexpr const char* const EVENT_XATTR_NAME = "user.appevent";
static constexpr const char* const OOM_QUOTA_XATTR_NAME = "user.oomdump.quota";
static constexpr const char* const HIAPPEVENT_PATH = "/data/storage/el2/base/cache/hiappevent";
static constexpr const char* const OOM_QUOTA_PATH = "/data/storage/el2/base/cache/rawheap";
static constexpr uint64_t OOM_DUMP_INTERVAL = 7 * 24 * 60 * 60;
static constexpr uint64_t OOM_DUMP_SPACE_LIMIT = 30ull * 1024 * 1024 * 1024;
static constexpr uint32_t EVENT_RESOURCE_OVERLIMIT_MASK = 6;
static constexpr uint64_t BIT_MASK = 1;
static constexpr uint32_t BUF_SIZE_256 = 256;

DumpRuntimeHelper::DumpRuntimeHelper(const std::shared_ptr<OHOSApplication> &application)
    : application_(application)
{}

bool DumpRuntimeHelper::CheckOOMDumpOpt()
{
    char* env = getenv("DFX_RESOURCE_OVERLIMIT_OPTIONS");
    if (env == nullptr) {
        return false;
    }
    return strstr(env, "oomdump:enable") != nullptr;
}

void DumpRuntimeHelper::SetAppFreezeFilterCallback()
{
    if (application_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null application");
        return;
    }
    auto& runtime = application_->GetRuntime();
    if (runtime == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null runtime");
        return;
    }
    auto appfreezeFilterCallback = [this] (const int32_t pid) -> bool {
        if (OHOS::system::GetParameter("hiview.oomdump.switch"), "unknown") == "disable" {
            TAG_LOGi(AAFwkTag::APPKIT, "oom dump is disabled");
            return false;
        }
        auto client = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
        if (client == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null client");
            return false;
        }
        if (!g_betaVersion && !g_developMode) {
            if (!CheckOOMDumpOpt()) {
                TAG_LOGI(AAFwkTag::APPKIT, "CheckOOMDumpOpt failed");
                return false;
            }
            uint32_t oomDumpMaxQuota = OHOS::system::GetIntParameter("persist.hiview.oomdump.maxcount", 0);
            uint32_t oomDumpProcessMaxQuota =
                OHOS::system::GetIntParameter("persist.hiview.oomdump.process.maxcount", 0);
            if (!InitOOMDumpQuota(OOM_QUOTA_PATH, oomDumpProcessMaxQuota)) {
                return false;
            }
            if (!CheckOOMDumpQuota(oomDumpMaxQuota, oomDumpProcessMaxQuota)) {
                return false;
            }
            SetQuota(OOM_QUOTA_PATH, GetCurrentTimestamp(), g_oomDumpProcessQuota - 1);
        }
        client->SetAppFreezeFilter(pid);
        return true;
    };
    auto vm = (static_cast<AbilityRuntime::JsRuntime&>(*runtime)).GetEcmaVm();
    panda::DFXJSNApi::SetAppFreezeFilterCallback(vm, appfreezeFilterCallback);
}

void DumpRuntimeHelper::DumpJsHeap(const OHOS::AppExecFwk::JsHeapDumpInfo &info)
{
    if (application_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null application");
        return;
    }
    auto& runtime = application_->GetRuntime();
    if (runtime == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null runtime");
        return;
    }
    if (info.needLeakobj) {
        std::string checkList = "";
        GetCheckList(runtime, checkList);
        WriteCheckList(checkList);
    }

    if (info.needSnapshot == true) {
        runtime->DumpHeapSnapshot(info.tid, info.needGc);
    } else {
        if (info.needGc == true) {
            runtime->ForceFullGC(info.tid);
        }
    }
}

void DumpRuntimeHelper::GetCheckList(const std::unique_ptr<AbilityRuntime::Runtime> &runtime, std::string &checkList)
{
    if (runtime->GetLanguage() != AbilityRuntime::Runtime::Language::JS) {
        TAG_LOGE(AAFwkTag::APPKIT, "current language not js");
        return;
    }
    AbilityRuntime::JsRuntime &jsruntime = static_cast<AbilityRuntime::JsRuntime&>(*runtime);
    AbilityRuntime::HandleScope handleScope(jsruntime);
    auto env = jsruntime.GetNapiEnv();

    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_value requireValue = GetJsLeakModule(env, global);
    if (requireValue == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null requireValue");
        return;
    }
    napi_value result = GetMethodCheck(env, requireValue, global);
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null result");
        return;
    }

    size_t checkListSize = 0;
    napi_get_value_string_utf8(env, result, nullptr, 0, &checkListSize);
    checkList.resize(checkListSize + 1);
    napi_get_value_string_utf8(env, result, &checkList[0], checkListSize + 1, &checkListSize);
}

napi_value DumpRuntimeHelper::GetJsLeakModule(napi_env env, napi_value global)
{
    napi_value napiFunc = nullptr;
    napi_status status = napi_get_named_property(env, global, REQUIRE_NAPI, &napiFunc);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail, %{public}d", status);
        return nullptr;
    }
    napi_value moduleName = nullptr;
    napi_create_string_utf8(env, MODULE_NAME, strlen(MODULE_NAME), &moduleName);
    napi_value param[1] = {moduleName};
    napi_value requireValue = nullptr;
    status = napi_call_function(env, global, napiFunc, 1, &param[0], &requireValue);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail, %{public}d", status);
        return nullptr;
    }
    return requireValue;
}

napi_value DumpRuntimeHelper::GetMethodCheck(napi_env env, napi_value requireValue, napi_value global)
{
    napi_value methodCheck = nullptr;
    napi_status status = napi_get_named_property(env, requireValue, CHECK, &methodCheck);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail, %{public}d", status);
        return nullptr;
    }
    napi_valuetype valuetype = napi_undefined;
    status = napi_typeof(env, methodCheck, &valuetype);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed, %{public}d", status);
        return nullptr;
    }
    napi_value result = nullptr;
    status = napi_call_function(env, global, methodCheck, 0, nullptr, &result);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail, %{public}d", status);
        return nullptr;
    }
    return result;
}

void DumpRuntimeHelper::WriteCheckList(const std::string &checkList)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    int32_t fd = RequestFileDescriptor(static_cast<int32_t>(FaultLoggerType::JS_HEAP_LEAK_LIST));
    if (fd < 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "fd:%{public}d.\n", fd);
        return;
    }
    if (write(fd, checkList.c_str(), strlen(checkList.c_str())) == -1) {
        TAG_LOGE(AAFwkTag::APPKIT, "fd:%{public}d, errno:%{public}d.\n", fd, errno);
        close(fd);
        return;
    }
    close(fd);
}

bool DumpRuntimeHelper::InitOOMDumpQuota(const std::string &path, uint32_t oomDumpProcessMaxQuota)
{
    if (IsFileExists(path)) {
        TAG_LOGI(AAFwkTag::APPKIT, "File existed. dir=%{public}s", path.c_str());
        return true;
    }
    if (!ForceCreateDirectory(path)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Failed to create dir=%{public}s", path.c_str());
        return false;
    }
    uint64_t currentTime = GetCurrentTimestamp();
    if (!SetQuota(path, currentTime, oomDumpProcessMaxQuota)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Failed to init quota.");
        return false;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Init dumpTime=%{public}llu, quota=%{public}d.",
        currentTime, oomDumpProcessMaxQuota);
    return true;
}

bool DumpRuntimeHelper::CheckOOMDumpQuota(uint32_t oomDumpMaxQuota, uint32_t oomDumpProcessMaxQuota)
{
    if (!CheckAppListenedEvents(HIAPPEVENT_PATH)) {
        TAG_LOGI(AAFwkTag::APPKIT, "Not subscribe oom event.");
        return false;
    }
    if (oomDumpMaxQuota <= 0) {
        TAG_LOGI(AAFwkTag::APPKIT, "The whole machine quota has been exhausted, quota=%{public}u", oomDumpMaxQuota);
        return false;
    }
    if (!CheckOOMFreeSpace()) {
        TAG_LOGI(AAFwkTag::APPKIT, "Device space is not enough.");
        return false;
    }
    uint64_t currentTime = GetCurrentTimestamp();
    if (!GetQuota(OOM_QUOTA_PATH, g_lastOOMDumpTime, g_oomDumpProcessQuota)) {
        TAG_LOGE(AAFwkTag::APPKIT, "CheckOOMDumpQuota failed to get quota.");
        return false;
    }
    if (currentTime - g_lastOOMDumpTime <= OOM_DUMP_INTERVAL) {
        if (g_oomDumpProcessQuota <= 0) {
            TAG_LOGI(AAFwkTag::APPKIT, "Weekly quota has been exhausted, quota=%{public}d", g_oomDumpProcessQuota);
            return false;
        }
    } else {
        TAG_LOGI(AAFwkTag::APPKIT, "Over one week, reset process quota=%{public}u", oomDumpProcessMaxQuota);
        g_oomDumpProcessQuota = static_cast<int>(oomDumpProcessMaxQuota);
        if (!SetQuota(OOM_QUOTA_PATH, currentTime, oomDumpProcessMaxQuota)) {
            TAG_LOGE(AAFwkTag::APPKIT, "Failed to reset quota.");
            return false;
        }
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Last oom time=%{public}llu, currentTime=%{public}llu, quota=%{public}d",
        g_lastOOMDumpTime, currentTime, g_oomDumpProcessQuota);
    return true;
}

bool DumpRuntimeHelper::GetQuota(const std::string &path, uint64_t &timestamp, int &quota)
{
    std::string value;
    if (!GetDirXattr(path, OOM_QUOTA_XATTR_NAME, value)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Failed to get xattr.");
        return false;
    }
    std::istringstream ss(value);
    char delimiter;
    if (!(ss >> timestamp >> delimiter >> quota) || delimiter != ',') {
        return false;
    }
    return true;
}

bool DumpRuntimeHelper::SetQuota(const std::string &path, uint64_t timestamp, int newQuota)
{
    std::ostringstream value;
    value << timestamp << "," << newQuota;
    if (newQuota < 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "Invalid quota.");
        return false;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "Set quota=%{public}d", newQuota);
    return SetDirXattr(path, OOM_QUOTA_XATTR_NAME, value.str());
}

uint64_t DumpRuntimeHelper::GetCurrentTimestamp()
{
    return static_cast<int64_t>(time(nullptr));
}

bool DumpRuntimeHelper::CheckOOMFreeSpace()
{
    struct statvfs st;
    if (statvfs("/data/storage/el2/base/", &st) != 0) {
        return false;
    }

    uint64_t freeSize = st.f_bsize * st.f_bfree;
    TAG_LOGI(AAFwkTag::APPKIT, "FreeSize=%{public}llu", freeSize);
    if (freeSize <= OOM_DUMP_SPACE_LIMIT) {
        return false;
    }
    return true;
}

uint64_t DumpRuntimeHelper::GetMaskFromDirXattr(const std::string &path)
{
    std::string value;
    if (!GetDirXattr(path, EVENT_XATTR_NAME, value)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Failed to get subscirbe xattr.");
        return 0;
    }
    return static_cast<uint64_t>(std::strtoull(value.c_str(), nullptr, 0));
}

bool DumpRuntimeHelper::CheckAppListenedEvents(const std::string &path)
{
    uint64_t eventsMask = GetMaskFromDirXattr(path);
    if (eventsMask == 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "Failed to get events mask for path:%{public}s", path.c_str());
        return false;
    }
    if (!(eventsMask & (BIT_MASK << EVENT_RESOURCE_OVERLIMIT_MASK))) {
        TAG_LOGI(AAFwkTag::APPKIT, "Unlistened event for path:%{public}s", path.c_str());
        return false;
    }
    return true;
}

bool DumpRuntimeHelper::IsFileExists(const std::string &file)
{
    return access(file.c_str(), F_OK) == 0;
}

bool DumpRuntimeHelper::ForceCreateDirectory(const std::string &path)
{
    std::string::size_type index = 0;
    do {
        std::string subPath;
        index = path.find('/', index + 1); // (index + 1) means the next char traversed
        if (index == std::string::npos) {
            subPath = path;
        } else {
            subPath = path.substr(0, index);
        }

        if (!IsFileExists(subPath) && mkdir(subPath.c_str(), S_IRWXU) != 0) {
            return false;
        }
    } while (index != std::string::npos);
    return IsFileExists(path);
}

bool DumpRuntimeHelper::SetDirXattr(const std::string &path, const std::string &name, const std::string &value)
{
    return setxattr(path.c_str(), name.c_str(), value.c_str(), strlen(value.c_str()), 0) == 0;
}

bool DumpRuntimeHelper::GetDirXattr(const std::string &path, const std::string &name, std::string &value)
{
    char buf[BUF_SIZE_256] = {0};
    if (getxattr(path.c_str(), name.c_str(), buf, sizeof(buf) - 1) == -1) {
        return false;
    }
    value = buf;
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
