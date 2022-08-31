/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mix_stack_dumper.h"

#include <dirent.h>
#include <securec.h>
#include <unistd.h>

#include "faultloggerd_client.h"
#include "file_ex.h"
#include "hilog_wrapper.h"
#include "js_runtime.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int FRAME_BUF_LEN = 1024;
constexpr int PATH_MAX_LEN = 4096;
}

static std::string PrintJsFrame(JsFrames& jsFrame)
{
    return "  at " + jsFrame.functionName + " (" + jsFrame.fileName + ":" + jsFrame.pos + ")\n";
}

static std::string PrintNativeFrame(std::shared_ptr<OHOS::HiviewDFX::DfxFrame> frame)
{
    char buf[FRAME_BUF_LEN] = {0};
    std::string mapName = frame->GetFrameMapName();
    if (mapName.empty()) {
        mapName = "Unknown";
    }

#ifdef __LP64__
    char frameFormatWithMapName[] = "#%02zu pc %016" PRIx64 " %s\n";
    char frameFormatWithFuncName[] = "#%02zu pc %016" PRIx64 " %s(%s+%" PRIu64 ")\n";
#else
    char frameFormatWithMapName[] = "#%02zu pc %08" PRIx64 " %s\n";
    char frameFormatWithFuncName[] = "#%02zu pc %08" PRIx64 " %s(%s+%" PRIu64 ")\n";
#endif

    if (frame->GetFrameFuncName().empty()) {
        int ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, frameFormatWithMapName, \
            frame->GetFrameIndex(), frame->GetFrameRelativePc(), mapName.c_str());
        if (ret <= 0) {
            HILOG_ERROR("MainThread::PrintNativeFrame snprintf_s failed.");
        }
        return std::string(buf);
    }

    int ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, frameFormatWithFuncName, \
        frame->GetFrameIndex(), frame->GetFrameRelativePc(), mapName.c_str(),\
        frame->GetFrameFuncName().c_str(), frame->GetFrameFuncOffset());
    if (ret <= 0) {
        HILOG_ERROR("MainThread::PrintNativeFrame snprintf_s failed.");
    }
    return std::string(buf);
}

bool MixStackDumper::IsJsNativePcEqual(uintptr_t *jsNativePointer, uint64_t nativePc, uint64_t nativeOffset)
{
    uint64_t jsPc_ = (uint64_t)jsNativePointer;
    if (nativePc - nativeOffset == jsPc_) {
        return true;
    }
    return false;
}

void MixStackDumper::BuildJsNativeMixStack(int fd, std::vector<JsFrames>& jsFrames,
    std::vector<std::shared_ptr<OHOS::HiviewDFX::DfxFrame>>& nativeFrames)
{
    uint32_t jsIdx = 0;
    uint32_t nativeIdx = 0;
    while (jsIdx < jsFrames.size() && jsFrames[jsIdx].nativePointer == nullptr) {
        HILOG_ERROR("BuildJsNativeMixStack::skip unuseful js frames.");
        jsIdx++;
    }
    while (jsIdx < jsFrames.size() && nativeIdx < nativeFrames.size()) {
        if (jsFrames[jsIdx].nativePointer == nullptr) {
            std::string jsframe = PrintJsFrame(jsFrames[jsIdx]);
            write(fd, jsframe.c_str(), jsframe.size());
            jsIdx++;
            continue;
        }
        if (IsJsNativePcEqual(jsFrames[jsIdx].nativePointer, nativeFrames[nativeIdx]->GetFramePc(),
            nativeFrames[nativeIdx]->GetFrameFuncOffset())) {
            std::string mixframe = PrintNativeFrame(nativeFrames[nativeIdx])+ PrintJsFrame(jsFrames[jsIdx]);
            write(fd, mixframe.c_str(), mixframe.size());
            nativeIdx++;
            jsIdx++;
        } else {
            std::string nativeFrame = PrintNativeFrame(nativeFrames[nativeIdx]);
            write(fd, nativeFrame.c_str(), nativeFrame.size());
            nativeIdx++;
        }
    }
    while (nativeIdx < nativeFrames.size()) {
        std::string nativeFrame = PrintNativeFrame(nativeFrames[nativeIdx]);
        write(fd, nativeFrame.c_str(), nativeFrame.size());
        nativeIdx++;
    }
}

std::string MixStackDumper::GetThreadStackTraceLabel(pid_t tid)
{
    std::ostringstream result;
    result << "Tid:" << tid;
    std::string path = "/proc/self/task/" + std::to_string(tid) + "/comm";
    std::string threadComm;
    if (LoadStringFromFile(path, threadComm)) {
        result << " comm:" << threadComm;
    } else {
        result << std::endl;
    }
    return result.str();
}

void MixStackDumper::DumpMixFrame(std::shared_ptr<OHOSApplication> application, int fd, pid_t tid)
{
    bool onlyDumpNative = false;
    std::vector<JsFrames> jsFrames;
    if (application != nullptr && application->GetRuntime() != nullptr) {
        bool ret = application->GetRuntime()->BuildJsStackInfoList(tid, jsFrames);
        if (!ret || jsFrames.size() == 0) {
            onlyDumpNative = true;
        }
    }
    OHOS::HiviewDFX::DfxDumpCatcher dumplog;
    std::vector<std::shared_ptr<OHOS::HiviewDFX::DfxFrame>> nativeFrames;
    std::string nativeFrameStr;
    if (tid != -1 &&
        dumplog.DumpCatchFrame(getpid(), tid, nativeFrameStr, nativeFrames) == false) {
        HILOG_ERROR("MainThread::DumpMixFrame get process stack info failed.");
    }
    if (onlyDumpNative) {
        write(fd, nativeFrameStr.c_str(), nativeFrameStr.size());
        return;
    }
    std::string jsnativeFrameLabel = GetThreadStackTraceLabel(tid);
    write(fd, jsnativeFrameLabel.c_str(), jsnativeFrameLabel.size());
    BuildJsNativeMixStack(fd, jsFrames, nativeFrames);
    write(fd, "\n", 1);
}

void MixStackDumper::GetThreadList(std::vector<pid_t>& threadList)
{
    char realPath[PATH_MAX_LEN] = {'\0'};
    if (realpath("/proc/self/task", realPath) == nullptr) {
        HILOG_ERROR("MainThread::GetThreadList return false as realpath failed.");
        return;
    }
    DIR *dir = opendir(realPath);
    if (dir == nullptr) {
        HILOG_ERROR("MainThread::GetThreadList return false as opendir failed.");
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        pid_t tid = atoi(ent->d_name);
        if (tid == 0) {
            continue;
        }
        threadList.emplace_back(tid);
    }
    if (closedir(dir) == -1) {
        HILOG_ERROR("GetThreadList::closedir failed.");
    }
}
} // AppExecFwk
} // OHOS
