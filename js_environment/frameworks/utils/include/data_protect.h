/**
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBPANDAFILE_DATA_PROTECT_H
#define LIBPANDAFILE_DATA_PROTECT_H

#include <cstdint>
#include <vector>
#include <string>
#include <string_view>
#include <algorithm>

namespace OHOS {
namespace JsEnv {

class DataProtect {
public:
    DataProtect() : protect_pointer_(0) {}
    explicit DataProtect(const uintptr_t pointer)
    {
        if (pointer == 0) {
            protect_pointer_ = 0;
            return;
        }
        protect_pointer_ = DataProtectPac(pointer, reinterpret_cast<uintptr_t>(&protect_pointer_));
    }

    ~DataProtect() = default;

    static bool CheckPacSupport();

    static inline uintptr_t DataProtectAut(const uintptr_t pointer,
                                           [[maybe_unused]]const uintptr_t address)
    {
#if defined(PANDA_TARGET_ARM64)
        // todo: print t1, t2
        if (!isSupportPacA_) {
            return pointer;
        }
        void *t1 = reinterpret_cast<void*>(pointer);
        void *t2 = reinterpret_cast<void*>(address);
#ifdef PAC_DFI_PTR_BKEY
        __asm__ __volatile__("autdb %0, %1":"+r"(t1):"r"(t2):);
#else
        __asm__ __volatile__("autda %0, %1":"+r"(t1):"r"(t2):);
#endif
        return reinterpret_cast<uintptr_t>(t1);
#else
        return pointer;
#endif
    }

    static inline uintptr_t DataProtectPac(const uintptr_t pointer,
                                           [[maybe_unused]]const uintptr_t address)
    {
#if defined(PANDA_TARGET_ARM64)
        if (!isSupportPacA_) {
            return pointer;
        }
        void *t1 = reinterpret_cast<void*>(pointer);
        void *t2 = reinterpret_cast<void*>(address);
#ifdef PAC_DFI_PTR_BKEY
        __asm__ __volatile__("pacdb %0, %1":"+r"(t1):"r"(t2):);
#else
        __asm__ __volatile__("pacda %0, %1":"+r"(t1):"r"(t2):);
#endif
        return reinterpret_cast<uintptr_t>(t1);
#else
        return pointer;
#endif
    }

    static bool isSupportPacA_;

private:
    void Update(const uintptr_t pointer)
    {
        if (pointer == 0) {
            protect_pointer_ = 0;
            return;
        }
        protect_pointer_ = DataProtectPac(pointer, reinterpret_cast<uintptr_t>(&protect_pointer_));
    }

    uintptr_t GetOriginPointer() const
    {
        if (protect_pointer_ == 0) {
            return protect_pointer_;
        }
        return DataProtectAut(protect_pointer_, reinterpret_cast<uintptr_t>(&protect_pointer_));
    }

    uintptr_t protect_pointer_;
};

class StringPacProtect : public DataProtect {
public:

    enum Shift : uint8_t {
        SHIFT8 = 8,
        SHIFT16 = 16,
        SHIFT24 = 24
    };

    StringPacProtect() : data(std::vector<uintptr_t>()), originLength(0) {}

    explicit StringPacProtect(std::string_view strData)
    {
        Update(strData);
    }

    ~StringPacProtect()
    {
        Clear();
    }

    // replace data by pac(strData)
    void Update(std::string_view strData)
    {
        Clear();
        AppendWithoutCheckBack(strData);
    }

    void Append(char ch)
    {
        constexpr uint32_t step = 4;
        if (originLength % step > 0) {
            // Filling back empty
            uint32_t emptyCount = step - (originLength % step);
            auto lastData = DataProtectAut(data.back(), reinterpret_cast<uintptr_t>(&data));
            data.pop_back();
            uint8_t shift = (SHIFT8 * (emptyCount - 1));
            lastData |= ch << shift;
            data.push_back(DataProtectPac(lastData, reinterpret_cast<uintptr_t>(&data)));
        } else {
            uintptr_t tempData = uintptr_t(ch);
            tempData <<= SHIFT24;
            data.push_back(DataProtectPac(tempData, reinterpret_cast<uintptr_t>(&data)));
        }
        originLength ++;
    }

    // data += pac(strData)
    void Append(std::string_view strData)
    {
        if (strData.empty()) {
            return;
        }
        constexpr uint32_t step = 4;
        
        auto str = reinterpret_cast<const uint8_t *>(strData.data());
        auto len = strData.length();
        if (originLength % step != 0) {
            // Filling back empty
            uint32_t iter = 0;
            uint32_t emptyCount = step - (originLength % step);
            auto lastData = DataProtectAut(data.back(), reinterpret_cast<uintptr_t>(&data));
            data.pop_back();
            
            lastData >>= SHIFT8 * emptyCount;
            while (iter < emptyCount) {
                lastData <<= SHIFT8;
                lastData += (iter < len ? str[iter] : 0);
                iter++;
            }
            data.push_back(DataProtectPac(lastData, reinterpret_cast<uintptr_t>(&data)));
            originLength += (emptyCount < len ? emptyCount : len);
            if (emptyCount < len) {
                AppendWithoutCheckBack(strData.substr(emptyCount));
            }
        } else {
            AppendWithoutCheckBack(strData);
        }
    }

    // return string(aut(data))
    std::string GetOriginString() const
    {
        if (data.empty()) {
            return "";
        }
        std::string res = "";
        
        constexpr uintptr_t mask = (1 << SHIFT8) - 1;
        int32_t iter = data.size() - 1;
        uint32_t dataCount = originLength % 4;
        // need to delete back empty
        if (dataCount != 0) {
            uintptr_t tempData = DataProtectAut(data[iter], reinterpret_cast<uintptr_t>(&data));
            constexpr uint32_t step = 4;
            uint32_t emptyCount = step - dataCount;
            tempData >>= SHIFT8 * emptyCount;
            while (dataCount > 0) {
                res.push_back(char(tempData & mask));
                tempData >>= SHIFT8;
                --dataCount;
            }
            --iter;
        }

        for (; iter >= 0; --iter) {
            uintptr_t tempData = DataProtectAut(data[iter], reinterpret_cast<uintptr_t>(&data));
            res.push_back(char(tempData & mask));
            tempData >>= SHIFT8;
            res.push_back(char(tempData & mask));
            tempData >>= SHIFT8;
            res.push_back(char(tempData & mask));
            tempData >>= SHIFT8;
            res.push_back(char(tempData & mask));
            tempData >>= SHIFT8;
        }
        std::reverse(res.begin(), res.end());
        return res;
    }

    // Compare strData with Paced data, return true if equal
    bool CompareStringWithPacedString(std::string_view strData)
    {
        auto len = strData.length();
        constexpr uint32_t step = 4;
        if (len != originLength) {
            return false;
        }
        auto str = reinterpret_cast<const uint8_t *>(strData.data());
        
        auto dataPtr = data.begin();
        for (uint32_t left = 0; left < len; left += step) {
            uint32_t right = (len > left + step ? left + step : len);
            uintptr_t tempData = 0;

            for (uint32_t iter = left; iter < right; ++iter) {
                tempData += str[iter];
                tempData <<= SHIFT8;
            }
            auto res = DataProtectPac(tempData, reinterpret_cast<uintptr_t>(&data));
            if (res != *dataPtr) {
                return false;
            }
            ++dataPtr;
        }
        return true;
    }

    void Clear()
    {
        std::vector<uintptr_t>().swap(data);
        originLength = 0;
    }

    // PacDataSize = ceil(StrLength / 4)
    uint32_t PacDataSize()
    {
        return data.size();
    }

    // Original String Length Before Pac
    uint32_t StrLength()
    {
        return originLength;
    }

private:

    void AppendWithoutCheckBack(std::string_view strData)
    {
        if (strData.empty()) {
            return;
        }
        auto str = reinterpret_cast<const uint8_t *>(strData.data());
        auto len = strData.length();
        
        constexpr uint32_t step = 4;
        // uint32 = char << 24 | char << 16 | char << 8 | char
        // compress 4 char => 1 uint32 => PAC(uint32) => uintptr_t
        for (uint32_t left = 0; left < len; left += step) {
            uint32_t right = left + step;
            uintptr_t tempData = 0;

            for (uint32_t iter = left; iter < right; ++iter) {
                tempData <<= SHIFT8;
                tempData += (iter < len ? str[iter] : 0);
            }
            data.push_back(DataProtectPac(tempData, reinterpret_cast<uintptr_t>(&data)));
        }
        originLength += strData.length();
    }

    std::vector<uintptr_t>data;
    uint32_t originLength;
};
}
}
#endif  // LIBPANDAFILE_DATA_PROTECT_H
