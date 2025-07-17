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

#ifndef OHOS_MOCK_UTIL_H
#define OHOS_MOCK_UTIL_H

#include <any>
#include <map>
#include <string>
#include <type_traits>
#include <vector>
#include "hilog_tag_wrapper.h"

// inner utils class, you should not use this.
class ResultWrap {
public:
    ResultWrap(std::any result)
    {
        result_ = result;
    }

    ResultWrap() {}

    template <typename T>
    T Get() const
    {
        return std::any_cast<T>(result_);
    }
private:
    std::any result_;
};

// donnot use or change this map.
inline thread_local std::map<std::string, std::vector<ResultWrap>> g_mockMap;
inline thread_local std::map<std::string, std::vector<std::vector<ResultWrap>>> g_RefMap;

/**
 * @brief Mock a member function.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string, if you need mock a function with sptr, use
 *            OH_MOCK_METHOD_RET_SPTR instead.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD(ret, className, funcName, ...)                              \
ret funcName(__VA_ARGS__)                                                          \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> expectRets;                                        \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    ret temp;                                                                      \
    ResultWrap tempRet(temp);                                                      \
    auto it = g_mockMap.find(key);                                                 \
    if (it != g_mockMap.end()) {                                                   \
        std::vector<ResultWrap> expectRets = it->second;                           \
        if (!expectRets.empty()) {                                                 \
            tempRet = expectRets[0];                                               \
            expectRets.erase(expectRets.begin());                                  \
        }                                                                          \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a member function with output params.
 *        This macro function while create a definition of a function that expected to be mocked.
 *        The output params must be the last params.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string, if you need mock a function with sptr, use
 *            OH_MOCK_METHOD_RET_SPTR instead.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD_WITH_OUTPUT_1(ret, oPName, className, funcName, ...)        \
ret funcName(__VA_ARGS__)                                                          \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> expectRets;                                        \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    ret temp;                                                                      \
    ResultWrap tempRet(temp);                                                      \
    auto it = g_mockMap.find(key);                                                 \
    if (it != g_mockMap.end()) {                                                   \
        std::vector<ResultWrap> expectRets = it->second;                           \
        if (!expectRets.empty()) {                                                 \
            tempRet = expectRets[0];                                               \
            expectRets.erase(expectRets.begin());                                  \
        }                                                                          \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    if (g_RefMap.find(key) == g_RefMap.end()) {                                    \
        std::vector<std::vector<ResultWrap>> expectRefs;                           \
        g_RefMap[key] = expectRefs;                                                \
    }                                                                              \
    std::remove_reference_t<decltype(oPName)> tempOp;                              \
    ResultWrap tempRef(tempOp);                                                    \
    auto it1 = g_RefMap.find(key);                                                 \
    if (it1 != g_RefMap.end()) {                                                   \
        std::vector<std::vector<ResultWrap>> expectRefs = it1->second;             \
        if (!expectRefs.empty()) {                                                 \
            tempRef = expectRefs[0][0];                                            \
            expectRefs.erase(expectRefs.begin());                                  \
        }                                                                          \
        g_RefMap[key] = expectRefs;                                                \
    }                                                                              \
    oPName = tempRef.Get<decltype(tempOp)>();                                      \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a member function with return sptr<xxx> type value.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: ret must be sptr<xxx>
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD_RET_SPTR(ret, className, funcName, ...)                     \
ret funcName(__VA_ARGS__)                                                          \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> tempExpectRets;                                    \
        g_mockMap[key] = tempExpectRets;                                           \
    }                                                                              \
    ret tmp = nullptr;                                                             \
    ResultWrap tempRet(tmp);                                                       \
    std::vector<ResultWrap>& expectRets = g_mockMap[key];                          \
    if (!expectRets.empty()) {                                                     \
        tempRet = expectRets[0];                                                   \
        expectRets.erase(expectRets.begin());                                      \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a virtual or static member function.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string, if you need mock a function with sptr, use
 *            OH_MOCK_METHOD_RET_SPTR instead.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD_WITH_DECORATOR(decorator, ret, className, funcName, ...)    \
decorator ret funcName(__VA_ARGS__)                                                \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> expectRets;                                        \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    ret temp;                                                                      \
    ResultWrap tempRet(temp);                                                      \
    auto it = g_mockMap.find(key);                                                 \
    if (it != g_mockMap.end()) {                                                   \
        std::vector<ResultWrap> expectRets = it->second;                           \
        if (!expectRets.empty()) {                                                 \
            tempRet = expectRets[0];                                               \
            expectRets.erase(expectRets.begin());                                  \
        }                                                                          \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a virtual or static member function.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string, if you need mock a function with sptr, use
 *            OH_MOCK_METHOD_RET_SPTR instead.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX(prefix, suffix, ret, className, funcName, ...)    \
prefix ret funcName(__VA_ARGS__) suffix                                                \
{                                                                                  \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> expectRets;                                        \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    ret temp;                                                                      \
    ResultWrap tempRet(temp);                                                      \
    auto it = g_mockMap.find(key);                                                 \
    if (it != g_mockMap.end()) {                                                   \
        std::vector<ResultWrap> expectRets = it->second;                           \
        if (!expectRets.empty()) {                                                 \
            tempRet = expectRets[0];                                               \
            expectRets.erase(expectRets.begin());                                  \
        }                                                                          \
        g_mockMap[key] = expectRets;                                               \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a global function.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: this param only support basic type e.g int/string.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_GLOBAL_METHOD(ret, funcName, ...)                                  \
ret funcName(__VA_ARGS__)                                                          \
{                                                                                  \
    std::string key = #funcName"_"#__VA_ARGS__;                                    \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> tempExpectRets;                                    \
        g_mockMap[key] = tempExpectRets;                                           \
    }                                                                              \
    ret temp;                                                                      \
    ResultWrap tempRet(temp);                                                      \
    std::vector<ResultWrap>& expectRets = g_mockMap[key];                          \
    if (!expectRets.empty()) {                                                     \
        tempRet = expectRets[0];                                                   \
        expectRets.erase(expectRets.begin());                                      \
    }                                                                              \
    return tempRet.Get<ret>();                                                     \
}

/**
 * @brief Mock a global template function with return sptr<xxx> type value.
 *        This macro function while create a definition of a function that expected to be mocked.
 * @param ret Indicate the type of return value.
 *            Warning: ret must be sptr<xxx>
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_MOCK_GLOBAL_TEMPLATE_METHOD_RET_SPTR(funcName, ...)                     \
template <typename INTERFACE> sptr<INTERFACE> funcName(__VA_ARGS__)                \
{                                                                                  \
    std::string key = #funcName"_"#__VA_ARGS__;                                    \
    if (g_mockMap.find(key) == g_mockMap.end()) {                                  \
        std::vector<ResultWrap> tempExpectRets;                                    \
        g_mockMap[key] = tempExpectRets;                                           \
    }                                                                              \
    sptr<INTERFACE> tmp = nullptr;                                                 \
    ResultWrap tempRet(tmp);                                                       \
    std::vector<ResultWrap>& expectRets = g_mockMap[key];                          \
    if (!expectRets.empty()) {                                                     \
        tempRet = expectRets[0];                                                   \
        expectRets.erase(expectRets.begin());                                      \
    }                                                                              \
    return tempRet.Get<sptr<INTERFACE>>();                                         \
}

/**
 * @brief Mock a serial of expect results for specified member function.
 * @param expectRetVec Indicate expect results vector.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_EXPECT_RET(expectRetVec, className, funcName, ...)                      \
do {                                                                               \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                       \
    std::vector<ResultWrap> v;                                                     \
    for (auto e : expectRetVec) {                                                  \
        if (std::is_same<decltype(e), vector<bool>::reference>::value == true) {   \
            bool conE = bool(e);                                                   \
            ResultWrap r(conE);                                                 \
            v.emplace_back(r);                                                     \
        } else {                                                                   \
            ResultWrap r(e);                                                       \
            v.emplace_back(r);                                                     \
        }                                                                          \
    }                                                                              \
    g_mockMap[key] = v;                                                            \
} while (0)

/**
 * @brief Mock a serial of expect results for specified member function.
 * @param expectRetVec Indicate expect results vector.
 * @param className Indicate the className of function.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_EXPECT_RET_AND_OUTPUT(expectRetVec, expectOutputVec, className, funcName, ...)  \
do {                                                                                       \
    std::string key = #className"_"#funcName"_"#__VA_ARGS__;                               \
    std::vector<ResultWrap> v;                                                             \
    for (auto e : expectRetVec) {                                                          \
        if (std::is_same<decltype(e), vector<bool>::reference>::value == true) {           \
            bool conE = bool(e);                                                           \
            ResultWrap r(conE);                                                            \
            v.emplace_back(r);                                                     \
        } else {                                                                   \
            ResultWrap r(e);                                                       \
            v.emplace_back(r);                                                     \
        }                                                                          \
    }                                                                                      \
    g_mockMap[key] = v;                                                                    \
    std::vector<std::vector<ResultWrap>> vRefs;                                            \
    for (auto eOuters : expectOutputVec) {                                                 \
        std::vector<ResultWrap> vRef;                                                      \
        for (auto eOuter : eOuters) {                                                      \
            if (std::is_same<decltype(eOuter), vector<bool>::reference>::value == true) {   \
                bool conE = bool(eOuter);                                                   \
                ResultWrap r(conE);                                                        \
                vRef.emplace_back(r);                                                         \
            } else {                                                                       \
                ResultWrap r(eOuter);                                                      \
                vRef.emplace_back(r);                                                     \
            }                                                                          \
        }                                                                                  \
        vRefs.emplace_back(vRef);                                                          \
    }                                                                                      \
    g_RefMap[key] = vRefs;                                                                 \
} while (0)

/**
 * @brief Mock a serial of expect results for specified global function.
 * @param expectRetVec Indicate expect results vector.
 * @param funcName Indicate the functionName of function.
 * @param ... Indicate the params of function.
 */
#define OH_GLOBAL_EXPECT_RET(expectRetVec, funcName, ...)                          \
do {                                                                               \
    std::string key = #funcName"_"#__VA_ARGS__;                                    \
    std::vector<ResultWrap> v;                                                     \
    for (auto e : expectRetVec) {                                                  \
        ResultWrap r(e);                                                           \
        v.emplace_back(r);                                                         \
    }                                                                              \
    g_mockMap[key] = v;                                                            \
} while (0)

#endif  // OHOS_MOCK_UTIL_H