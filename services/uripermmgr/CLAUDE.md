# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在此代码库中工作时提供指导。

## 概述

这是 **URI 权限管理服务（Uri Permission Manager Service，UPMS）** - OpenHarmony 中的系统服务（SA ID: 183），负责管理跨应用的文件URI访问权限。当前UPMS仅作为文件URI权限管理入口，负责对URI类型按照media、docs、沙箱URI和分布式docs uri进行分发，分别对接到MediaLibrary、SandboxManager和StorageManager进行权限管理。

## 架构

### 服务结构

该服务作为按需启动的 SystemAbility 运行在 `foundation` 进程中。主要组件包括：

- **UriPermissionManagerService** (`uri_permission_manager_service.h/cpp`)：SystemAbility 入口点，单例生命周期管理
- **UriPermissionManagerStubImpl** (`uri_permission_manager_stub_impl.h/cpp`)：核心 IPC 实现（约 74KB），处理所有 URI 权限操作

### 支持的 URI 类型
仅支持文件URI，格式为：`file://authority/path`。按照authority的划分，文件URI又可以分为以下三种类型：
1. Media URIs：`file://media/xxx` 媒体文件的专用处理，权限对接mediaLibrary
2. Document URIs：`file://docs/xxx`  公共目录URI，权限对接SandboxManager
3. Sandbox URIS：`file://bundleName/xxx` 应用沙箱URI，权限对接SandboxManager
4. Docs Clound URIS：`file://docs/xxx?networkId=xxx` 分布式Document URI, 权限对接StorageManager

### 专用管理器

- **FilePermissionManager**：处理文件 URI 权限，支持基于策略的访问控制（SandboxManager）
- **MediaPermissionManager**：管理Media Uris的授权，当定义 `ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE` 时启用
- **TokenIdPermission**：基于令牌的权限验证，通过缓存提升性能
- **BatchUri** (`batch_uri.h/cpp`)：管理批量 URI 操作，按类型分类 URI
- **FileUriDistributionUtils** (`file_uri_distribution_utils.h/cpp`)：URI 分发逻辑，包名解析，Token ID 映射
- **UDMFUtils** (`upms_udmf_utils.h/cpp`)：UDMF（统一数据模型框架）集成，支持大批量URI授权，当定义 `ABILITY_RUNTIME_UDMF_ENABLE` 时启用

### 关键对外接口

- **CheckUriAuthorization & CheckUriAuthorizationWithType**
给定批量URI、tokenId和权限flag, 返回是否有权限分享URI。

- **GrantUriPermissionPrivileged & GrantUriPermissionWithType**
给定批量URI、目标应用和授权flag，对目标应用授权。仅有特殊权限的SA可以调用，与CheckUriAuthorization结合使用。

- **GrantUriPermission**
给定批量URI、目标应用包名、权限flag，先对校验调用方是否有权限分享URI，再调用URI授权。

- **RevokeUriPermission**
移除已授予目标应用的 URI 访问权限。

- **GrantUriPermissionByKey & GrantUriPermissionByKeyAsCaller**
通过统一数据密钥(Uniform Data Key)读取 URI，并授权给目标应用。

- **ClearPermissionTokenByMap**
清理临时URI权限，应用退出时调用。

- **VerifyUriPermission**
校验tokenId对应的应用是否有指定URI的临时权限，仅限制DFS调用。

### 关键数据结构

- **GrantInfo**：`{flag, fromTokenId, targetTokenId}` - 权限授予记录
- **GrantPolicyInfo**：`{callerTokenId, targetTokenId}` - 策略授予跟踪
- **CheckResult**：权限检查结果
- **PolicyInfo**：基于路径的访问策略（SELF_PATH、AUTHORIZATION_PATH、OTHERS_PATH）
- **FUDAppInfo**：文件 URI 分发的应用标识信息

## 构建命令

### 构建服务

```bash
# 构建 UriPermissionManager 服务库 (libupms.z.so)
./build.sh --product-name <product> --build-target libupms 

# 独立编译命令
hb build ability_runtime -i --build-target //foundation/ability/ability_runtime/services/uripermmgr:libupms
```

### 特性标志（定义在 ability_runtime.gni）

- `ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER`：启用 SandboxManager 集成以增强安全性
- `ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE`：启用媒体库权限支持
- `ABILITY_RUNTIME_UDMF_ENABLE`：启用 UDMF 集成以支持批量 URI 操作
- `ABILITY_RUNTIME_UPMS`：通用 UPMS 特性标志

## 测试

### 测试位置

单元测试位于：
- `test/unittest/uri_permission_manager_test`
- `test/unittest/uri_permission_impl_test`
- `test/unittest/uri_permission_test`
- `test/unittest/uri_perm_mgr_test`

Mock 框架：`test/new_test/mock/upms/uri_permission_mgr/`

### 运行测试

```bash
# 运行所有 uripermmgr 单元测试
run -t UT -tp uripermmgr

# 运行特定测试（示例：uri_permission_manager_test）
run -t UT -ts uri_permission_manager_test
```


## 依赖项

### 内部依赖
- `ability_manager`：Ability 管理服务集成
- `uri_permission_mgr`：客户端接口库
- `perm_verification`：权限验证工具

### 外部依赖
- `access_token`：基于令牌的身份验证（libaccesstoken_sdk、libtokenid_sdk）
- `bundle_framework`：包管理（appexecfwk_base、appexecfwk_core）
- `ipc_core`：IPC/RPC 通信
- `safwk`：SystemAbility 框架
- `hilog`：日志记录
- `hisysevent`：安全审计的事件跟踪
- `hitrace`: 性能打点

### 可选依赖
- `sandbox_manager`：沙箱管理，管理公共目录URI和沙箱URI（启用特性时）
- `media_library`：媒体权限（启用特性时）
- `udmf`：批量操作（启用特性时）

## 客户端接口

位于 `interfaces/inner_api/uri_permission/`：

- **UriPermissionManagerClient**：应用的主客户端接口
- **IUriPermissionManager.idl**：IPC 接口定义
- **uri_permission_load_callback.h**：加载回调
- **uri_permission_raw_data.h**：原始 URI 数据的数据结构


## 系统能力配置

位于 `services/sa_profile/183.json`：
- **SA ID**：183
- **库**：`libupms.z.so`
- **进程**：`foundation`
- **按需启动**：`run-on-create: false`
