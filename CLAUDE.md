# CLAUDE.md

本文件为 Claude Code (claude.ai/code) 在此代码库中工作时提供指导。

## 概述

这是 OpenHarmony 的 **ability_runtime** 组件（元能力运行时）。它提供核心组件框架，用于管理应用生命周期、组件调度和扩展组件管理。

### 开发者框架

**UIAbility 组件**：
- 提供应用界面的核心组件
- 支持多实例、多窗口模式
- 完整的生命周期管理（onStart、onForeground、onBackground、onStop）

**Extension 扩展组件**：
- ServiceExtension：后台服务扩展
- UIExtension：UI 扩展组件
- UIServiceExtension：UI 服务扩展
- AppServiceExtension：应用服务扩展
- DataShareExtension：数据共享扩展

**Uri 授权**：
- 跨应用 URI 访问权限管理
- URI 权限授予和撤销
- 安全的跨进程数据访问

**意图框架 (InsightIntent)**：
- 系统级意图标准体系，连接应用内的业务功能
- 智能意图识别和分发，支持意图匹配和路由
- 跨应用意图调度，实现应用间智能协同
- 帮助开发者将应用内的业务功能智能化
- 支持配置和装饰器两种方式开发意图

**启动框架**：
- 应用启动流程管理
- 启动模式和启动规则控制
- 冷启动、热启动优化

**自动填充框架**：
- 表单自动填充支持
- 跨应用数据填充

**子进程**：
- 子进程创建和管理
- 父子进程通信
- 进程隔离和资源控制

**应用上下文环境**：
- 提供应用级别和组件级别的上下文
- 支持获取应用信息、资源访问、权限管理
- 提供应用级数据共享和通信能力

**系统环境变化监听**：
- 配置变化监听（系统语言、主题、方向等）
- 内存级别变化监听
- 系统状态变化监听

**组件生命周期监听**：
- UIAbility 生命周期状态变化监听
- Extension 组件生命周期状态变化监听
- 进程生命周期监听

**任务管理**：
- 任务栈管理
- 多任务切换
- 任务持久化和恢复

### 系统服务

**组件管理服务**：
- 管理 UIAbility 和 Extension 组件生命周期
- 组件启动/停止、连接管理
- 任务栈和任务列表管理
- 与应用管理服务协调进行进程管理

**应用管理**：
- 应用进程生命周期管理
- 与 AppSpawn 服务协调应用孵化
- 应用状态管理（前台、后台）
- 进程状态上报、子进程管理、进程预加载
- 应用恢复和重启

**快速修复**：
- 应用热修复能力
- 补丁管理和应用
- 无需重启的修复机制

## 构建系统

本项目使用 **GN (Generate Ninja)** 作为构建系统。

### 构建命令

```bash
# 构建整个 ability_runtime 组件
./build.sh --product-name <product> --build-target ability_runtime

# 构建特定目标：以abilityms为例
./build.sh --product-name <product> --build-target abilityms

# 构建全量tdd测试用例
./build.sh --product-name <product> --build-target ability_runtime_test

# 构建特定TDD用例：以 ability_manager_service_first_test 为例
./build.sh --product-name <product> --build-target ability_manager_service_first_test
```

### 清理构建

```bash
./build.sh --product-name <product> --build-target ability_runtime --clean
```

## 测试

### 单元测试

单元测试位于 `test/unittest/` 并按组件组织。

```bash
# 运行所有单元测试
run -t UT -tp ability_runtime

# 运行特定测试（示例：ability_manager_service_first_test 测试）
run -t UT -ts ability_manager_service_first_test
```

### 模块测试

位于 `test/moduletest/`，以 ability_caller_fw_module_test 为例：

```bash
run -t UT -ts ability_caller_fw_module_test
```

### Fuzz 测试

位于 `test/fuzztest/`, 以 AbilityAppDebugInfoFuzzTest 为例：

```bash
run -t UT -ts AbilityAppDebugInfoFuzzTest
```

## 架构

### 目录结构

```
ability_runtime/
├── frameworks/               # 框架实现层
│   ├── native/              # C++ 原生框架
│   │   ├── ability/         # Ability 组件框架
│   │   │   ├── native/      # UIAbility、Extension 组件实现
│   │   │   │   ├── action_extension_ability/         # Action 扩展
│   │   │   │   ├── agent_extension_ability/          # Agent 扩展
│   │   │   │   ├── auto_fill_extension_ability/      # 自动填充扩展
│   │   │   │   ├── photo_editor_extension_ability/   # 照片编辑器扩展
│   │   │   │   ├── share_extension_ability/          # 分享扩展
│   │   │   │   ├── ui_extension_ability/             # UI 扩展
│   │   │   │   ├── ui_service_extension_ability/     # UI 服务扩展
│   │   │   │   ├── embedded_ui_extension_ability/    # 嵌入式 UI 扩展
│   │   │   │   ├── form_runtime/                     # Form 卡片运行时
│   │   │   │   ├── continuation/                     # 组件迁移
│   │   │   │   ├── recovery/                         # 组件恢复
│   │   │   │   ├── insight_intent_executor/          # 意图执行器
│   │   │   │   ├── child_process_manager/            # 子进程管理
│   │   │   │   └── auto_startup_callback/            # 自动启动回调
│   │   │   └── ability_runtime/ # Ability 运行时核心
│   │   ├── appkit/          # 应用工具包
│   │   │   ├── ability_runtime/ # 应用运行时
│   │   │   │   ├── app/      # Application 实现
│   │   │   │   └── context/  # 应用上下文环境
│   │   │   ├── app/          # 应用模型
│   │   │   ├── app_startup/  # 应用启动
│   │   │   ├── dfr/          # 应用动态帧率（DFR）
│   │   │   ├── ability_delegator/ # 测试委托器
│   │   │   └── ability_bundle_manager_helper/ # Bundle 管理助手
│   │   ├── child_process/    # 子进程框架
│   │   ├── insight_intent/   # 意图框架
│   │   │   └── insight_intent_context/ # 意图上下文
│   │   ├── runtime/          # 运行时核心
│   │   └── simulator/        # 模拟器支持
│   ├── js/napi/             # JavaScript NAPI 绑定
│   ├── ets/                 # ETS/ArkTS 绑定
│   ├── cj/                  # CJ FFI 绑定
│   └── c/                   # ability_runtime 的 C API
├── interfaces/              # 接口层
│   ├── inner_api/           # 内部组件接口（IPC 客户端）
│   │   ├── ability_manager/      # Ability 管理接口
│   │   ├── extension_manager/    # Extension 管理接口
│   │   ├── app_manager/          # 应用管理接口
│   │   ├── auto_fill_manager/    # 自动填充管理接口
│   │   ├── uri_permission/       # URI 权限接口
│   │   ├── insight_intent/       # 意图接口
│   │   ├── mission_manager/      # 任务管理接口
│   │   ├── dataobs_manager/      # 数据观察接口
│   │   ├── child_process_manager/# 子进程管理接口
│   │   ├── quick_fix/            # 快速修复接口
│   │   ├── wantagent/            # WantAgent 接口
│   │   ├── foreground_app_obs_manager/ # 前台应用观察
│   │   ├── connectionobs_manager/# 连接观察
│   │   ├── session_handler/      # 会话处理
│   │   ├── ani_base_context/     # ANI 基础上下文
│   │   ├── napi_base_context/    # NAPI 基础上下文
│   │   ├── native_extension/     # 原生扩展接口
│   │   ├── runtime/              # 运行时接口
│   │   ├── connect_server_manager/# 连接服务器管理
│   │   ├── page_config_manager/  # 页面配置管理
│   │   ├── deps_wrapper/         # 依赖包装
│   │   └── error_utils/          # 错误工具
│   └── kits/                # 公共 SDK 接口
│       ├── native/          # Native SDK
│       └── c/               # C SDK
├── services/                # 系统服务层
│   ├── abilitymgr/          # 组件管理服务（AbilityManagerService）
│   ├── appmgr/              # 应用管理服务（AppManagerService）
│   ├── uripermmgr/          # URI 权限管理服务
│   ├── dataobsmgr/          # 数据观察管理服务
│   ├── quickfixmgr/         # 快速修复管理服务
│   ├── appdfr/              # 应用动态帧率服务
│   ├── dialog_ui/           # 系统对话框 UI
│   ├── common/              # 服务通用模块
│   └── sa_profile/          # 系统能力配置
├── agent_runtime_framework/ # Agent 组件框架
├── service_router_framework/ # 服务路由框架
├── js_environment/          # JavaScript 运行时环境
├── ets_environment/         # ETS/ArkTS 运行时环境
├── cj_environment/          # CJ 运行时环境
├── utils/                   # 工具库
│   ├── global/              # 全局工具
│   └── server/              # 服务端工具
├── tools/                   # 工具
│   ├── aa/                  # "aa" 命令行工具
│   └── test/                # 测试工具
├── test/                    # 测试
│   ├── unittest/            # 单元测试
│   ├── moduletest/          # 模块测试
│   ├── fuzztest/            # Fuzz 测试
│   ├── new_test/            # 新测试
│   ├── mock/                # Mock 对象
│   ├── sample/              # 测试示例
│   └── resource/            # 测试资源
├── docs/                    # 文档
├── figures/                 # 图片资源
├── ability_runtime.gni      # 构建配置
├── bundle.json              # 组件描述
├── BUILD.gn                 # GN 构建入口
├── hisysevent.yaml          # 系统事件定义
├── OAT.xml                  # 开源合规性
└── CODEOWNERS               # 代码所有者
```

### 核心组件

#### AbilityManagerService
位于 `services/abilitymgr/`，这是核心系统能力，负责：
- 启动和停止组件
- 管理组件生命周期（onStart、onForeground、onBackground、onStop）
- 处理组件连接（connectAbility、disconnectAbility）
- 管理任务栈和任务列表
- 与 AppManagerService 协调进行进程管理

主要子管理器：
- `AbilityConnectManager`：Extension 扩展组件连接和生命周期管理
- `DataAbilityManager`：Data Ability 管理
- `MissionListManager`：任务/任务栈管理（需要图形支持）
- `PendingWantManager`：待定意图/Want 管理
- `FreeInstallManager`：免安装（按需）组件支持
- `KioskManager`：Kiosk 模式管理
- `AutoStartupService`：自动启动组件管理

#### AppManagerService
位于 `services/appmgr/`，负责管理：
- 应用进程生命周期
- 与 AppSpawn 服务协调应用孵化
- 应用状态（前台、后台）
- 进程状态上报、子进程管理、进程预加载
- 应用恢复和重启

#### UriPermissionManager
位于 `services/uripermmgr/`，负责：
- 跨应用 URI 访问权限管理
- URI 权限授予和撤销
- 安全的跨进程数据访问

#### DataObserverManager
位于 `services/dataobsmgr/`，负责：
- 数据变化观察
- 跨应用数据同步

#### QuickFixManager
位于 `services/quickfixmgr/`，负责：
- 应用热修复能力
- 补丁管理和应用
- 无需重启的修复机制

#### AppDFRManager
位于 `services/appdfr/`，负责：
- 应用动态帧率管理
- 性能优化和功耗控制

#### 框架层

**Native 框架** (`frameworks/native/`)：
- **UIAbility 组件**：`ability/native/` - Ability、AbilityContext 实现
- **Extension 扩展组件**：`ability/native/`
  - `action_extension_ability/` - Action 扩展
  - `agent_extension_ability/` - Agent 扩展
  - `auto_fill_extension_ability/` - 自动填充扩展
  - `photo_editor_extension_ability/` - 照片编辑器扩展
  - `share_extension_ability/` - 分享扩展
  - `ui_extension_ability/` - UI 扩展
  - `ui_service_extension_ability/` - UI 服务扩展
  - `embedded_ui_extension_ability/` - 嵌入式 UI 扩展
  - `form_runtime/` - Form 卡片运行时
  - `continuation/` - 组件迁移
  - `recovery/` - 组件恢复
- **意图框架**：`insight_intent/` - InsightIntent 意图框架实现
  - `insight_intent_context/` - 意图上下文
  - `ability/native/insight_intent_executor/` - 意图执行器
- **应用上下文环境**：`appkit/ability_runtime/context/` - Context 实现
- **应用启动**：`appkit/app_startup/` - 应用启动流程
- **子进程**：`child_process/` - 子进程框架
  - `ability/native/child_process_manager/` - 子进程管理器
- **应用模型**：`appkit/` - Application、AbilityStage、TestRunner
- **其他**：
  - `runtime/` - 运行时核心
  - `simulator/` - 模拟器支持

**NAPI 层** (`frameworks/js/napi/`)：
- JavaScript/TypeScript 应用的绑定
- 模块：ability、abilityManager、appManager、context、wantAgent 等

**ANI 层** (`frameworks/ets/` 和 `frameworks/ets/ets/`)：
- ArkTS 原生接口绑定
- ETS 特定的性能优化实现

**CJ 层** (`frameworks/cj/`)：
- 面向云的语言 (CJ) FFI 绑定
- 与 Ark 运行时的互操作

### 两种应用模型

此代码库同时支持 FA（Feature Ability）和 Stage 模型：

**FA 模型**（API 8 及更早版本）：
- 使用 `config.json` 进行模块配置
- PageAbility、ServiceAbility、DataAbility、FormAbility
- 每个 Ability 有自己独立的 JS VM 实例

**Stage 模型**（API 9+）：
- 使用 `module.json5` 进行模块配置
- Ability (UIAbility)、ExtensionAbility 系列
- 每个进程共享 JS VM 实例
- 更好地支持复杂应用和分布式场景

## 开发说明

### 添加新的 Ability 或 Extension

1. 在 `interfaces/kits/native/` 中定义扩展类型
2. 在 `frameworks/native/ability/native/` 中实现
3. 在 `frameworks/ets/ani/` 中添加 ANI 绑定
4. 在 `frameworks/js/napi/` 中添加 NAPI 绑定
5. 在 `services/abilitymgr/` 中添加服务端管理
6. 更新 BUILD.gn 文件
7. 在 `test/unittest/` 中添加测试

### 特性标志

特性标志在 `ability_runtime.gni` 中定义：
- `ability_runtime_auto_fill`：自动填充扩展支持
- `ability_runtime_child_process`：子进程支持
- `ability_runtime_ui_service_extension`：UI 服务扩展
- `ability_runtime_photo_editor_extension`：照片编辑器扩展
- `ability_runtime_graphics`：图形依赖特性（任务栈）
- `ability_runtime_screenlock_enable`：锁屏集成

添加条件特性时请检查这些标志。

### 错误处理

- 使用在 `interfaces/inner_api/error_utils/` 中定义的 `ERR_*` 错误码
- 常见错误：`ERR_OK`、`ERR_NO_INIT`、`ERR_INVALID_VALUE`、`ERR_INVALID_CALLING`
- 业务错误在 `frameworks/native/ability/native/ability_business_error.h` 中

### 日志记录

使用 `hilog_tag_wrapper.h` 进行日志记录：

```cpp
#include "hilog_tag_wrapper.h"

// 使用预定义的日志标签枚举
TAG_LOGI(AAFwkTag::ABILITYMGR, "Ability started: %{public}s", abilityName.c_str());
TAG_LOGE(AAFwkTag::ABILITYMGR, "Failed to start ability, error: %{public}d", errorCode);
TAG_LOGW(AAFwkTag::ABILITYMGR, "Warning: %{public}s", message.c_str());
TAG_LOGD(AAFwkTag::ABILITYMGR, "Debug info: %{public}s", debugInfo.c_str());
TAG_LOGF(AAFwkTag::ABILITYMGR, "Fatal error: %{public}s", errorStr.c_str());

// 可用的日志标签（AAFwkLogTag 枚举）：
// DEFAULT, ABILITY, TEST, AA_TOOL, ABILITY_SIM,
// APPDFR, APPMGR, DBOBSMGR, DIALOG, QUICKFIX, URIPERMMGR, BUNDLEMGRHELPER, APPKIT,
// JSENV, JSRUNTIME, FA, INTENT, JSNAPI, CJRUNTIME, ETSRUNTIME, ANI,
// DELEGATOR, CONTEXT, UIABILITY, WANT, MISSION, CONNECTION, ABILITYMGR, ...
```

日志标签定义位于 `services/common/include/hilog_tag_wrapper.h`。

### aa 命令

`aa` 工具（`tools/aa/`）是 Ability 管理命令行工具，用于调试和管理 Ability 组件。

#### 常用命令

```bash
# 启动 Ability
aa start -a <ability-name> -b <bundle-name> [-D]

# 查询并输出系统信息
aa dump -a

# 强制停止应用进程
aa force-stop <bundle-name>
```

## 配置

### 应用模块配置

- FA 模型：`entry/src/main/config.json`
- Stage 模型：`entry/src/main/module.json5`

### 系统服务配置

- 系统服务配置文件：`services/sa_profile/`

## 依赖项

主要依赖项（在 `bundle.json` 中定义）：
- `ability_base`：Ability 基础工具
- `bundle_framework`：Bundle 管理
- `eventhandler`：事件处理
- `ipc`：IPC/RPC 通信
- `samgr`：系统能力管理器
- `hilog`：日志记录
- `window_manager`：窗口管理
- `ace_engine`：ArkUI 引擎
- `ets_runtime`：ETS 运行时
- `napi`：NAPI 框架
